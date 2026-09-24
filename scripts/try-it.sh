#!/usr/bin/env bash
# Run the plugin inside a real Traefik, end to end, on your machine.
#
# You do not need Traefik or Docker installed: this downloads a Traefik
# binary into .local-test/ and runs it there. You do need Go (to build the
# sample databases) plus curl and python3 (the throwaway backend).
#
#   ./scripts/try-it.sh            run the checks and exit
#   ./scripts/try-it.sh --keep     leave Traefik running for manual curls
#
# Everything lives in .local-test/ and nothing is installed system wide.

set -u

TRAEFIK_VERSION="${TRAEFIK_VERSION:-v3.3.4}"
PORT="${PORT:-8000}"
BACKEND_PORT="${BACKEND_PORT:-9000}"
KEEP=0
[ "${1:-}" = "--keep" ] && KEEP=1

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$ROOT/.local-test"
MODULE="github.com/IPGeolocation/traefik-plugin-ipgeolocation"

red() { printf '\033[31m%s\033[0m\n' "$1"; }
green() { printf '\033[32m%s\033[0m\n' "$1"; }
info() { printf '\033[36m==>\033[0m %s\n' "$1"; }

for tool in curl python3; do
	command -v "$tool" >/dev/null 2>&1 || {
		red "$tool is required."
		exit 1
	}
done
command -v go >/dev/null 2>&1 || {
	red "Go is required to build the sample databases."
	echo "Install Go from https://go.dev/dl/, or use the Docker route in TESTING.md."
	exit 1
}

mkdir -p "$WORK/ipgeo" "$WORK/plugins-local/src/$MODULE"

# ---------------------------------------------------------------------------
info "Building sample databases"
# ---------------------------------------------------------------------------
# These are tiny MMDB files written by the test suite, in the real binary
# format, holding a handful of networks. Replace them with your own
# IPGeolocation.io downloads whenever you like.
(cd "$ROOT" && IPGEO_FIXTURE_OUT="$WORK/ipgeo" go test -run TestWriteFixtureDatabase ./... >/dev/null) || {
	red "could not build the sample databases"
	exit 1
}
ls "$WORK/ipgeo"

# ---------------------------------------------------------------------------
info "Staging the plugin"
# ---------------------------------------------------------------------------
# Traefik loads local plugins from a directory tree that mirrors the module
# name, so the path below is not arbitrary.
rm -rf "${WORK:?}/plugins-local/src/${MODULE:?}"
mkdir -p "$WORK/plugins-local/src/$MODULE"
(cd "$ROOT" && tar --exclude=.local-test --exclude=.git -cf - .) |
	(cd "$WORK/plugins-local/src/$MODULE" && tar -xf -)

# ---------------------------------------------------------------------------
info "Fetching Traefik $TRAEFIK_VERSION"
# ---------------------------------------------------------------------------
if [ ! -x "$WORK/traefik" ]; then
	case "$(uname -s)" in
	Linux) os=linux ;;
	Darwin) os=darwin ;;
	*)
		red "unsupported OS $(uname -s); see TESTING.md for the Docker route"
		exit 1
		;;
	esac
	case "$(uname -m)" in
	x86_64 | amd64) arch=amd64 ;;
	arm64 | aarch64) arch=arm64 ;;
	*)
		red "unsupported architecture $(uname -m)"
		exit 1
		;;
	esac
	url="https://github.com/traefik/traefik/releases/download/${TRAEFIK_VERSION}/traefik_${TRAEFIK_VERSION}_${os}_${arch}.tar.gz"
	curl -fsSL "$url" -o "$WORK/traefik.tgz" || {
		red "download failed: $url"
		exit 1
	}
	tar -xzf "$WORK/traefik.tgz" -C "$WORK" traefik
	chmod +x "$WORK/traefik"
fi
"$WORK/traefik" version | head -2

# ---------------------------------------------------------------------------
info "Writing the test configuration"
# ---------------------------------------------------------------------------
cat >"$WORK/traefik.yml" <<EOF
experimental:
  localPlugins:
    ipgeolocation:
      moduleName: $MODULE

entryPoints:
  web:
    address: ":$PORT"
    # Traefik overwrites X-Forwarded-For with the real peer address before
    # any middleware runs, unless the peer is trusted. Without this, the
    # faked header below never reaches the plugin and every request looks
    # like it came from 127.0.0.1. Test instances only: never in production.
    forwardedHeaders:
      insecure: true

providers:
  file:
    filename: $WORK/dynamic.yml

log:
  level: INFO
EOF

cat >"$WORK/dynamic.yml" <<EOF
http:
  routers:
    test:
      rule: PathPrefix(\`/\`)
      entryPoints: [web]
      service: echo
      middlewares: [geo]

  services:
    echo:
      loadBalancer:
        servers:
          - url: http://127.0.0.1:$BACKEND_PORT

  middlewares:
    geo:
      plugin:
        ipgeolocation:
          databases:
            - $WORK/ipgeo/db-ip-location.mmdb
            - $WORK/ipgeo/db-ip-security.mmdb
            - $WORK/ipgeo/db-ip-asn.mmdb
          headerPreset: standard
          # The faked client address arrives in X-Forwarded-For.
          trustForwardedHeader: true
          blockVPN: true
          blockedCountries: [KP]
          logLevel: info
EOF

cat >"$WORK/echo.py" <<EOF
import http.server, json
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps(dict(self.headers.items()), indent=2).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass
http.server.HTTPServer(("127.0.0.1", $BACKEND_PORT), H).serve_forever()
EOF

# ---------------------------------------------------------------------------
info "Starting the backend and Traefik"
# ---------------------------------------------------------------------------
python3 "$WORK/echo.py" >/dev/null 2>&1 &
BACKEND_PID=$!
(cd "$WORK" && ./traefik --configfile="$WORK/traefik.yml" >"$WORK/traefik.log" 2>&1) &
TRAEFIK_PID=$!

cleanup() {
	kill "$TRAEFIK_PID" "$BACKEND_PID" 2>/dev/null
	wait 2>/dev/null
}
[ "$KEEP" -eq 1 ] || trap cleanup EXIT

ready=0
for _ in $(seq 1 30); do
	sleep 1
	curl -s --max-time 2 -o /dev/null "http://127.0.0.1:$PORT/" && {
		ready=1
		break
	}
done
if [ "$ready" -ne 1 ]; then
	red "Traefik did not come up. Log:"
	tail -30 "$WORK/traefik.log"
	exit 1
fi

if ! grep -aq "Plugins loaded" "$WORK/traefik.log"; then
	red "Traefik started but did not load the plugin. Log:"
	grep -ai "plugin\|error" "$WORK/traefik.log" | head -20
	exit 1
fi
green "Traefik loaded the plugin"

# ---------------------------------------------------------------------------
info "Running checks"
# ---------------------------------------------------------------------------
failures=0

check() { # name expected actual
	if [ "$2" = "$3" ]; then
		green "  PASS  $1"
	else
		red "  FAIL  $1 (expected '$2', got '$3')"
		failures=$((failures + 1))
	fi
}

get_header() { # ip headerName [extra curl args...]
	ip="$1"
	header="$2"
	shift 2
	curl -s --max-time 5 -H "X-Forwarded-For: $ip" "$@" "http://127.0.0.1:$PORT/" |
		python3 -c "import sys,json;print(json.load(sys.stdin).get('$header',''))" 2>/dev/null
}

status_for() { # ip
	curl -s --max-time 5 -o /dev/null -w '%{http_code}' -H "X-Forwarded-For: $1" "http://127.0.0.1:$PORT/"
}

check "UK address is enriched with its country" "GB" "$(get_header 81.2.69.142 X-Ipgeo-Country-Code)"
check "UK address is enriched with its city" "Gloucester" "$(get_header 81.2.69.142 X-Ipgeo-City-Name)"
check "ASN comes from the second database" "AS1257" "$(get_header 81.2.69.142 X-Ipgeo-Asn)"
check "IPv6 address resolves" "Gloucester" "$(get_header 2a04:4540:1234::9 X-Ipgeo-City-Name)"
check "allowed country passes through" "200" "$(status_for 81.2.69.142)"
check "flagged VPN address is blocked" "403" "$(status_for 2.56.188.34)"
check "address outside the database passes" "200" "$(status_for 8.8.8.8)"
check "a spoofed geolocation header is replaced" "GB" \
	"$(get_header 81.2.69.142 X-Ipgeo-Country-Code -H 'X-IPGeo-Country-Code: KP')"

echo
if [ "$failures" -eq 0 ]; then
	green "All checks passed."
else
	red "$failures check(s) failed. Traefik log: $WORK/traefik.log"
fi

if [ "$KEEP" -eq 1 ]; then
	echo
	info "Traefik is still running on http://127.0.0.1:$PORT (pid $TRAEFIK_PID)"
	echo "  curl -H 'X-Forwarded-For: 81.2.69.142' http://127.0.0.1:$PORT/"
	echo "  edit $WORK/dynamic.yml and Traefik reloads it automatically"
	echo "  stop with: kill $TRAEFIK_PID $BACKEND_PID"
fi

exit "$failures"
