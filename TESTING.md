# Testing this plugin

Four ways to exercise the plugin, from fastest to most realistic. You do not need Traefik installed
for any of them, and only the last one needs Docker.

| | What it proves | Needs | Time |
| --- | --- | --- | --- |
| [1. Unit tests](#1-unit-tests) | Lookups, rules, headers, client IP, API mode | Go | seconds |
| [2. Yaegi check](#2-yaegi-check) | Traefik can actually load and run the code | Go | seconds |
| [3. Real Traefik](#3-real-traefik-no-docker) | The whole middleware, end to end, in Traefik | Go, curl, python3 | a minute |
| [4. Docker Compose](#4-docker-compose) | The same, in containers, close to production | Docker | a minute |

If you only run one thing, run number 3: `./scripts/try-it.sh`.

---

## Sample databases

Routes 1 to 4 all work without an IPGeolocation.io subscription. The test suite writes small but
genuine MMDB files, in the real binary format, holding a few networks:

```bash
mkdir -p /tmp/ipgeo
IPGEO_FIXTURE_OUT=/tmp/ipgeo go test -run TestWriteFixtureDatabase ./...
```

| Address | Present in | Resolves to |
| --- | --- | --- |
| `81.2.69.142` | location, ASN | Gloucester, GB, AS1257 |
| `2a04:4540:1234::9` | location | the same record, over IPv6 |
| `2.56.188.34` | security | threat score 80, VPN, proxy, known attacker, cloud |
| `8.8.8.8` | nothing | unknown, to exercise `allowUnknown` |

Swap in your real `.mmdb` downloads whenever you want: nothing else changes.

## 1. Unit tests

```bash
make test        # or: go test -race -cover ./...
```

These build MMDB files byte by byte and read them back, so the reader is tested against the real
format rather than a mock. They also cover the rule engine, header enrichment and stripping, client
IP strategies, the cache, database refresh, and API mode against a local HTTP server.

## 2. Yaegi check

```bash
make yaegi
```

Traefik does not compile plugins, it interprets them with [Yaegi](https://github.com/traefik/yaegi),
which supports a subset of Go. Code that builds and passes `go test` can still fail to load in
Traefik. This harness imports the package through Yaegi, calls `CreateConfig` and `New` by
reflection exactly as Traefik's plugin loader does, and serves real requests in both MMDB and API
mode. Two genuine incompatibilities were found this way while building the plugin; both are
described at the bottom of the README.

## 3. Real Traefik, no Docker

```bash
./scripts/try-it.sh
```

This downloads a Traefik binary into `.local-test/` (nothing is installed system wide), stages the
plugin as a local plugin, writes a test configuration, starts a throwaway echo backend, and asserts:

```
Traefik loaded the plugin
  PASS  UK address is enriched with its country
  PASS  UK address is enriched with its city
  PASS  ASN comes from the second database
  PASS  IPv6 address resolves
  PASS  allowed country passes through
  PASS  flagged VPN address is blocked
  PASS  address outside the database passes
  PASS  a spoofed geolocation header is replaced
```

To poke at it by hand, keep it running:

```bash
./scripts/try-it.sh --keep

curl -H 'X-Forwarded-For: 81.2.69.142' http://127.0.0.1:8000/   # enriched headers
curl -i -H 'X-Forwarded-For: 2.56.188.34' http://127.0.0.1:8000/ # 403
```

Edit `.local-test/dynamic.yml` and Traefik reloads it immediately, so you can try rules without
restarting anything. Traefik's own log, including the plugin's, is in `.local-test/traefik.log`.

Delete `.local-test/` to clean up.

### The one thing that will confuse you

Testing from your own machine means every request arrives from `127.0.0.1`, and the plugin skips
private and loopback addresses by design, so nothing appears to happen. Faking the address needs
**two** settings that are easy to conflate:

```yaml
# Static configuration: let Traefik itself keep the header you send.
entryPoints:
  web:
    address: ":8000"
    forwardedHeaders:
      insecure: true      # test instances only

# Middleware: let the plugin read it.
trustForwardedHeader: true
```

Without the first, Traefik overwrites `X-Forwarded-For` with the real peer address before any
middleware runs, and the plugin correctly sees `127.0.0.1`. The symptom is a plugin that loads
cleanly, logs nothing, and enriches nothing. If you see
`DEBUG 127.0.0.1 is private or loopback, skipping the lookup` with `logLevel: debug`, this is why.

Both settings are for local testing. In production, `forwardedHeaders.trustedIPs` should list your
real load balancers, and `trustForwardedHeader` belongs on only if Traefik sits behind a proxy you
operate.

## 4. Docker Compose

```bash
cd examples/local-dev
mkdir -p ipgeo && IPGEO_FIXTURE_OUT=$PWD/ipgeo go test -run TestWriteFixtureDatabase ../../...
docker compose up
```

Then in another terminal:

```bash
curl -H 'Host: whoami.localhost' -H 'X-Forwarded-For: 81.2.69.142' http://localhost:8000/
curl -i -H 'Host: whoami.localhost' -H 'X-Forwarded-For: 2.56.188.34' http://localhost:8000/
```

This mounts the repository into `/plugins-local/` so your edits apply on the next
`docker compose restart traefik`. It is the closest thing to how the plugin will run in production,
and the right place to test volume mounts and file permissions for real databases.

## Testing against a published release

Once the repository is tagged and listed in the Plugin Catalog, switch from a local plugin to the
published one by replacing `localPlugins` with `plugins` and adding a version:

```yaml
experimental:
  plugins:
    ipgeolocation:
      moduleName: github.com/IPGeolocation/traefik-plugin-ipgeolocation
      version: v1.0.0
```

Traefik downloads it at startup and caches it under its plugin storage directory. If you re-tag the
same version, clear that cache or Traefik keeps serving the old copy.

## Continuous integration

`.github/workflows/ci.yml` runs formatting, `go vet`, the race-enabled tests, the Yaegi check, and a
guard that fails the build if anything ever adds a third-party dependency to `go.mod`. Traefik
requires plugin dependencies to be vendored, and the standard MMDB readers cannot run under Yaegi,
so staying on the standard library is a hard constraint rather than a preference.
