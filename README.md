# Traefik IP Geolocation Plugin for IPGeolocation.io

Geo-blocking, VPN and proxy detection, and IP intelligence headers for Traefik, powered by [IPGeolocation.io](https://ipgeolocation.io) MMDB databases. This Traefik middleware plugin reads the databases from local disk and answers every lookup inside the Traefik process, with no API calls and no per-request cost.

Use it to block traffic by country, stop Tor exit nodes, VPNs, proxies and known attackers at the edge, route visitors by region, and add country, city, ASN and threat data to requests and access logs.

```bash
# Block Tor and known attackers, refuse high risk addresses, tell the backend where visitors are
http:
  middlewares:
    geo:
      plugin:
        ipgeolocation:
          databases:
            - /etc/traefik/ipgeo/db-ip-location.mmdb
            - /etc/traefik/ipgeo/db-ip-security.mmdb
          headerPreset: standard
          blockTor: true
          blockKnownAttacker: true
          blockThreatScoreAbove: 80
```

**Jump to:** [Installation](#installation) | [Quick start](#quick-start) | [Databases](#getting-the-databases) | [Configuration](#configuration-reference) | [Fields](#field-reference) | [Client IP](#client-ip-selection) | [Troubleshooting](#troubleshooting) | [FAQ](#frequently-asked-questions)

## Why use this plugin

Most Traefik geolocation setups call a remote API on every request or put a GeoIP library inside each application. This plugin loads IPGeolocation.io databases into Traefik once and answers each lookup locally in about ten microseconds ([benchmarks](#performance-and-memory)).

- No API calls and no per-request billing. Every lookup is a read from a local file.
- Decisions at the edge. Block, redirect or route in Traefik before the request reaches your backend.
- One middleware, many databases. Location, Security, Company, ASN, Abuse Contact, Hosting and Residential Proxy all load through one list, and the plugin [layers them](#how-it-works).
- Works with every database tier. Security v1, v3 and v4 all resolve without configuration changes.
- Zero dependencies. The MMDB reader is written using only the Go standard library, so it runs inside [Traefik's plugin interpreter](#development).
- Safe by default. [Forwarded headers](#client-ip-selection) are ignored unless you trust them, private addresses skip the lookup, failures fail open, and client supplied `X-IPGeo-*` headers are stripped.

## How it works

You list one or more `.mmdb` files under [`databases`](#data-source). The plugin opens each file at startup and, for every request:

1. Resolves the client IP address (see [Client IP selection](#client-ip-selection)).
2. Looks that address up in each database, in the order you declared them.
3. For each field, takes the value from the first database that has it. Declaration order is priority order.
4. Sets the [headers](#enrichment) you asked for, evaluates the [rules](#access-control) you enabled, then forwards or blocks.

Because the first match wins, databases layer: load a Location and a Security database together, and `country_code` comes from the first while `is_vpn` comes from the second.

## Requirements

- Traefik v3.x (tested against v3.3). Traefik v2.x is not supported.
- One or more IPGeolocation.io [`.mmdb` databases](#getting-the-databases), or an API key for [API mode](#api-mode).
- Read access to the database files from inside the Traefik process or container.

No Go toolchain is needed. Traefik downloads and interprets the plugin.

## Installation

### Declare the plugin in the static configuration

```bash
# traefik.yml
experimental:
  plugins:
    ipgeolocation:
      moduleName: github.com/IPGeolocation/traefik-plugin-ipgeolocation
      version: v1.0.0
```

The command line equivalents are `--experimental.plugins.ipgeolocation.modulename=...` and `--experimental.plugins.ipgeolocation.version=v1.0.0`. The [Traefik plugin documentation](https://doc.traefik.io/traefik/plugins/) covers how plugins are loaded at startup.

### Mount the databases

The plugin reads files from the Traefik container's filesystem, so mount them with a volume such as `./ipgeo:/etc/traefik/ipgeo:ro`. Database paths in your configuration are then resolved inside the container, not on the host. If Traefik logs `cannot open ...: no such file or directory` at startup, check the mount and the path first. [Troubleshooting](#troubleshooting) covers the other common startup problems.

### Attach the middleware to a router

Define a middleware in your dynamic configuration and reference it from a router, as in the [Quick start](#quick-start) below. Middleware basics are in the [Traefik middleware overview](https://doc.traefik.io/traefik/middlewares/http/overview/).

## Quick start

### Add geolocation headers for your backend

```bash
http:
  routers:
    my-app:
      rule: Host(`example.com`)
      service: my-app
      middlewares: [geo-enrich]

  middlewares:
    geo-enrich:
      plugin:
        ipgeolocation:
          databases:
            - /etc/traefik/ipgeo/db-ip-location.mmdb
            - /etc/traefik/ipgeo/db-ip-asn.mmdb
          headerPreset: standard
```

Your backend receives `X-IPGeo-Country-Code: US`, `X-IPGeo-City-Name: Philadelphia`, `X-IPGeo-ASN: AS1257` and the rest of the standard preset. The [field reference](#field-reference) lists every name you can ask for.

### Block countries in Traefik

Middleware definitions below go under `http.middlewares`, as in the example above.

```bash
us-and-canada-only:
  plugin:
    ipgeolocation:
      databases: [/etc/traefik/ipgeo/db-ip-location.mmdb]
      allowedCountries: [US, CA]
      blockStatusCode: 451
      blockMessage: This service is not available in your region.
```

### Stop VPNs, proxies and attackers in front of a login page

```bash
login-shield:
  plugin:
    ipgeolocation:
      databases: [/etc/traefik/ipgeo/db-ip-security.mmdb]
      blockTor: true
      blockKnownAttacker: true
      blockResidentialProxy: true
      blockThreatScoreAbove: 80
```

Put your monitoring and office ranges in [`allowedIPs`](#access-control). They bypass every rule, so a policy change can never lock you out of your own service.

### Docker labels

```bash
labels:
  - "traefik.http.middlewares.geo.plugin.ipgeolocation.databases[0]=/etc/traefik/ipgeo/db-ip-location.mmdb"
  - "traefik.http.middlewares.geo.plugin.ipgeolocation.blockedCountries[0]=KP"
  - "traefik.http.routers.my-app.middlewares=geo"
```

On Kubernetes, the same keys go under `spec.plugin.ipgeolocation` in a Traefik `Middleware` resource.

[!TIP]
> Start with `dryRun: true` and `logLevel: info`. The plugin evaluates every rule, logs what it would have blocked, tags the request with `X-IPGeo-Dry-Run`, and lets it through. Watch the log for a day, then remove `dryRun`. This is the safest way to introduce [any blocking rule](#access-control).

## Getting the databases

Download the `.mmdb` files from your [IPGeolocation.io account](https://app.ipgeolocation.io/signup) and point [`databases`](#data-source) at them. Each database has its own static download link that never changes, so the same link serves the first download and every update.

| Database | File | What it adds |
| --- | --- | --- |
| [IP Geolocation](https://ipgeolocation.io/ip-geolocation-database.html) | `db-ip-location.mmdb` | country, state, district, city, postal code, coordinates, time zone, currency |
| [IP Security](https://ipgeolocation.io/ip-security-database.html) | `db-ip-security.mmdb` | threat score, Tor, VPN, proxy, relay, bot, spam, attacker and cloud flags |
| [IP Company](https://ipgeolocation.io/ip-company-database.html) | `db-ip-company.mmdb` | company or ISP name, domain and type |
| [IP to ASN](https://ipgeolocation.io/ip-asn-database.html) | `db-ip-asn.mmdb` | AS number, organization, type, RIR, peers and routes in the Deep tier |
| [IP Abuse Contact](https://ipgeolocation.io/ip-abuse-contact-database.html) | `db-ip-abuse.mmdb` | abuse email, phone, address, route, country |
| [Residential Proxy](https://ipgeolocation.io/residential-proxy-database.html) | `db-residential-proxy.mmdb` | residential proxy provider and last seen date |
| [IP Hosting](https://ipgeolocation.io/ip-hosting-database.html) | `db-ip-hosting.mmdb` | hosting provider name |

Load only what you need. Fields from a database you did not load stay empty, so referencing them is safe. Bundles that ship two databases in one archive work the same way: list both files. Tiers are on the [pricing page](https://ipgeolocation.io/db-pricing.html), the [field schemas](https://ipgeolocation.io/documentation/databases.html) show what each database contains.

[!TIP]
> You can evaluate the plugin before buying anything. IPGeolocation.io publishes sample databases that need no API key, so you can try them out. Each is a real MMDB file with a subset of ranges, so you can work through the whole [Quick start](#quick-start) with one. To read a file directly, use [mmdbio](https://github.com/IPGeolocation/mmdbio).

## Configuration reference

Every option is a camelCase key under `plugin.ipgeolocation`. The tables give the short version; [OPTIONS.md](https://github.com/IPGeolocation/traefik-plugin-ipgeolocation/blob/main/OPTIONS.md) explains what each value does in detail.

### Data source

| Option | Default | Description |
| --- | --- | --- |
| `mode` | `mmdb` | `mmdb` reads local files, `api` calls the [REST API](#api-mode) |
| `databases` | | List of `.mmdb` paths. Declaration order is [priority order](#how-it-works) |
| `loadInMemory` | `true` | Read each file into RAM. Set `false` for multi gigabyte files, see [Performance](#performance-and-memory) |
| `refreshInterval` | `0` | Reload a database when its file changes, for example `1h`. See [Keeping databases up to date](#keeping-databases-up-to-date) |

### Enrichment

| Option | Default | Description |
| --- | --- | --- |
| `headerPreset` | `minimal` | `none`, `minimal` (country, city, ASN), `standard` (15 headers), `full` |
| `headers` | | Map of header name to [field name](#field-reference), applied over the preset. An empty value removes a preset header |
| `language` | `en` | Localized names: `en`, `de`, `ru`, `ko`, `pt`, `ja`, `fa`, `fr`, `zh`, `es`, `cs`, `it` |
| `listSeparator` | `,` | Joins list fields such as VPN provider names |
| `booleanFormat` | `true_false` | `one_zero` emits `1` and `0`, like the [Nginx module](https://ipgeolocation.io/documentation/nginx-integration) |

Header names follow `X-IPGeo-<Field-Name>`, so `country_code` becomes `X-IPGeo-Country-Code`. Headers the plugin manages are deleted from the incoming request before enrichment, so your backend can trust them.

### Access control

| Option | Default | Description |
| --- | --- | --- |
| `allowedCountries` / `blockedCountries` | | ISO 3166-1 alpha-2 codes. Set one list, not both |
| `allowedContinents` / `blockedContinents` | | `AF`, `AN`, `AS`, `EU`, `NA`, `OC`, `SA` |
| `allowedASNs` / `blockedASNs` | | `AS1257` or `1257` |
| `allowedIPs` | | CIDRs that skip every check. Evaluated first |
| `blockedIPs` | | CIDRs refused before any lookup |
| `blockTor`, `blockVPN`, `blockProxy`, `blockRelay` | `false` | Anonymizer flags from the [Security database](https://ipgeolocation.io/ip-security-database.html) |
| `blockResidentialProxy`, `blockAnonymous` | `false` | Residential proxy and combined anonymity flags |
| `blockKnownAttacker`, `blockSpam` | `false` | Threat flags |
| `blockBot` | `false` | Known bots. Crawlers marked as known good bots are spared, see [Troubleshooting](#troubleshooting) |
| `blockKnownGoodBots` | `false` | Make `blockBot` apply to search engines and monitors too |
| `blockCloudProvider` | `false` | Cloud and hosting infrastructure. Also catches corporate VPN exits and CI runners |
| `blockCorporateGateway` | `false` | Corporate egress gateways (Security v4) |
| `blockThreatScoreAbove` | `-1` | Block when the score is above this value, for example `80`. `0` counts as off, use `1` to block everything above zero |
| `allowPrivate` | `true` | Skip private and loopback addresses instead of treating them as unknown |
| `allowUnknown` | `true` | Allow addresses no database covers |
| `dryRun` | `false` | Evaluate and log without blocking |

### Block response and failure handling

| Option | Default | Description |
| --- | --- | --- |
| `blockStatusCode` | `403` | `451` is conventional for legal restrictions |
| `blockMessage` | `Access denied.` | Plain text body |
| `blockRedirectURL` | | Send a `302` to this URL instead of a status. Do not point it at a route behind the same middleware |
| `failOpen` | `true` | Forward the request when a lookup fails. `false` blocks instead |

### Client IP, cache, API and logging

| Option | Default | Description |
| --- | --- | --- |
| `trustForwardedHeader` | `false` | Read the client address from a forwarded header, see [Client IP selection](#client-ip-selection) |
| `forwardedHeaderName` | `X-Forwarded-For` | For example `CF-Connecting-IP` behind Cloudflare |
| `forwardedDepth` | `0` | Take the Nth address counting from the right. `0` means leftmost |
| `trustedProxies` | | Your proxy CIDRs. The first address from the right that is not yours is used |
| `cacheSize` | `10000` | Cached addresses. `0` disables the cache |
| `cacheTTL` | `1h` | Lifetime of a cached lookup. Use `24h` in [API mode](#api-mode) |
| `apiKey`, `apiEndpoint`, `apiInclude`, `apiFields`, `apiTimeout` | | [API mode](#api-mode) settings |
| `logLevel` | `info` | `error`, `warn`, `info` or `debug` |

## Field reference

Use any of these names in the [`headers`](#enrichment) map. They match the [Nginx module](https://ipgeolocation.io/documentation/nginx-integration)'s `$ip_*` variables without the prefix.

| Group | Fields |
| --- | --- |
| Location | `country_code`, `country_code3`, `country_code_ioc`, `country_name`, `country_name_official`, `country_capital`, `continent_code`, `continent_name`, `state_code`, `state_name`, `district_name`, `city_name`, `zip_code`, `latitude`, `longitude`, `geoname_id`, `time_zone`, `accuracy_radius`, `confidence`, `dma_code`, `connection_type`, `is_eu` |
| Country metadata | `currency_code`, `currency_name`, `currency_symbol`, `calling_code`, `languages`, `tld` |
| Company | `company_name`, `company_domain`, `company_type`, `isp_name`, `organization_name` |
| ASN | `asn`, `asn_number`, `asn_name`, `asn_organization`, `asn_country`, `asn_domain`, `asn_type`, `asn_rir`, `asn_date_allocated`, `asn_allocation_status`, `asn_routes`, `asn_peers`, `asn_upstreams`, `asn_downstreams` |
| Security | `threat_score`, `is_tor`, `is_proxy`, `is_vpn`, `is_relay`, `is_residential_proxy`, `is_anonymous`, `is_known_attacker`, `is_bot`, `is_spam`, `is_cloud_provider`, `cloud_provider`, `proxy_type`, `proxy_provider`, `vpn_provider`, `relay_provider`, `proxy_confidence`, `vpn_confidence`, `proxy_last_seen`, `vpn_last_seen` |
| Security v4 | `is_known_good_bot`, `bot_type`, `bot_operator`, `bot_confidence`, `bot_last_seen`, `is_corporate_gateway`, `corporate_gateway_provider`, `corporate_gateway_type` |
| Residential proxy and hosting | `residential_proxy_provider`, `residential_proxy_last_seen`, `hosting_provider` |
| Abuse contact | `abuse_name`, `abuse_email`, `abuse_phone`, `abuse_address`, `abuse_country_code`, `abuse_kind`, `abuse_route` |
| Special | `ip`, the client address the plugin used |

Booleans render as `true` or `false` (or `1` and `0` with `booleanFormat: one_zero`), lists are joined with `listSeparator`, AS numbers are normalized to `AS1257`, and a field with no data is omitted rather than sent empty.

The Residential Proxy and Hosting databases have no boolean column, since a record existing is the signal, so `is_residential_proxy` and `is_cloud_provider` become `true` when those databases contain the address. A flag from a database declared earlier still wins.

## Real world examples

### Route visitors to a regional backend

Map the [fields](#field-reference) you need to your own header names, then read them in the application:

```bash
headers:
  X-Geo-Country: country_code
  X-Geo-Currency: currency_code
  X-Geo-Language: languages
```

### Different rules for different paths

Attach a lighter middleware to the whole site and a stricter one to sensitive routes:

```bash
http:
  routers:
    checkout:
      rule: Host(`example.com`) && PathPrefix(`/checkout`)
      middlewares: [geo-enrich, no-anonymizers]
      service: app

  middlewares:
    no-anonymizers:
      plugin:
        ipgeolocation:
          databases: [/etc/traefik/ipgeo/db-ip-security.mmdb]
          headerPreset: none
          blockVPN: true
          blockProxy: true
          blockTor: true
          blockResidentialProxy: true
```

### Separate humans from infrastructure

```bash
headers:
  X-Is-Cloud: is_cloud_provider
  X-ASN-Type: asn_type
  X-Bot-Operator: bot_operator
```

Rate limit or serve a lighter page when `X-Is-Cloud` is `true`, and log `X-Bot-Operator` to see which crawlers visit, without blocking anyone.

### Enrich access logs

Traefik logs any request header you name under `accessLog.fields.headers.names`, so `X-IPGeo-Country-Code`, `X-IPGeo-ASN` and `X-IPGeo-Threat-Score` flow straight into your log pipeline with no application changes.

## Client IP selection

The plugin geolocates one address per request. By default that is the address of the TCP connection, which is correct when Traefik faces the internet directly. Behind a load balancer or CDN, every visitor would look like the balancer, so you need the forwarded header:

```bash
# Behind exactly one proxy you control
trustForwardedHeader: true
forwardedDepth: 1

# Behind a variable number of your own proxies
trustForwardedHeader: true
trustedProxies: [10.0.0.0/8, 172.16.0.0/12]

# Behind Cloudflare
trustForwardedHeader: true
forwardedHeaderName: CF-Connecting-IP
```

[!IMPORTANT]
> X-Forwarded-For` is written by clients and can be forged. With `trustForwardedHeader: true` and neither `forwardedDepth` nor `trustedProxies` set, a visitor can pick their own country by sending one header. Trust it only when a proxy you operate overwrites it, and pair it with one of the two strategies above. Traefik also replaces the header with the peer address before any middleware runs, unless the entrypoint's `forwardedHeaders.trustedIPs` lists that peer, so both settings are needed.

When testing locally, a plugin that loads cleanly but enriches nothing is almost always this. Set `logLevel: debug` and look for `127.0.0.1 is private or loopback, skipping the lookup`.

Private, loopback, link local and carrier grade NAT ranges are absent from every public database. With [`allowPrivate: true`](#access-control) they skip the lookup and pass through untouched.

## Keeping databases up to date

IPGeolocation.io publishes fresh releases daily. The plugin never downloads anything itself. It watches the files you gave it, and a scheduled job replaces them:

```bash
refreshInterval: 1h
```

When a file's size or modification time changes, the plugin opens the new file, swaps it in atomically, clears the lookup cache, and closes the old one after a short grace period. If the new file will not open, it keeps serving the old one and logs a warning. No restart, no failed requests.

The download side is yours to run, from cron, a systemd timer, a Kubernetes CronJob or your existing pipeline. Each database has its own static link with its own `apiKey` parameter, and each archive holds the `.mmdb`, a `README.md` and a `checksum.txt`. A good refresh job verifies the checksum, confirms the file really is an MMDB before installing it, and handles bundles holding two databases.

[!IMPORTANT]
> Save each download under a temporary name in the same directory and then rename it into place. Rename is atomic on one filesystem, so the plugin sees either the whole old file or the whole new one, while a file overwritten in place can be picked up half written. Note also that with `refreshInterval` left at `0`, new files only take effect when Traefik restarts.

## Performance and memory

Measured with `go test -bench` on a 2.8 GHz Xeon, one request end to end through the middleware:

| Case | Per request | Allocations |
| --- | --- | --- |
| Repeat visitor, served from cache | 3.8 µs | 21 |
| Cache miss, [`headerPreset: minimal`](#enrichment) | 9.4 µs | 98 |
| Cache miss, `headerPreset: standard` | 18.5 µs | 248 |
| Cache miss, `headerPreset: full` | 44.6 µs | 409 |

Cost scales with the number of fields you resolve, not with database size. The plugin resolves only the fields your headers and rules reference, and picks a lookup strategy at startup to match: with eight fields or fewer it seeks to each field inside the record and skips the rest, and with more it decodes the record once.

Memory depends on [`loadInMemory`](#data-source). With `true` the whole file is resident and a lookup takes 9.9 µs. With `false` only the search tree stays in memory and each record is read from disk in one windowed read, at 11.1 µs. During a refresh with `true`, both copies are briefly resident, so size the container for twice the largest database.

Leave the cache on. Real traffic repeats addresses constantly, and a cached request costs less than half of an uncached one.

## API mode

When you cannot ship database files, the plugin can call the [IPGeolocation.io REST API](https://ipgeolocation.io/ip-location-api.html) instead:

```bash
http:
  middlewares:
    geo:
      plugin:
        ipgeolocation:
          mode: api
          apiKey: YOUR_API_KEY
          apiInclude: security
          cacheTTL: 24h
          headerPreset: standard
          failOpen: true
```

Every cache miss is an outbound HTTPS request that costs a credit and adds a round trip, so keep `cacheTTL` high and `failOpen` on, and prefer MMDB mode for production traffic. [Field names](#field-reference) and [rules](#access-control) are identical in both modes, so switching later is a configuration change.

## Troubleshooting

**Traefik will not start and logs a plugin error.** Check that `moduleName` is exactly `github.com/IPGeolocation/traefik-plugin-ipgeolocation` and that the [version tag](#installation) exists.

**A field is always empty.** Confirm you loaded a database that carries it. Security fields need the [Security database](https://ipgeolocation.io/ip-security-database.html), ASN fields need the [ASN database](https://ipgeolocation.io/ip-asn-database.html). The startup log prints one `loaded` line per database with its type and build date. To inspect a file directly, use [mmdbio](https://github.com/IPGeolocation/mmdbio): `mmdbio read --db db-ip-security.mmdb --ip 2.56.188.34`.

**Everything is blocked, or nothing is.** Turn on `dryRun` and read the reasons in the log. Remember that [`allowPrivate`](#access-control) skips internal traffic and `allowUnknown` decides what happens to addresses no database covers.

**All visitors look like one address.** Traefik is behind a proxy. See [Client IP selection](#client-ip-selection).

**`blockBot` lets Googlebot through.** By design. Crawlers are flagged as bots and as known good bots in Security v4, and blocking them removes you from search results. Set `blockKnownGoodBots: true` if you really want them blocked.

## Frequently asked questions

<details> <summary><strong>Does this plugin call the IPGeolocation.io API?</strong></summary> Not in MMDB mode. It reads local `.mmdb` files and makes no outbound requests, so there are no per-request costs. [API mode](#api-mode) exists for setups that cannot ship files.
</details>

<details> <summary><strong>How is this different from other Traefik GeoIP plugins?</strong></summary> Most call a remote service on every request, or wrap `libmaxminddb`, which cannot run inside Traefik's plugin interpreter. This plugin reads MMDB files natively, is built for IPGeolocation.io schemas, [layers multiple databases](#how-it-works), exposes [security and ASN data](#field-reference) as well as location, and blocks on any of it without extra tooling.
</details>

<details> <summary><strong>Can I test it without Traefik installed?</strong></summary> Yes. `./scripts/try-it.sh` downloads a Traefik binary into a scratch directory, builds sample databases, runs the plugin inside it and checks enrichment, geo-blocking and VPN filtering. [TESTING.md](https://github.com/IPGeolocation/traefik-plugin-ipgeolocation/blob/main/TESTING.md) also covers the Docker Compose route.
</details>

<details> <summary><strong>Which databases do I need?</strong></summary> It depends on what you are blocking or sending to your backend. Country and city headers or geo-blocking need the IP Geolocation database. VPN, proxy, Tor, bot and threat score rules need IP Security. ASN filtering needs IP to ASN, and ISP or company names need IP Company. You can load several together and the plugin [layers them](#how-it-works), so start with one and add more later without changing your rules. The full list is in [Getting the databases](#getting-the-databases), and the same files also work with the [Nginx module](https://ipgeolocation.io/documentation/nginx-integration) if you run both.
</details>

<details> <summary><strong>Does it work behind Cloudflare, an AWS load balancer or another proxy?</strong></summary> Yes, but two settings are needed. Set `trustForwardedHeader: true` on the middleware with either `forwardedDepth` or `trustedProxies`, and list your proxy under the Traefik entrypoint's `forwardedHeaders.trustedIPs`. Without the second, Traefik overwrites the header before any middleware runs and every visitor looks like your load balancer. Behind Cloudflare, set `forwardedHeaderName: CF-Connecting-IP`. See [Client IP selection](#client-ip-selection).
</details>

<details> <summary><strong>How much latency does it add?</strong></summary> Around 3.8 µs for a repeat visitor served from cache, and 9.4 µs to 44.6 µs for a cache miss depending on how many fields you resolve. Cost scales with the number of headers and rules you use, not with the size of the database, so a minimal preset stays fast even with multi gigabyte files. The numbers and the benchmark setup are in [Performance and memory](#performance-and-memory).
</details>

<details> <summary><strong>How do I update the databases without restarting Traefik?</strong></summary> Set `refreshInterval: 1h` and have a scheduled job replace the files. The plugin notices the change, swaps the database in atomically, clears its cache and keeps serving the old copy if the new file will not open. Your job must write the download under a temporary name in the same directory and then rename it into place, otherwise a half written file can be picked up. See [Keeping databases up to date](#keeping-databases-up-to-date).
</details>

<details> <summary><strong>Does it support IPv6?</strong></summary> Yes. IPGeolocation.io databases cover both address families, and the plugin looks up whichever address the visitor connected with. Every rule and header works the same for IPv6, including the [forwarded header strategies](#client-ip-selection), which accept bracketed addresses such as `[2a04:4540::1]:443`.
</details>

---

## Development

```bash
make test       # unit tests, including MMDB fixtures built byte by byte
make yaegi      # load the plugin through Yaegi, the interpreter Traefik uses
make try        # end to end inside a real Traefik binary
make check      # all of the above
```

Traefik does not compile plugins. It interprets them with [Yaegi](https://github.com/traefik/yaegi), which supports a subset of Go, so code that passes `go test` can still fail to load. Run `make yaegi` before every release. The reader is also checked against the official MMDB Go reader on real databases.

Two Yaegi rules for contributors, documented where they apply in the code: never assign a concrete type to an interface variable in a multi value assignment from a call, and never convert a value to an interface inside a loop body (return it from a function instead, see `newMMDBRecord` in `provider.go`). Neither fails under `go test`. Third party dependencies are not allowed.

## Related tools and links

**IPGeolocation.io tools**

- [Nginx module](https://github.com/IPGeolocation/ngx_http_ipgeolocation_module), the same databases as native `$ip_*` variables ([docs](https://ipgeolocation.io/documentation/nginx-integration))
- [mmdbio](https://github.com/IPGeolocation/mmdbio), a command line tool for reading and inspecting MMDB files
- [IPGeolocation CLI](https://github.com/IPGeolocation/cli), IP intelligence from your terminal and shell scripts
- [n8n community node](https://github.com/IPGeolocation/n8n-nodes-ipgeolocation), IP lookups inside n8n workflows
- [Integration guides](https://github.com/IPGeolocation/ipgeolocation-guides), setup guides for every integration
- [All repositories](https://github.com/IPGeolocation)

**Account, data and support**

- [Sign up for a free account](https://app.ipgeolocation.io/signup)
- [Database documentation and schemas](https://ipgeolocation.io/documentation/databases.html)
- [Database pricing and bundles](https://ipgeolocation.io/db-pricing.html)
- [Contact support](https://ipgeolocation.io/contact.html)
- [Service status](https://status.ipgeolocation.io)

**Traefik and format references**

- [Traefik plugin documentation](https://doc.traefik.io/traefik/plugins/) and the [Plugin Catalog](https://plugins.traefik.io/plugins)
- [Traefik HTTP middleware overview](https://doc.traefik.io/traefik/middlewares/http/overview/)
- [Yaegi](https://github.com/traefik/yaegi), the Go interpreter Traefik runs plugins with

## License

MIT. See [LICENSE](https://github.com/IPGeolocation/traefik-plugin-ipgeolocation/blob/main/LICENSE).

Built for [IPGeolocation.io](https://ipgeolocation.io) databases. Questions about the data, tiers or bundles are answered on the [database documentation](https://ipgeolocation.io/documentation/databases.html) and [pricing](https://ipgeolocation.io/db-pricing.html) pages.
