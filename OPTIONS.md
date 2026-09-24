# Options reference

Every setting the plugin accepts, in plain language. All 49 keys go under `plugin.ipgeolocation` in a middleware definition, and they are camelCase in YAML, JSON, TOML and Docker labels alike.

If you are in a hurry, read [Start here](#start-here) and skip the rest until you need it.

## Start here

Most setups only need a handful of keys. Pick the row that matches what you are doing and copy it.

### I want my backend to know where visitors are

```yaml
databases: [/etc/traefik/ipgeo/db-ip-location.mmdb]
headerPreset: standard
```

Your backend now gets `X-IPGeo-Country-Code`, `X-IPGeo-City-Name` and thirteen more headers.

### I want to allow only certain countries

```yaml
databases: [/etc/traefik/ipgeo/db-ip-location.mmdb]
allowedCountries: [US, CA]
blockStatusCode: 451
```

### I want to block VPNs, Tor and attackers

```yaml
databases: [/etc/traefik/ipgeo/db-ip-security.mmdb]
blockTor: true
blockVPN: true
blockKnownAttacker: true
blockThreatScoreAbove: 80
```

### I want to see what a rule would do before turning it on

```yaml
dryRun: true
logLevel: info
```

Nothing gets blocked. The log shows what would have been, and each request carries `X-IPGeo-Dry-Run` with the reason.

### Traefik sits behind a load balancer or Cloudflare

```yaml
trustForwardedHeader: true
forwardedDepth: 1          # or: forwardedHeaderName: CF-Connecting-IP
```

Read [Client IP](#client-ip) before using this. It needs a matching setting on the Traefik entrypoint too.

## What happens on each request

Options apply at different points. This order explains most surprises.

```bash
1.  work out the client IP        trustForwardedHeader, forwardedHeaderName,
                                  forwardedDepth, trustedProxies
2.  delete any X-IPGeo-* headers  always, so clients cannot fake them
3.  is the IP in allowedIPs?      yes, forward now and skip everything else
4.  is the IP in blockedIPs?      yes, block now, no lookup
5.  is it private or loopback?    allowPrivate decides
6.  is it in the cache?           cacheSize, cacheTTL
7.  look it up                    mode, databases, loadInMemory, api*
8.  did the lookup fail?          failOpen decides
9.  set headers                   headerPreset, headers, language,
                                  listSeparator, booleanFormat
10. run the rules                 allowed*, blocked*, block*, allowUnknown
11. act                           dryRun, blockStatusCode, blockMessage,
                                  blockRedirectURL
```

Headers are set at step 9, before the rules run at step 10. A blocked request had its headers filled in, it just never reached your backend.

## Where the data comes from

### `mode`

Default `mmdb`. Where lookups come from.

| Value | What happens |
| --- | --- |
| `mmdb` | Reads your local database files. No network calls, no cost per request. |
| `api` | Calls the IPGeolocation.io REST API. Needs `apiKey`. Each cache miss costs a credit. |
| left out | `api` if you set `apiKey` and no `databases`, otherwise `mmdb`. |
| anything else | Traefik refuses to start the middleware and logs `unknown mode`. |

### `databases`

Default empty. The list of `.mmdb` files, required in `mmdb` mode.

```yaml
databases:
  - /etc/traefik/ipgeo/db-ip-location.mmdb   # country, city, coordinates
  - /etc/traefik/ipgeo/db-ip-security.mmdb   # VPN, proxy, threat score
  - /etc/traefik/ipgeo/db-ip-asn.mmdb        # ASN, organization
```

The order matters. For each field the plugin checks the databases top to bottom and uses the first one that has a value. That is how layering works: country comes from the first file, VPN flags from the second, ASN from the third, with nothing to configure.

Fields from a database you did not load stay empty, so it is safe to reference any field name.

> [!IMPORTANT]
> Paths are read inside the Traefik container, not on your host. Every file is opened at startup, so a wrong path or an unreadable file stops the middleware immediately with the reason in the log, rather than failing later on a request.

### `loadInMemory`

Default `true`.

| Value | What happens |
| --- | --- |
| `true` | The whole file is held in RAM. Needs as much memory as the file is big. A lookup takes 9.9 µs. |
| `false` | Only the search index is held in RAM, records are read from disk. A lookup takes 11.1 µs. |

The speed difference is small, so treat this as a memory setting. Use `false` for the Security and Residential Proxy databases, which run to several gigabytes.

### `refreshInterval`

Default `0`, which means off. Set it to a duration like `1h` and the plugin watches your database files and reloads any that changed.

| Value | What happens |
| --- | --- |
| `0` or left out | Files are never re-read. New databases apply only after a Traefik restart. |
| `1h`, `30m`, `24h` | Checks that often. A change swaps the database in with no restart and no failed requests. |
| under `1m` | Quietly raised to `1m`. |
| not a duration | Startup error. |

If the new file will not open, the plugin keeps the old one and logs a warning.

> [!IMPORTANT]
> The plugin never downloads anything. Whatever updates your files must write to a temporary name in the same folder and then rename it into place. A rename is instant and complete, so the plugin always sees either the whole old file or the whole new one. Overwriting a file directly can be caught half written.

## API mode settings

These are ignored in `mmdb` mode.

| Option | Default | What it does |
| --- | --- | --- |
| `apiKey` | | Required for `mode: api`. Keep it in a secret, not in the repo. |
| `apiEndpoint` | `https://api.ipgeolocation.io/v3/ipgeo` | Change it to pin a version or point at your own proxy. |
| `apiInclude` | `security` | Extra data to request. `security,abuse` adds abuse contacts. Empty means no security fields, so security rules never fire. |
| `apiFields` | | Trims the response, for example `location.country_code2`. Anything you cut cannot be used in headers or rules. |
| `apiTimeout` | `2s` | How long to wait. On timeout the lookup fails and `failOpen` decides. |

> [!TIP]
> In API mode set `cacheTTL: 24h`. With the default `cacheSize: 10000`, ten thousand different visitors a day cost ten thousand credits no matter how many requests they make.

## Headers

### `headerPreset`

Default `minimal`. A shortcut for which headers to add.

| Value | Headers you get |
| --- | --- |
| `none` | No headers. Use this when the middleware only blocks. |
| `minimal` | Country code, city, ASN. Three headers. |
| `standard` | Those plus country name, continent, state, ZIP, latitude, longitude, time zone, organization, threat score, and the VPN, proxy and Tor flags. Fifteen headers. |
| `full` | Every field, plus `X-IPGeo-IP` with the address the plugin used. |

Header names come from field names: `country_code` becomes `X-IPGeo-Country-Code`. You will see it as `X-Ipgeo-Country-Code` in a header dump because Go normalizes the capitals, and HTTP header names are case insensitive, so your app sees the same thing either way.

The preset also decides how much work each request does, since only the fields you reference get resolved:

| Preset | Cost per request when not cached |
| --- | --- |
| `minimal` | 9.4 µs |
| `standard` | 18.5 µs |
| `full` | 44.6 µs |

### `headers`

Default empty. A map of header name to field name, applied on top of the preset. Use it to rename headers, add fields the preset misses, or remove ones you do not want.

```yaml
headerPreset: standard
headers:
  X-Country: country_code          # your own name
  X-Geo-Currency: currency_code    # a field standard does not include
  X-IPGeo-Latitude: ""             # remove a header the preset added
```

| What you write | What happens |
| --- | --- |
| a known field name | Header is set when the value is not empty, and left out when it is. |
| `""` | Removes that header, including one the preset added. |
| a field name that does not exist | Startup error listing every valid field name. |

Set `headerPreset: none` plus your own `headers` map to get exactly the headers you asked for and nothing else.

> [!IMPORTANT]
> Any header the plugin manages is deleted from the incoming request first. A visitor sending `X-IPGeo-Country-Code: KP` gets it replaced with the real answer, so your backend can trust these headers.

### `language`

Default `en`. Applies to country, state, district, city, continent, capital and currency names.

Available: `en`, `de`, `ru`, `ko`, `pt`, `ja`, `fa`, `fr`, `zh`, `es`, `cs`, `it`. With `language: ja` a Thai address returns `タイ王国`. If a record has no translation for your language, the plugin falls back to English. An unknown code is not an error, it just always falls back.

### `listSeparator`

Default `,`. Joins fields that hold lists, such as `vpn_provider` or `asn_routes`. Two providers arrive as `Nord VPN,Proton VPN`.

### `booleanFormat`

Default `true_false`.

| Value | Booleans look like |
| --- | --- |
| `true_false` | `true` and `false` |
| `one_zero` or `1_0` | `1` and `0`, matching the Nginx module |

This changes header values only. Rules understand `true`, `1`, `yes` and `on` either way.

## Blocking rules

Rules run in the order listed here. The first one that blocks wins.

### `allowedIPs`

Default empty. CIDRs or plain addresses that skip everything: no lookup, no headers, no rules.

```yaml
allowedIPs: [203.0.113.0/24, 198.51.100.7]
```

> [!TIP]
> Put your monitoring, health checks and office ranges here. They bypass every rule, so no policy change can ever lock you out of your own service.

### `blockedIPs`

Default empty. CIDRs or addresses refused before any lookup. Cheaper than a rule and works even for addresses no database covers.

### `allowPrivate`

Default `true`. Covers loopback, link local, `10.x`, `192.168.x`, `172.16.x`, carrier grade NAT and IPv6 unique local addresses.

| Value | What happens |
| --- | --- |
| `true` | These skip the lookup and pass through with no headers. |
| `false` | They go through the normal path, find nothing, and then `allowUnknown` decides. |

No public database contains private addresses, so `allowPrivate: false` together with `allowUnknown: false` blocks your own internal traffic, health checks included.

### `allowUnknown`

Default `true`. Decides what to do with addresses your databases do not cover.

| Value | What happens |
| --- | --- |
| `true` | Unknown addresses are allowed. An allow list is skipped when the field is empty. |
| `false` | Unknown addresses are blocked, and so is anything whose country, continent or ASN is empty while an allow list is set. |

`false` is the strict reading of an allow list: if the plugin cannot prove you are in the US, you do not get in. It blocks more than people expect, because coverage is never total. Try it with `dryRun` first.

### `allowedCountries` and `blockedCountries`

Default empty. Two letter ISO codes, upper or lower case. You can write them as a list or as one comma separated string.

```yaml
allowedCountries: [US, CA]     # only these two get in
# or
blockedCountries: [KP, RU]     # everyone except these two gets in
```

| Situation | What happens |
| --- | --- |
| both set | Startup error. Pick one. |
| a code that is not two letters | Startup error. `GBR` is rejected, `GB` is right. |
| country unknown for an address | `allowUnknown` decides. |

### `allowedContinents` and `blockedContinents`

Default empty. `AF`, `AN`, `AS`, `EU`, `NA`, `OC`, `SA`. Same rules as countries. Continent codes are not length checked, so a typo silently matches nothing.

### `allowedASNs` and `blockedASNs`

Default empty. `AS1257`, `as1257` and `1257` all work. `AS0` and `0` are ignored because they mean no ASN. Needs a database with ASN data.

### The security flags

All default `false`. Each one needs a database that carries the matching field, so with no Security database loaded they never fire.

| Option | Blocks | Good for | Watch out |
| --- | --- | --- | --- |
| `blockTor` | Tor exit nodes | login, checkout | |
| `blockVPN` | VPNs | licensing, fraud | blocks privacy minded real customers |
| `blockProxy` | proxies | scraping | |
| `blockRelay` | relays | rarely useful | blocks normal iCloud Private Relay users |
| `blockResidentialProxy` | residential proxies | credential stuffing, bots | |
| `blockAnonymous` | anonymized addresses | broad catch all | overlaps the four above |
| `blockKnownAttacker` | known attackers | almost anywhere | |
| `blockBot` | known bots | scraping | see the good bot note below |
| `blockSpam` | known spam sources | signup and contact forms | |
| `blockCloudProvider` | cloud and hosting IPs | keeping servers out | also blocks corporate VPN exits, CI runners and legitimate API clients |
| `blockCorporateGateway` | corporate egress gateways | rarely useful | these carry ordinary employees |

> [!IMPORTANT]
> `blockBot` does not block crawlers that the Security v4 database marks as known good bots, such as search engines and uptime monitors. Blocking those removes you from search results. Set `blockKnownGoodBots: true` if you want them blocked too.

### `blockKnownGoodBots`

Default `false`. Makes `blockBot` apply to good bots as well. Only matters with Security v4 data, since earlier versions do not have the field.

### `blockThreatScoreAbove`

Default `-1`, which is off. Blocks when the score is higher than the number you give, on a scale of 0 to 100.

| Value | What happens |
| --- | --- |
| `-1` | Off. |
| `0` | Also off. A zero coming through dynamic configuration cannot be told apart from a missing key. Use `1` if you really mean above zero. |
| `80` | Blocks 81 and up. A sensible starting point. |
| `50` | Aggressive, expect false positives. |
| `100` | Blocks nothing, since the scale stops at 100. |

### `dryRun`

Default `false`. With `true` the rules run and log, but nothing is blocked, and each request carries `X-IPGeo-Dry-Run` with the reason it would have been.

This is how to introduce a policy safely. Turn it on with `logLevel: info`, watch for a day, then turn it off. While it is on, nothing is refused, `blockedIPs` included.

## What a blocked visitor sees

### `blockStatusCode`

Default `403`. Any code from 100 to 599. `451` is the conventional choice for legal or licensing blocks, `404` hides that the page exists, `429` hints at trying later.

### `blockMessage`

Default `Access denied.` Sent as plain text. An empty string sends the status with no body.

### `blockRedirectURL`

Default empty. Set it and blocked visitors get a `302` to that address instead of a status code, which is useful for sending people to a regional site. `blockStatusCode` and `blockMessage` are then unused.

> [!IMPORTANT]
> Do not point `blockRedirectURL` at a URL that goes through the same middleware. The visitor will be redirected in a loop.

### `failOpen`

Default `true`. Applies when the client IP cannot be worked out, or the lookup itself fails: a broken database, an API timeout, an HTTP error.

| Value | What happens |
| --- | --- |
| `true` | The request goes through and the error is logged. Your site stays up. |
| `false` | The request is blocked. |

`false` ties your uptime to the lookup path, which in API mode means to the API being reachable. Choose it only when not being able to check is itself a reason to refuse.

## Client IP

The plugin geolocates one address per request. By default that is the address Traefik sees on the connection, which is right when Traefik faces the internet directly. Behind a load balancer, every visitor looks like the balancer, and that is what these settings fix.

### `trustForwardedHeader`

Default `false`.

| Value | What happens |
| --- | --- |
| `false` | Uses the connection address. Visitors cannot influence it. |
| `true` | Uses the forwarded header, falling back to the connection address when the header is missing. |

> [!IMPORTANT]
> `X-Forwarded-For` is written by whoever sends the request, so it can be faked. With `trustForwardedHeader: true` and neither `forwardedDepth` nor `trustedProxies` set, a visitor can choose their own country by sending one header. Turn it on only when a proxy you run overwrites that header, and always pair it with one of the two settings below.

There is a second piece on the Traefik side. Traefik replaces `X-Forwarded-For` with the real peer address before any middleware runs, unless the entrypoint's `forwardedHeaders.trustedIPs` lists that peer. Without it the plugin never sees your header.

### `forwardedHeaderName`

Default `X-Forwarded-For`. Use `CF-Connecting-IP` behind Cloudflare, or whatever single value header your proxy sets.

### `forwardedDepth`

Default `0`. Counts from the right of the header.

With `X-Forwarded-For: 81.2.69.142, 198.51.100.4, 10.0.0.9`:

| Value | Address used | Meaning |
| --- | --- | --- |
| `0` | `81.2.69.142` | Leftmost. This is what the chain claims, and a visitor can prepend anything. |
| `1` | `10.0.0.9` | What the nearest proxy reported. |
| `2` | `198.51.100.4` | One hop further out. |
| bigger than the list | connection address | Falls back. |

Set it to the number of proxies you actually run. This is the reliable choice when that number is fixed.

### `trustedProxies`

Default empty. CIDRs of your own proxies. Used only when `trustForwardedHeader: true` and `forwardedDepth: 0`.

The plugin reads the header from the right and takes the first address that is not one of yours. Use this when the number of hops varies.

## Cache

Lookups are cached per address. Errors are never cached, and the cache is emptied automatically when a database is reloaded.

### `cacheSize`

Default `10000`, the number of addresses remembered.

| Value | What happens |
| --- | --- |
| `0` or less | Cache off. Every request does a full lookup. |
| `10000` | Ten thousand addresses. Entries are small. |
| higher | Better hit rate for sites with many different visitors, which matters most in API mode. |

Memory stays around twice this number of entries, because the cache keeps two generations and drops the older one in one go instead of tracking each entry.

### `cacheTTL`

Default `1h`. How long a cached answer lives. `0` turns the cache off, same as `cacheSize: 0`. Use `24h` in API mode.

## Logging

### `logLevel`

Default `info`. Goes to stdout with an `[ipgeolocation]` prefix, so it lands in the Traefik log.

| Value | What you see |
| --- | --- |
| `error` | Failed lookups only. |
| `warn` | Plus failed database refreshes and the API mode cost warning. |
| `info` | Plus one startup line per database with its type and build date, and one line per blocked request with the reason. |
| `debug` | Plus per request detail: which addresses were skipped as private, allow listed or unreadable. |

`info` is right for production, since you get a record of every block. `debug` floods a busy log, but it is the fastest way to answer "why is nothing happening?". The line `127.0.0.1 is private or loopback, skipping the lookup` explains most local testing confusion.

## Mistakes caught at startup

These stop the middleware loading, so you find out immediately rather than on a live request. Traefik logs the reason.

| What you did | What the log says |
| --- | --- |
| a `mode` that is not `mmdb` or `api` | `unknown mode "x"` |
| `mmdb` mode with no `databases` | `no database files configured` |
| a database file missing, unreadable or not an MMDB | names the file and the reason |
| `api` mode without `apiKey` | `apiKey is required when mode is "api"` |
| an allow list and a block list for the same thing | `set either allowedCountries or blockedCountries, not both` |
| a country code that is not two letters | names the entry |
| a header pointing at a field that does not exist | names the field and lists the valid ones |
| a `headerPreset` that is not one of the four | `use none, minimal, standard or full` |
| a bad CIDR in `allowedIPs`, `blockedIPs` or `trustedProxies` | names the entry |
| a bad duration in `cacheTTL`, `refreshInterval` or `apiTimeout` | names the option |
| `blockStatusCode` outside 100 to 599 with no redirect set | names the code |

## Full list at a glance

| Option | Default |
| --- | --- |
| `mode` | `mmdb` |
| `databases` | |
| `loadInMemory` | `true` |
| `refreshInterval` | `0` |
| `apiKey` | |
| `apiEndpoint` | `https://api.ipgeolocation.io/v3/ipgeo` |
| `apiInclude` | |
| `apiFields` | |
| `apiTimeout` | `2s` |
| `trustForwardedHeader` | `false` |
| `forwardedHeaderName` | `X-Forwarded-For` |
| `forwardedDepth` | `0` |
| `trustedProxies` | |
| `headerPreset` | `minimal` |
| `headers` | |
| `language` | `en` |
| `listSeparator` | `,` |
| `booleanFormat` | `true_false` |
| `allowedIPs` | |
| `blockedIPs` | |
| `allowPrivate` | `true` |
| `allowUnknown` | `true` |
| `allowedCountries` | |
| `blockedCountries` | |
| `allowedContinents` | |
| `blockedContinents` | |
| `allowedASNs` | |
| `blockedASNs` | |
| `blockTor` | `false` |
| `blockVPN` | `false` |
| `blockProxy` | `false` |
| `blockRelay` | `false` |
| `blockResidentialProxy` | `false` |
| `blockAnonymous` | `false` |
| `blockKnownAttacker` | `false` |
| `blockBot` | `false` |
| `blockSpam` | `false` |
| `blockCloudProvider` | `false` |
| `blockCorporateGateway` | `false` |
| `blockKnownGoodBots` | `false` |
| `blockThreatScoreAbove` | `-1` |
| `dryRun` | `false` |
| `blockStatusCode` | `403` |
| `blockMessage` | `Access denied.` |
| `blockRedirectURL` | |
| `failOpen` | `true` |
| `cacheSize` | `10000` |
| `cacheTTL` | `1h` |
| `logLevel` | `info` |

Field names you can use in `headers` are listed in the [README](README.md#field-reference).
