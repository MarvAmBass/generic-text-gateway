# Generic Text Gateway — Implementation Plan

A self-hosted SMS gateway built from a **USB cellular modem** (3G/4G/LTE/5G stick) and a SIM
card, replacing phone-app-based SMS gateways. Two components in this repo:

- **`server/`** — runs on the machine the modem is plugged into. Owns the modem (discovery,
  mode switching, AT dispatch, PDU encoding, SIM PIN), persists messages, and exposes an
  **authenticated HTTPS API** (auto self-signed TLS or externally provided certs) for sending
  and receiving SMS.
- **`client/`** — runs anywhere. Connects to the server with **certificate pinning**, relays
  inbound SMS into **Home Assistant** (event + sensor), and exposes a small local HTTP endpoint
  so HA (or anything else) can send SMS without dealing with TLS/pinning itself.

Language: **Python 3**, stdlib-only wherever possible. The single third-party dependency is
**pyserial**, consumed as a distro package (`py3-pyserial` on Alpine, `python3-serial` on
Debian) — **no pip at runtime, ever**.

All example phone numbers in this repo are fake (`+15551234567` style).

---

## 1. Goals / non-goals

**Goals**

- Support as many USB modems as practical: 2G/3G sticks (e.g. Huawei E1750, tested),
  LTE/4G and 5G modems — anything that exposes a **serial AT port** (Level A below).
- Robust unattended operation: survives USB re-enumeration, modem resets, server reboots.
- Reliable send semantics: no duplicate sends. Inbound: **fan-out to ALL connected
  subscribers** (not just one), with the SIM storage acting as the crash/offline buffer.
- **Privacy-first defaults**: message contents are NOT persisted to disk unless a store
  directory is explicitly configured. The SIM PIN can be provided at runtime (web UI or
  API) instead of via config — then it lives in memory only and is never written to disk.
- Optional **minimal embedded web UI**: login, send box, live incoming-message feed,
  runtime PIN entry, and a history browser (history only when the file store is enabled).
- Full configuration via **environment variables**; optional **config file** (INI); env wins.
- Ship as: multi-arch container images, **Alpine apk** (noarch), **Debian deb** (all) — built
  by GitHub workflows.

**Non-goals (v1)**

- Mobile data / PPP / QMI / MBIM data connections — SMS only.
- HiLink/router-mode modems with only a vendor HTTP API (plugin point reserved, not built).
- MMS, binary SMS, delivery reports (schema reserves fields; implementation later).
- Multi-modem per server (design keeps a `modem_id` in the schema so it can come later).

---

## 2. Architecture

```
                       separate machine (modem host)                 anywhere (e.g. HA host)
                 ┌──────────────────────────────────────┐      ┌──────────────────────────────┐
  ┌─────────┐    │  generic-text-gateway  (server)      │      │  generic-text-client         │
  │ USB     │    │                                      │      │                              │
  │ modem + │◄──►│  ModemWorker (single serial owner)   │ TLS  │  SSE subscriber ──► HA       │
  │ SIM     │    │      │                               │◄────►│  (event + sensor)            │
  └─────────┘    │      ▼                               │ pin  │                              │
                 │  Broadcast hub (RAM ring)            │      │  local HTTP :8082  ◄── HA    │
                 │   ├── optional file store            │      │  POST /message | /v1/send    │
                 │   ▼                                  │      └──────────────────────────────┘
                 │  HTTPS API + embedded Web UI :8443   │            browsers (Web UI)
                 │  (Authorization: Bearer | Basic)     │◄────────── EventSource /v1/subscribe
                 └──────────────────────────────────────┘
```

- Exactly **one** component (ModemWorker thread) reads/writes the serial port.
- The API layer never touches the modem directly; it enqueues jobs and reads the hub.
- Client/browser → server is always client-initiated (works through NAT; one TLS endpoint).
- Inbound delivery is **broadcast**: every connected subscriber (gtg-client instances, open
  web UIs) receives every message. Nothing touches disk unless the file store is enabled;
  the SIM's own storage bridges crashes and subscriber-less periods (see 3.7).

### Modem compatibility levels

| Level | Description                                   | v1 support |
|-------|-----------------------------------------------|------------|
| A     | Serial AT port (`/dev/ttyUSB*`, `/dev/ttyACM*`) | ✅ primary |
| B     | ModemManager via D-Bus                        | plugin point reserved |
| C     | Vendor HTTP API (HiLink etc.)                 | plugin point reserved |
| D     | No accessible interface                       | ❌ report in health |

---

## 3. Server (`server/`)

Package name: `gtg_server`. Entry point: `gtg-server` (console script) with subcommands:
`run` (default), `fingerprint` (print TLS cert SHA-256), `probe` (one-shot discovery report,
useful for bug reports), `send` (CLI one-shot send for testing).

### 3.1 Modem discovery (`modem/discovery.py`)

1. Enumerate `serial.tools.list_ports.comports()` → device, VID/PID, manufacturer, product,
   serial number, sysfs `location`.
2. Filter to `ttyUSB*` / `ttyACM*` (plus explicit `GTG_SERIAL_PORT` override, which skips
   discovery entirely).
3. Probe each candidate: open 115200 8N1, drain, `AT\r`, expect `OK` (2 retries, short
   timeout). Some sticks expose 3–5 ports (AT / data / diag / NMEA); pick the first that
   answers reliably, prefer ports whose sibling-count/interface-number matches a known-good
   entry in the modem DB.
4. Identify: `ATI`, `AT+CGMI`, `AT+CGMM`, `AT+CGMR`, `AT+CGSN`. Unsupported commands don't
   disqualify a modem.
5. Bind the chosen port to the physical device by **USB serial number + sysfs ancestry**,
   not by `/dev/ttyUSB0` name — re-resolve after every reconnect.

### 3.2 Mode switching (`modem/modeswitch.py`)

Many sticks enumerate first as USB mass storage ("ZeroCD"). The "switch" is just a known
31-byte USB mass-storage CBW written to the stick's bulk endpoint — Linux exposes exactly
that via `usbdevfs` ioctls on `/dev/bus/usb/*`, so **no external tool or library is
required**. Strategy, in order:

1. **Built-in switcher** (pure stdlib, `usbdevfs.py`): for USB IDs in the internal
   `KNOWN_SWITCHES` table, detach the kernel driver, claim the interface, bulk-write the
   recipe's message (ctypes ioctls; struct sizes computed at import so 32-/64-bit both
   work). E.g.:

   ```python
   KNOWN_SWITCHES = {
       (0x12D1, 0x1446): {           # Huawei ZeroCD (tested: E1750)
           "name": "Huawei ZeroCD",
           "message": HUAWEI_ZEROCD_MESSAGE,     # 31-byte CBW, field-tested
           "interface": 0, "endpoint": 0x01,
           "helper_args": ["-v", "0x12d1", "-p", "0x1446", "-J"],
           "expected_ids": [(0x12D1, 0x1001)],   # list — firmware variants differ
       },
   }
   ```

2. **`usb_modeswitch` fallback** — optional (Recommends, not Depends): used only when the
   built-in write fails; its community device database also covers quirky variants.
3. Wait for the device to disappear and reappear with an expected ID, then wait for
   `/dev/ttyUSB*` nodes (with timeout; `option`/`usbserial` usually auto-load — the server
   never calls modprobe itself; packaging docs cover it).
4. **Never** send a guessed switching message to an unknown USB ID. Unknown storage-mode
   devices are reported in health as "possible unswitched modem (VID:PID)" with a docs link.

Re-run the switch check whenever the AT port vanishes and a known storage-mode ID reappears
(stick reset back to ZeroCD).

### 3.3 AT dispatcher (`modem/at.py`)

The core correctness component. Single `ModemWorker` thread owns the serial handle:

- **Command queue**: one command in flight at a time; each command = (line(s), terminator
  set, timeout, optional `>`-prompt payload phase for `AT+CMGS`). Responses matched to the
  active command.
- **URC handling**: lines arriving outside a command (or interleaved) that match unsolicited
  patterns (`+CMTI:`, `+CMT:`, `+CDS:`, `RING`, `NO CARRIER`, `^…` vendor noise) are routed
  to an event queue, never treated as command responses.
- **Timeouts & recovery**: per-command timeout; on serial exception → close handle, mark
  modem offline, re-enter discovery loop (with modeswitch check), reapply init sequence
  (`ATE0`, `AT+CMEE=1`, CMGF, CPMS, CNMI), reconcile stored messages.
- Init also sets `AT+CMEE=1` so errors come back as `+CME ERROR: <n>` codes we can map.

### 3.4 SMS encoding (`modem/sms_codec.py`)

**PDU-first** (deviation from the operator doc's "text mode first" — PDU gives deterministic
encoding for umlauts/emoji/multipart on every modem that supports `AT+CMGF=0`, which is
nearly all):

- Outbound: GSM 7-bit default alphabet (incl. basic-table umlauts) when the text fits,
  else UCS-2; concatenated multipart with UDH (8-bit ref) when over 160/70 chars
  (153/67 per part). Alphanumeric + international numeric addresses.
- Inbound: full PDU decode (deliver PDUs): sender, SMSC timestamp w/ timezone, DCS,
  UDH/multipart reassembly (buffer parts, emit complete message; flush incomplete after a
  timeout with `partial: true`).
- Fallback: if `AT+CMGF=0` is rejected (`AT+CMGF=?` says text only), use text mode with
  charset from `AT+CSCS` (prefer `"GSM"`, else `"UCS2"` hex).
- Pure Python, zero deps, heavily unit-tested against fixture PDUs (this is where the tests
  earn their keep).

### 3.5 Receiving strategies (`modem/receive.py`)

Capability-probe with `AT+CNMI=?`, `AT+CPMS=?`, `AT+CMGL=?`, then select (recorded in health):

1. **Stored-message notification** (preferred): `AT+CNMI=2,1,0,0,0` → on `+CMTI: "<mem>",<i>`
   read `AT+CMGR=<i>`, persist, then `AT+CMGD=<i>`.
2. Direct delivery `AT+CNMI=2,2,0,0,0` (`+CMT:`) — only used if 1 is unsupported, since it
   loses messages when nobody is reading.
3. Poll `AT+CMGL="REC UNREAD"` (PDU: `AT+CMGL=4` reads ALL — see 4) every
   `GTG_POLL_INTERVAL` (default 15 s).
4. Poll ALL + dedup by (storage, index, sender, timestamp, body-hash).

**Reconciliation** (always on, regardless of strategy): every `GTG_RECONCILE_INTERVAL`
(default 300 s) list stored messages to catch anything missed across restarts/reconnects —
the doc's "notification + periodic reconciliation" combo. Storage: probe `AT+CPMS=?`, prefer
`"SM"` but use what the modem offers.

**Deletion from modem storage** follows the delivery policy in 3.7 (delivered-to-≥1-subscriber,
or persisted-to-store). Failed deletes are retried; dedup prevents double-processing.
Multipart: parts are deleted only after the full message was reassembled **and** delivered/
persisted; an incomplete set flushed as `partial: true` keeps its parts until that partial
delivery succeeds.

### 3.6 SIM / PIN (`modem/sim.py`)

`AT+CPIN?` on startup and after every reconnect:

- `READY` → proceed.
- `SIM PIN` → submit `GTG_SIM_PIN` **only if configured**, max `GTG_SIM_PIN_MAX_TRIES`
  (default **1** — a wrong configured PIN must not burn all 3 attempts). Re-query after a
  few seconds. If no PIN configured → health = `sim_pin_required`, API + web UI stay up
  (health visible), sending disabled, and the server waits for a **runtime PIN**.
- **Runtime PIN entry** (`POST /v1/sim/pin`, also surfaced as a modal in the web UI): for
  operators who refuse to store the PIN on the device. The submitted PIN is held **in
  memory only** — never written to disk, never logged, redacted from every error string —
  and must be re-entered after a reboot/power loss. Exactly one modem submission per API
  call; the response reports the resulting CPIN state. Requests are rejected (409) when the
  SIM isn't asking for a PIN, and **never** forwarded when the SIM reports `SIM PUK`.
  If `GTG_SIM_PIN` *is* configured, it wins at boot and the endpoint is a no-op (409).
  **Abuse guard**: the endpoint requires `all` scope — Basic web-UI credentials qualify,
  a leaked receive/send token does not (it must not be able to PUK-lock the SIM) — and
  regardless of caller the
  server accepts at most `GTG_SIM_PIN_MAX_TRIES` + 2 runtime submissions per process
  lifetime — after that it refuses (423) until restart, logging loudly. Where the modem
  reports remaining attempts (`AT^CPIN?` etc.), a last-attempt state is surfaced and the
  server refuses to spend the final try automatically.
- `SIM PUK` → **never** attempt; health = `sim_puk_required`, loud log, sending disabled.
- The PIN is never logged and is redacted from error strings (env- and API-provided alike).

Then wait for registration: `AT+CREG?` (also try `AT+CEREG?`/`AT+CGREG?` for LTE devices);
send only in states 1 (home) or 5 (roaming). `AT+CSQ` + `AT+COPS?` feed health.

### 3.7 Delivery & retention model (`hub.py`, `store.py`)

**Default: nothing is persisted.** No database. The moving parts:

- **Broadcast hub** (RAM): every inbound message gets a monotonic id (per server run,
  alongside a random `server_run_id` so consumers detect restarts) and is pushed to **every
  connected subscriber** — each subscriber (gtg-client, open web UI, curl) has its own
  bounded queue, so one slow consumer never blocks the others (a lagging subscriber gets a
  `gap` marker instead of unbounded buffering).
- **Replay ring** (RAM): the last `GTG_RING_SIZE` (default 100) messages. A subscriber that
  reconnects with `Last-Event-ID`/`after=<id>` replays what it missed from the ring.
- **Pending ≠ replay**: a message that has never been delivered to *any* subscriber lives in
  a **pending queue**, not just the ring — it is handed to the next receive-scope subscriber
  even one that connects in tail mode (no/invalid cursor). Rationale: tail mode exists to
  skip *history a client chose not to resume* (replay), never to skip *first-time
  deliveries* — e.g. SMS that arrived on the SIM while server and clients were down.
- **SIM storage as crash buffer**: an inbound message is deleted from the modem/SIM only
  after it was **delivered to at least one subscriber** (socket write succeeded) — or, when
  the file store is enabled, after it was persisted. With **no subscriber connected and no
  store**, messages simply remain on the SIM; the reconciliation pass reads and broadcasts
  them as soon as a subscriber appears. So a power loss never eats messages that nobody
  saw — at the cost of the SIM's small capacity (~20–30; health reports storage usage and
  warns when nearly full).
- **Optional file store** (`GTG_STORE_DIR`, unset by default): when set, each message is
  written as one JSON file (`inbox/2026-01-01T120000+0100_+15551234567_<id>.json`, same for
  `outbox/`) — greppable, rsyncable, no database. Enables the history API and the web UI's
  scrollable history; delete-from-SIM then happens after the file is fsynced.
- **Store-on semantics upgrade — durable replay**: with the store enabled, the id counter
  and the stream identity are persisted too (`GTG_STORE_DIR/stream.json`: stable stream id
  replacing the per-run `server_run_id`, plus the last assigned id). Server restarts no
  longer reset the stream, so a subscriber's saved cursor stays valid across them, and
  `Last-Event-ID=N` is answered from the **files** for anything older than the RAM ring
  (the ring becomes a cache). Net effect: full at-least-once for every subscriber — a
  message consumed only by some other subscriber (e.g. an open web UI) while a client was
  down is recovered from history on reconnect, which is exactly the window that exists in
  store-off mode. No per-subscriber delivery bookkeeping needed; each client's cursor is
  the only progress state.

**Outbound state machine** (prevents duplicate sends — the Ctrl+Z-timeout problem), kept in
RAM (and mirrored to `outbox/` files when the store is enabled):

```
queued → sending → submitted (+CMGS ref stored)
                 → failed (definitive CMS/CME error)
                 → submission_unknown (timeout after payload sent — NEVER auto-retried;
                                       surfaced via API so the caller decides)
```

Each outbound accepts an optional client-supplied `idempotency_key`; replays within the
in-memory window return the original record instead of sending again.

`GTG_DATA_DIR` (default `/var/lib/generic-text-gateway`) holds only the generated TLS
material — with the store disabled, no message content ever touches it.

### 3.8 HTTPS API

Stdlib `ThreadingHTTPServer` + `ssl` (same pattern as proven HA-listener code). JSON only.

**Binding** (`GTG_LISTEN`): comma-separated list of `host:port` / `[v6addr]:port` entries;
each entry is resolved with `getaddrinfo` and **every returned address family gets its own
listener socket** — full IPv4 + IPv6 support with zero special syntax. Default:
`localhost:8443` → binds `127.0.0.1:8443` **and** `[::1]:8443` (loopback only — exposing
the server to the LAN is an explicit operator decision, e.g.
`GTG_LISTEN=0.0.0.0:8443,[::]:8443` or a specific interface address).

| Method/path                | Auth scope | Purpose |
|----------------------------|-----------|---------|
| `GET /healthz`             | none      | liveness only (`{"status":"ok"}`) for container healthchecks |
| `GET /v1/health`           | any       | full health (see 3.12) |
| `GET /v1/modem`            | any       | manufacturer/model/firmware/IMEI/port/USB IDs |
| `POST /v1/messages`        | send      | `{"to": ["+15551234567"], "text": "...", "idempotency_key": "..."}` → `202 {"id": 41, "state": "queued"}` |
| `GET /v1/messages/<id>`    | send      | outbound state (incl. `submission_unknown`) |
| `GET /v1/subscribe`        | receive   | **SSE stream** (`text/event-stream`): every inbound message as `event: message` with `id: <n>` (so browsers' `EventSource` and the client resume via `Last-Event-ID` / `?after=<id>` from the replay ring); `event: health` on state changes; comment heartbeat every 15 s. **Broadcast — every connected subscriber gets every message.** |
| `POST /v1/sim/pin`         | `all`     | runtime SIM PIN entry (memory-only + abuse guard, see 3.6) |
| `GET /v1/history?box=inbox&before=…&limit=…` | receive | paged history — **404 unless `GTG_STORE_DIR` is configured**; pages over an internal index by message id — client input is never used to build file paths |

**Auth mechanics — one mechanism, the `Authorization` header, two forms**:
`Bearer <token>` (API clients) and `Basic <user:pass>` (web UI; Basic credentials count as
`all` scope — with `GTG_WEBUI_USER` unset, Basic with an API token as the password grants
that token's scope). No cookies, no server-side sessions, no CSRF tokens — there is no
ambient credential to ride; as belt-and-suspenders, mutating endpoints require
`Content-Type: application/json`, which cross-site forms cannot send. `EventSource` can't
set *custom* headers, but browsers attach cached Basic credentials to it automatically
after the 401 challenge — which is exactly why UI auth is Basic. Tokens are **never**
accepted in query strings (they'd leak into logs/proxies/browser history).
Connection hygiene: `GTG_MAX_SUBSCRIBERS` caps concurrent SSE streams (excess → 503 +
`Retry-After`), and all request parsing runs under short header/body read timeouts
(slowloris guard) — `ThreadingHTTPServer` is one thread per connection, so streams are the
resource to protect. Outbound sending is rate-limited (`GTG_SEND_RATE`) as a cost brake
against leaked send tokens *and* runaway automations on the caller's side.

Errors: proper status codes + `{"error": {"code": "...", "message": "..."}}`. A `Retry-After`
is set when the modem is offline/unregistered (503).

SSE was chosen over long-poll/webhooks: natural fan-out to N subscribers, works unchanged in
browsers (`EventSource` powers the web UI's live feed), client-initiated (NAT-friendly), and
`Last-Event-ID` + replay ring + SIM-side buffering (3.7) + client-side dedup still give
solid delivery semantics without any server-side persistence.

### 3.9 TLS (`tlsutil.py`)

- `GTG_TLS_CERT` / `GTG_TLS_KEY` set → use provided files (external CA, ACME, whatever).
- Otherwise **auto-TLS**: on first start generate a self-signed cert into `GTG_DATA_DIR`
  via the **`openssl` CLI** (subprocess; declared package dependency — stdlib can't mint
  certs and pip is off-limits): EC P-256, 3650 days, SANs from `GTG_TLS_SANS`
  (default: hostname + detected IPs). Reused on every subsequent start (stable pin).
- On startup, log the **SHA-256 fingerprint of the DER cert** prominently;
  `gtg-server fingerprint` prints it for out-of-band transfer to clients.
- `GTG_TLS=off` allowed for reverse-proxy/loopback setups (refuses to bind non-loopback
  unless `GTG_TLS_INSECURE_OK=true`).

### 3.10 Authentication

- Bearer tokens, compared with `hmac.compare_digest`.
- `GTG_TOKENS` = comma list of `scope:token` entries; scopes: `send`, `receive`, `all`.
  Example: `GTG_TOKENS=all:s3cr3t-ops,send:ha-send-only,receive:client-inbox`.
- Failed auth: 401, per-IP exponential backoff after repeated failures (in-memory).
- Optional `GTG_ALLOWED_RECIPIENTS` (comma list / prefixes) as a safety net against a
  leaked send token running up the bill.

### 3.11 Configuration

Precedence: **env > config file > defaults**. Config file: INI (`configparser`),
`GTG_CONFIG=/etc/generic-text-gateway/gateway.conf`, one `[gateway]` section whose keys are
the env names minus the prefix (`sim_pin = 1234` ≙ `GTG_SIM_PIN=1234`).

| Env | Default | Meaning |
|-----|---------|---------|
| `GTG_SERIAL_PORT` | `auto` | AT port path, or `auto` for discovery |
| `GTG_BAUD` | `115200` | serial baud |
| `GTG_SIM_PIN` | *(unset)* | SIM PIN; only submitted when the SIM asks |
| `GTG_SIM_PIN_MAX_TRIES` | `1` | PIN submissions per process lifetime |
| `GTG_LISTEN` | `localhost:8443` | comma list of binds; IPv4+IPv6 per entry (3.8); loopback-only by default |
| `GTG_TLS` | `auto` | `auto` \| `provided` \| `off` |
| `GTG_TLS_CERT` / `GTG_TLS_KEY` | *(unset)* | external cert/key (implies `provided`) |
| `GTG_TLS_SANS` | auto-detected | comma list for generated cert |
| `GTG_TOKENS` | *(required)* | `scope:token,...` — server refuses to start without |
| `GTG_ALLOWED_RECIPIENTS` | *(unset = all)* | recipient allowlist/prefixes |
| `GTG_DATA_DIR` | `/var/lib/generic-text-gateway` | generated TLS material only |
| `GTG_STORE_DIR` | *(unset = no persistence)* | opt-in file store for message history (3.7) |
| `GTG_RING_SIZE` | `100` | in-RAM replay ring for reconnecting subscribers |
| `GTG_WEBUI` | `true` | serve the embedded web UI at `/ui` (set `false` to disable) |
| `GTG_WEBUI_USER` / `GTG_WEBUI_PASS` | *(unset)* | web UI login; unset → UI accepts an API token as login |
| `GTG_POLL_INTERVAL` | `15` | inbound poll seconds (fallback strategies) |
| `GTG_RECONCILE_INTERVAL` | `300` | stored-message reconciliation seconds |
| `GTG_MAX_SUBSCRIBERS` | `20` | concurrent SSE connections cap |
| `GTG_SEND_RATE` | `30/hour` | outbound rate limit (`N/minute`, `N/hour`, `N/day`; `0` = off) |
| `GTG_MODESWITCH` | `true` | allow usb_modeswitch for known IDs |
| `GTG_LOG_LEVEL` | `info` | `debug` logs AT traffic (PIN always redacted) |
| `GTG_LOG_BODIES` | `false` | include SMS bodies in logs |

(Secrets that shouldn't sit in envs can go in the INI config file instead — same keys,
already supported by the precedence chain. No extra mechanism needed.)

### 3.12 Health (`GET /v1/health`)

Everything the operator doc lists: usb_present, port, at_ok, modem identity, USB VID/PID,
sim_state (`ready|pin_required|puk_required|absent`), registration (creg/cereg/cgreg),
operator, signal (CSQ → dBm + percent), receive_strategy, storage usage, counts, last_inbound
/ last_outbound timestamps, last_error, uptime, version. State machine summarized in a single
top-level `state: ok|degraded|down` for dumb monitors.

### 3.13 Embedded web UI (`/ui`)

Optional (`GTG_WEBUI`, default on), aimed at "minimal but genuinely useful":

- **One static, self-contained HTML file** (vanilla JS + inline CSS, no build step, no CDN,
  no external requests) embedded in the Python package and served by the same HTTPS server.
- **Login = HTTP Basic** (see 3.8): `/ui` answers 401 + `WWW-Authenticate: Basic` until the
  browser supplies `GTG_WEBUI_USER`/`GTG_WEBUI_PASS` (or any-user + API token as password).
  The browser's native prompt handles it once and then attaches the credentials to every
  fetch and EventSource call — zero auth JavaScript, zero cookies, zero server-side session
  state. Log out = close the browser (documented honestly). Same backoff-on-failure as the
  API. Responses carry a strict self-only `Content-Security-Policy`.
- **Send panel**: number + text box → `POST /v1/messages`; shows the resulting state
  (`submitted` / `failed` / `submission_unknown`) and the +CMGS ref.
- **Live feed**: `EventSource('/v1/subscribe')` — incoming SMS appear in real time while
  the tab is open. Multiple open tabs are just multiple subscribers (broadcast hub); they
  all get every message. With the store disabled, the feed is ephemeral by design: close
  the tab, see nothing old on return (except the RAM replay ring via `Last-Event-ID`).
- **History browser**: only rendered when `/v1/history` reports the store is enabled —
  scroll/page through the persisted inbox (and outbox) files.
- **PIN modal**: when the health stream reports `sim_pin_required`, the UI prompts for the
  PIN and posts it to `/v1/sim/pin` — the manual-after-reboot flow for operators who don't
  store the PIN on the device. The field is `type=password`, never persisted (no
  localStorage), and the UI shows remaining-attempts info from the response.
- Health strip: modem/SIM/registration/signal at the top, fed by `event: health`.

---

## 4. Client (`client/`)

Package `gtg_client`, entry point `gtg-client`. **Pure stdlib** (no pyserial). Two loops in
one process + a small local HTTP server:

### 4.1 Flows

- **Inbound**: subscribe to the server's SSE stream (`GET /v1/subscribe`, stdlib
  `http.client` reading the chunked stream; reconnect with backoff, resuming via
  `Last-Event-ID` = last processed message id, persisted in the state dir together with the
  `server_run_id`). For each message:
  1. POST HA event `GTC_HA_EVENT` (default `sms_received`) — payload below;
  2. update sensor `GTC_HA_SENSOR` (default `sensor.sms_received`).
  The client is just one subscriber among many (open web UIs etc. receive the same
  messages).

  **Exactly-no-retrigger guarantee** (a restarted client must never re-fire automations —
  at-most-once into HA, by design):
  1. *Durable cursor*: last processed id + `server_run_id`, fsynced in `GTC_STATE_DIR`;
     reconnects resume via `Last-Event-ID`, so the ring only replays strictly newer ids.
  2. *No cursor → no replay*: missing/invalid state file means subscribe from **now**
     (tail mode) — a fresh client can never flush ring history into HA.
  3. *Run/stream-id change*: an unknown stream id invalidates the cursor → tail from now
     (old-run messages the client saw were already deleted from the SIM at delivery, so the
     server cannot re-broadcast them either). With a store-enabled server (durable stream
     id, 3.7) this case only occurs when the operator wipes/replaces the store — server
     restarts alone keep the cursor valid and are bridged losslessly from history.
  4. *Mark-then-fire journal*: a **stable content hash** (sender + SMSC timestamp + body,
     computed server-side) is appended to a processed-journal (bounded, in the state dir)
     **before** the HA event POST; replayed messages whose hash is journaled are skipped.
     Hashes rather than ids: ids reset when a store-less server restarts, the hash of a
     given SMS never does — so even a message re-read from the SIM after a crashed server
     restart cannot re-fire. A crash between journal-write and HA-POST drops that one
     message instead of doubling it — the correct bias for toggle-style automations.
  5. *HA-POST failure policy* (same bias): retry with backoff **only** on errors where the
     request provably never arrived (connect refused, DNS, TLS setup); on ambiguous
     failures (timeout after the request was sent, 5xx) drop and log — never blind-retry
     an event POST that might already have fired an automation.
  6. *Gap events*: a `gap` marker from the server (slow-subscriber overflow, store-off) is
     surfaced as a distinct HA event (`<GTC_HA_EVENT>_gap`) + warning log, so "messages
     were missed" is visible instead of silent.
- **Outbound**: local HTTP (default `localhost:8082` — IPv4 + IPv6 loopback, plain HTTP;
  bind non-loopback only with auth configured):
  - `POST /v1/send` `{"to": ["+15551234567"], "text": "..."}` — clean API.
  - `POST /message` — **compat endpoint** accepting the android-sms-gateway shape
    `{"textMessage": {"text": "..."}, "phoneNumbers": [...]}` with HTTP Basic auth, so
    existing Home Assistant `rest_command` setups migrate by changing only the URL/creds.
  - Both normalize recipients (string/int/list → `+`-prefixed E.164 strings — absorbing the
    HA template-coercion footgun into the client).
  - Forwards to server `POST /v1/messages` with a client-generated `idempotency_key` per
    accepted local request; forwards are **never blind-retried** (an ambiguous failure is
    reported back to the caller as such — the key makes an explicit caller retry safe).
  - Basic auth is optional for pure-loopback use but **strongly recommended even there**:
    on a host-networking container box, every container shares `127.0.0.1`. The client
    warns at startup when the bind is reachable and auth is unset.

### 4.2 Certificate pinning

`http.client.HTTPSConnection` with a no-verify `ssl` context, then manually verify
`sha256(getpeercert(binary_form=True))` against the configured pin **before** sending any
bytes (incl. the auth header). Modes:

- `GTC_SERVER_PIN_SHA256=<hex>` — explicit pin (recommended; value from
  `gtg-server fingerprint`).
- `GTC_SERVER_PIN_TOFU=true` — trust-on-first-use: store the first-seen fingerprint in the
  state dir, hard-fail on any later change.
- `GTC_SERVER_CA=<path>` — classic CA verification instead of pinning (for `provided` certs).

### 4.3 Home Assistant payload (compat)

Event payload matches the android-sms-gateway webhook shape so downstream automations keep
working unchanged:

```json
{
  "event": "sms:received",
  "deviceId": "generic-text-gateway",
  "payload": {
    "messageId": "<server inbound id>",
    "phoneNumber": "+15551234567",
    "message": "text body",
    "receivedAt": "2026-01-01T12:00:00+01:00",
    "simNumber": null
  }
}
```

(`phoneNumber` is the field name real gateways used; consumers may also read `sender` —
both are set.)

### 4.4 Configuration (env > INI file > defaults)

| Env | Default | Meaning |
|-----|---------|---------|
| `GTC_SERVER_URL` | *(required)* | `https://modem-host:8443` |
| `GTC_SERVER_TOKEN` | *(required)* | server bearer token (receive or all scope) |
| `GTC_SERVER_SEND_TOKEN` | = SERVER_TOKEN | separate send-scope token if desired |
| `GTC_SERVER_PIN_SHA256` / `GTC_SERVER_PIN_TOFU` / `GTC_SERVER_CA` | — | exactly one pin mode |
| `GTC_HA_URL` | *(required for HA relay)* | e.g. `http://homeassistant:8123` |
| `GTC_HA_TOKEN` | *(required for HA relay)* | long-lived HA token |
| `GTC_HA_EVENT` / `GTC_HA_SENSOR` | `sms_received` / `sensor.sms_received` | HA targets |
| `GTC_LISTEN` | `localhost:8082` | local send API bind; same comma-list + IPv4/IPv6 semantics as `GTG_LISTEN` |
| `GTC_BASIC_USER` / `GTC_BASIC_PASS` | *(unset)* | Basic auth on `/message` + `/v1/send` |
| `GTC_STATE_DIR` | `/var/lib/generic-text-client` | cursor + TOFU pin |
| `GTC_LOG_LEVEL` / `GTC_LOG_BODIES` | `info` / `false` | logging |

---

## 5. Repository layout

```
generic-text-gateway/
├── PLAN.md
├── README.md
├── VERSION                          # single source of truth, e.g. 0.1.0
├── server/
│   ├── gtg_server/                  # package (api, hub, store, tlsutil, config, webui/
│   │                                #   index.html, modem/{discovery,modeswitch,at,
│   │                                #   sms_codec,receive,sim}.py)
│   ├── bin/gtg-server
│   ├── tests/                       # stdlib unittest; PDU fixtures, fake-modem transport
│   ├── Dockerfile
│   ├── docker-compose.yml
│   └── packaging/
│       ├── apk/APKBUILD             # arch="noarch"; depends: python3 py3-pyserial openssl
│       │                            #   usb-modeswitch; OpenRC initd + confd
│       ├── openrc/{gtg-server.initd, gtg-server.confd}
│       ├── deb/nfpm.yaml            # Architecture: all; Depends: python3, python3-serial,
│       │                            #   openssl, usb-modeswitch; systemd unit
│       └── systemd/gtg-server.service
├── client/
│   ├── gtg_client/
│   ├── bin/gtg-client
│   ├── tests/
│   ├── Dockerfile
│   └── docker-compose.yml
└── .github/workflows/
    ├── ci.yml                       # unittest matrix (3.11/3.12), both packages
    ├── docker-publish.yml           # multi-arch images → ghcr
    └── packages.yml                 # apk + deb artifacts, attach to releases on tags
```

## 6. Packaging

**Containers** (both Alpine-based, no pip):

- `server/Dockerfile`: `FROM alpine:3.20` + `apk add python3 py3-pyserial openssl
  usb-modeswitch` + `COPY gtg_server`. Compose maps the modem:
  ```yaml
  devices: ["/dev/ttyUSB0", "/dev/ttyUSB1", "/dev/ttyUSB2"]
  # for ZeroCD modeswitch also: "/dev/bus/usb"
  volumes: ["./data:/var/lib/generic-text-gateway"]
  environment: [ "GTG_TOKENS=all:change-me", ... ]   # inline envs only
  ```
- `client/Dockerfile`: `FROM alpine:3.20` + `apk add python3`. Compose: `network_mode: host`
  friendly, state volume, inline envs.

**apk**: `abuild` in an `alpine:latest` job container; `arch="noarch"`; subpackage
`generic-text-gateway-openrc`. Signed with an abuild key from repo secrets when present,
otherwise built with `-F` and documented `--allow-untrusted` install. Service:
`rc-update add gtg-server; /etc/conf.d/gtg-server` for env config.

**deb**: `nfpm` in the workflow (`Architecture: all`), systemd unit, env config via
`/etc/default/gtg-server` (referenced by the unit) or `/etc/generic-text-gateway/gateway.conf`.

## 7. CI (GitHub workflows)

- `ci.yml`: run `python -m unittest` for server+client on push/PR.
- `docker-publish.yml`: mirror of the proven winet-extractor workflow — buildx + QEMU
  (`linux/amd64, linux/arm64, linux/arm/v7`), push to
  `ghcr.io/<owner>/generic-text-gateway-server` and `...-client` (matrix over the two
  contexts), metadata-action tags (semver + latest), cosign signing.
- `packages.yml`: build apk + deb, upload as artifacts; on `v*.*.*` tags attach to the
  GitHub release.

## 8. Testing

- **sms_codec**: golden-file PDU encode/decode tests (GSM7 incl. umlauts, UCS-2/emoji,
  multipart, alphanumeric senders, timezone quirks). Highest-value tests in the repo.
- **at dispatcher**: fake transport replaying recorded modem transcripts (E1750 sessions,
  interleaved URCs, timeouts, mid-command disconnect).
- **API/hub**: spin up server with fake modem backend; auth, SSE fan-out (N subscribers all
  receive; slow-subscriber gap markers), `Last-Event-ID` replay, SIM-delete-after-delivery
  policy, runtime PIN endpoint (PUK refusal, scope gating, lifetime cap), subscriber cap,
  send rate limit, Basic-vs-Bearer auth paths, no-token-in-query, JSON-content-type
  enforcement, history 404-without-store + traversal attempts, idempotency.
- **web UI**: 401-challenge flow, token-as-password mode, backoff.
- **client**: fake server + fake HA; pinning accept/reject, TOFU persistence, SSE reconnect
  + dedup, compat payload.
- Manual hardware checklist in README (E1750 = reference device).

## 9. Security notes

- Tokens/PIN never logged; bodies logged only with `GTG_LOG_BODIES=true`.
- Runtime-entered PIN exists in process memory only — no disk, no logs, no session state.
- Message contents never touch disk unless `GTG_STORE_DIR` is explicitly set.
- Constant-time credential comparison; backoff on auth failures (Bearer and Basic alike).
- No cookies, no sessions → no CSRF surface; mutating endpoints additionally require
  `Content-Type: application/json`. Web UI page fully self-contained (no external
  resources), served with a strict CSP.
- TLS private key `0600` in data dir; server refuses plaintext on non-loopback binds
  without an explicit insecure flag. Losing the data dir regenerates the cert → all pinned
  clients hard-fail **by design**; runbook: `gtg-server fingerprint` → update
  `GTC_SERVER_PIN_SHA256` (or clear the TOFU pin file).
- Recipient allowlist + send rate limit bound the blast radius/cost of a leaked send token.
- Runtime PIN endpoint is privilege-gated + lifetime-capped so no API token class can
  PUK-lock the SIM (3.6).
- Service runs as a dedicated non-root user (`gtg`, in `uucp` on Alpine / `dialout` on
  Debian for tty access; container images use a non-root user + the mapped tty's group).
  Modeswitch may need elevated USB access — documented per platform, never silently root.
- History API pages by internal id only — client input never reaches the filesystem layer.
- SSE connection cap + read timeouts.
- No personal data in this repo — fake numbers only, config values only via env/file.

## 10. Milestones

1. **M1 — modem core**: discovery, modeswitch (E1750 path), AT dispatcher, text+PDU send,
   `gtg-server probe|send` CLI. *Success: SMS sent via CLI on the reference stick.*
2. **M2 — receive + hub**: receive strategies + reconciliation, broadcast hub + replay
   ring, SIM-delete policy, outbound state machine, optional file store.
3. **M3 — API + TLS + auth**: full HTTPS API incl. SSE subscribe + runtime PIN endpoint,
   auto-TLS, tokens, health.
4. **M4 — web UI**: embedded page (login/session, send panel, live feed, PIN modal,
   history browser).
5. **M5 — client**: pinning, SSE relay → HA, local send API (incl. `/message` compat).
6. **M6 — packaging/CI**: Dockerfiles, composes, APKBUILD, nfpm deb, all three workflows.
7. **M7 — hardening**: reconnect storms, SIM-full behavior, docs, README with
   supported-modem table.
