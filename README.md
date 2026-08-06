# generic-text-gateway

A self-hosted SMS gateway built from a **USB cellular modem** (2G/3G/4G/5G stick with a
serial AT port) and a SIM card. Replaces phone-app-based SMS gateways.

Two components:

- **`server/`** (`gtg-server`) — runs where the modem is plugged in. Owns the modem
  (discovery, ZeroCD mode switching, AT command dispatch, PDU encoding, SIM PIN handling)
  and exposes an authenticated HTTPS API (auto self-signed TLS) plus a minimal embedded
  web UI for sending SMS and watching incoming messages live.
- **`client/`** (`gtg-client`) — runs anywhere. Connects to the server with certificate
  pinning, relays inbound SMS into **Home Assistant** (event + sensor), and exposes a
  small local HTTP endpoint so HA can send SMS with a plain `rest_command`.

Python 3, stdlib only — the single dependency is **pyserial** from your distro
(`py3-pyserial` on Alpine, `python3-serial` on Debian). No pip, ever.

See [PLAN.md](PLAN.md) for the full architecture and design decisions.

## Privacy-first defaults

- **No message persistence**: incoming SMS are broadcast live to all connected
  subscribers (API clients, open web UIs) and are *not* written to disk unless you
  explicitly set `GTG_STORE_DIR`. The SIM's own storage bridges crashes and offline gaps.
- **SIM PIN never has to touch disk**: leave `GTG_SIM_PIN` unset and enter the PIN after
  a reboot via the web UI (or `POST /v1/sim/pin`) — it is held in memory only.
- Server listens on **localhost only** by default (IPv4 + IPv6); exposing it to the
  network is an explicit decision.

## Quick start (server, Docker)

```sh
cd server
# edit docker-compose.yml: set GTG_TOKENS, check the /dev/ttyUSB* device mappings
docker compose up -d --build
docker compose exec gtg-server gtg-server fingerprint   # pin for your clients
```

Or natively on Alpine:

```sh
apk add --allow-untrusted generic-text-gateway-*.apk    # from the GitHub release
vi /etc/conf.d/gtg-server                               # set GTG_TOKENS etc.
rc-update add gtg-server default && rc-service gtg-server start
```

The package pulls `python3`, `py3-pyserial` and `openssl`. **`usb-modeswitch` is
optional**: sticks in the built-in switch table (see below) are flipped out of their
fake-CD-ROM mode by a pure-stdlib `usbdevfs` implementation — no external tool. Install
`usb-modeswitch` only as a fallback for untested device variants.

Probe your hardware first if unsure: `gtg-server probe` prints every candidate serial
port, what answered `AT`, and the modem's identity.

## Quick start (client, Docker)

```sh
cd client
# edit docker-compose.yml: GTC_SERVER_URL, GTC_SERVER_TOKEN, GTC_SERVER_PIN_SHA256,
# GTC_HA_URL, GTC_HA_TOKEN
docker compose up -d --build
```

Home Assistant then sends SMS via the compat endpoint (android-sms-gateway shape):

```yaml
rest_command:
  send_sms:
    url: "http://127.0.0.1:8082/message"
    method: POST
    username: !secret sms_user
    password: !secret sms_pass
    content_type: "application/json"
    payload: '{"textMessage": {"text": {{ message | to_json }}}, "phoneNumbers": ["+15551234567"]}'
```

Incoming SMS arrive as HA event `sms_received` (payload: `phoneNumber`, `message`,
`messageId`, `receivedAt`) and on `sensor.sms_received`.

## API (server)

All endpoints under HTTPS, `Authorization: Bearer <token>` (scoped tokens via
`GTG_TOKENS=all:tok1,send:tok2,receive:tok3`) or `Basic` (web UI credentials).

| Endpoint | Purpose |
|---|---|
| `GET /healthz` | liveness (no auth) |
| `GET /v1/health` | modem/SIM/registration/signal state |
| `POST /v1/messages` | send: `{"to": ["+15551234567"], "text": "hi"}` |
| `GET /v1/messages/<id>` | outbound state (`submitted`, `failed`, `submission_unknown`) |
| `GET /v1/subscribe` | SSE stream of incoming SMS (broadcast to all subscribers) |
| `POST /v1/sim/pin` | enter the SIM PIN at runtime (memory-only) |
| `GET /v1/history` | paged history (only when `GTG_STORE_DIR` is set) |

Web UI: `https://<host>:8443/ui`.

## Configuration

Everything is settable via environment variables (`GTG_*` / `GTC_*`), with an optional
INI config file (`GTG_CONFIG=/etc/generic-text-gateway/gateway.conf`); env wins.
The full reference tables are in [PLAN.md](PLAN.md) §3.11 (server) and §4.4 (client).

### Hashed credentials (recommended)

Server-side secrets don't have to be stored in plaintext — keep only hashes in the
config; the plaintext token lives solely with its consumer (your client/HA):

```sh
# Web UI password -> PBKDF2-SHA256 (interactive, nothing stored or echoed):
gtg-server hash-password
#   GTG_WEBUI_PASS_HASH=pbkdf2_sha256$210000$<salt>$<dk>

# API token -> sha256 (type the token on stdin, keeps it out of shell history):
gtg-server hash-token
#   sha256:<64 hex>
```

Put the results in your config:

```sh
export GTG_TOKENS='receive:sha256:<hex>,send:sha256:<hex>'
export GTG_WEBUI_PASS_HASH='pbkdf2_sha256$210000$<salt>$<dk>'
```

⚠️ **Single quotes are mandatory** for the password hash: it contains `$` characters —
double quotes (or no quotes) make the shell expand them away when the service sources
the file, silently breaking login. `GTG_WEBUI_PASS_HASH` takes precedence if the plain
`GTG_WEBUI_PASS` is also set. A hash cannot be reversed: if a plaintext token is lost,
generate a new token and replace the hash. The SIM PIN (`GTG_SIM_PIN`) cannot be
hashed — it must be sent to the modem as-is; protect the config file (mode 600)
instead.

## Tested hardware

| Modem | USB IDs | Mode switch | Notes |
|---|---|---|---|
| Huawei E1750 | `12d1:1446` → `12d1:1001` | built-in (no usb-modeswitch needed) | AT port = first `ttyUSB` |

Any stick that exposes a serial AT port and answers `AT+CMGF`/`AT+CMGS` should work —
run `gtg-server probe` and open an issue with the output to get it added here.

**Add native support for your stick — PRs welcome!** ZeroCD mode switching lives in one
table: `KNOWN_SWITCHES` in `server/gtg_server/modem/modeswitch.py`. A recipe is just the
installer-mode USB ID, the bulk switch message (find it for your device in usb_modeswitch's
database, `/usr/share/usb_modeswitch/`), the interface/endpoint, and the expected
post-switch USB IDs. If your stick works via the `usb_modeswitch` fallback today, adding
its recipe makes it work with zero external dependencies — please open a pull request with
the recipe and your `gtg-server probe` output. Never add guessed messages: only recipes
verified on real hardware.

## Development

```sh
PYTHONPATH=server python3 -m unittest discover -s server/tests
PYTHONPATH=client python3 -m unittest discover -s client/tests
./server/bin/gtg-server probe        # dev entry points, no install needed
```

All example phone numbers in this repo are fake.
