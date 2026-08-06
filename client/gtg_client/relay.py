"""Inbound relay: SSE subscribe (pinned) -> Home Assistant event + sensor.

No-retrigger rules (PLAN.md 4.1): durable cursor, tail mode without a cursor,
stream-id change detection, mark-then-fire journal, and HA-POST retry only on
errors where the request provably never arrived.
"""
import hashlib
import json
import time
import urllib.error
import urllib.request


class SSEReader:
    """Minimal SSE parser over an http.client response."""

    def __init__(self, response):
        self.response = response

    def events(self):
        event, data, event_id = None, [], None
        while True:
            raw = self.response.readline()
            if not raw:
                return
            line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
            if line == "":
                if event or data:
                    yield {"event": event or "message",
                           "data": "\n".join(data), "id": event_id}
                event, data, event_id = None, [], None
            elif line.startswith(":"):
                continue                          # heartbeat comment
            elif line.startswith("event:"):
                event = line[6:].strip()
            elif line.startswith("data:"):
                data.append(line[5:].lstrip())
            elif line.startswith("id:"):
                event_id = line[3:].strip()


class HAPoster:
    def __init__(self, cfg, logger):
        self.url = cfg.str("HA_URL").rstrip("/")
        self.token = cfg.str("HA_TOKEN")
        self.event = cfg.str("HA_EVENT")
        self.sensor = cfg.str("HA_SENSOR")
        self.log = logger

    def _post(self, path, payload):
        req = urllib.request.Request(
            self.url + path,
            data=json.dumps(payload).encode(),
            headers={"Authorization": "Bearer " + self.token,
                     "Content-Type": "application/json"},
            method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status

    def fire(self, msg):
        """Post the HA event (+ sensor, best effort).

        Retry policy: retry only when the request provably never arrived
        (connection refused / DNS / unreachable). Ambiguous failures (timeout
        after send, HTTP 5xx) -> raise AmbiguousDelivery: caller drops the
        message rather than risking a double automation trigger.
        """
        payload = {
            "event": "sms:received",
            "deviceId": "generic-text-gateway",
            "payload": {
                "messageId": str(msg.get("id", "")),
                "phoneNumber": msg.get("sender"),
                "sender": msg.get("sender"),
                "message": msg.get("text"),
                "receivedAt": msg.get("scts") or msg.get("received_at"),
                "partial": msg.get("partial", False),
                "simNumber": None,
            },
        }
        backoff = 2.0
        while True:
            try:
                self._post("/api/events/" + self.event, payload)
                break
            except (ConnectionRefusedError, ConnectionResetError) as e:
                self.log.warning("HA unreachable (%s) — retrying in %.0fs", e, backoff)
            except urllib.error.URLError as e:
                reason = getattr(e, "reason", None)
                if isinstance(reason, (ConnectionRefusedError, OSError)) and \
                        not isinstance(e, urllib.error.HTTPError):
                    self.log.warning("HA unreachable (%s) — retrying in %.0fs",
                                     reason, backoff)
                else:
                    raise AmbiguousDelivery(str(e)) from e
            except OSError as e:
                raise AmbiguousDelivery(str(e)) from e
            time.sleep(backoff)
            backoff = min(backoff * 2, 60.0)
        try:
            self._post("/api/states/" + self.sensor, {
                "state": (msg.get("text") or "")[:255],
                "attributes": {
                    "sender": msg.get("sender"),
                    "message": msg.get("text"),
                    "received_at": msg.get("scts") or msg.get("received_at"),
                    "message_id": str(msg.get("id", "")),
                    "friendly_name": "SMS received",
                    "icon": "mdi:message-text",
                },
            })
        except Exception as e:                   # sensor is cosmetic — never fatal
            self.log.debug("sensor update failed: %s", e)

    def fire_gap(self):
        try:
            self._post("/api/events/" + self.event + "_gap", {})
        except Exception as e:
            self.log.warning("gap event failed: %s", e)


class AmbiguousDelivery(Exception):
    """HA POST failed after the request may have been received."""


def message_hash(msg):
    """Mirror of the server-side stable hash; prefer the server's value."""
    if msg.get("hash"):
        return msg["hash"]
    h = hashlib.sha256()
    for part in (msg.get("sender"), msg.get("scts"), msg.get("text")):
        h.update((part or "").encode())
        h.update(b"|")
    return h.hexdigest()[:24]


def run_inbound(cfg, server, state, ha, logger, stop_event):
    """The SSE consume loop; reconnects with backoff until stop_event is set."""
    backoff = 2.0
    while not stop_event.is_set():
        conn = None
        try:
            conn = server.open(timeout=60)
            headers = {"Authorization": "Bearer " + cfg.str("SERVER_TOKEN"),
                       "Accept": "text/event-stream"}
            path = "/v1/subscribe"
            if state.last_id is not None and state.stream_id:
                headers["Last-Event-ID"] = str(state.last_id)
                headers["X-Stream-Id"] = state.stream_id
            conn.request("GET", path, headers=headers)
            resp = conn.getresponse()
            if resp.status != 200:
                logger.error("subscribe failed: HTTP %s %s", resp.status,
                             resp.read(200))
                raise ConnectionError(f"HTTP {resp.status}")
            logger.info("subscribed to %s:%s", server.host, server.port)
            backoff = 2.0
            for ev in SSEReader(resp).events():
                if stop_event.is_set():
                    return
                _handle_event(ev, state, ha, cfg, logger)
        except Exception as e:
            if stop_event.is_set():
                return
            logger.warning("subscribe connection lost (%s); retry in %.0fs",
                           e, backoff)
            stop_event.wait(backoff)
            backoff = min(backoff * 2, 120.0)
        finally:
            if conn is not None:
                conn.close()


def _handle_event(ev, state, ha, cfg, logger):
    kind = ev["event"]
    if kind == "hello":
        info = json.loads(ev["data"])
        state.on_hello(info.get("stream_id"))
        return
    if kind == "gap":
        logger.warning("server reported a gap — some messages were missed")
        ha.fire_gap()
        return
    if kind == "health":
        return
    if kind != "message":
        return
    msg = json.loads(ev["data"])
    h = message_hash(msg)
    if state.seen(h):
        logger.info("skipping already-processed message %s", msg.get("id"))
        state.advance(msg.get("id"))
        return
    body = msg.get("text") if cfg.bool("LOG_BODIES") else \
        f"<{len(msg.get('text') or '')} chars>"
    logger.info("SMS from %s: %s", msg.get("sender"), body)
    state.mark(h)                                # mark-then-fire
    try:
        ha.fire(msg)
    except AmbiguousDelivery as e:
        logger.error("dropping message %s after ambiguous HA failure: %s "
                     "(at-most-once by design)", msg.get("id"), e)
    state.advance(msg.get("id"))
