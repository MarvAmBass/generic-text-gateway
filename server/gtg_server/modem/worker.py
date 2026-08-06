"""ModemWorker: the single thread that owns the serial port.

Orchestrates: modeswitch -> discovery -> init -> SIM/PIN -> registration ->
receive setup, then serves jobs (send SMS, runtime PIN, SIM deletes) and URCs,
with periodic polling/reconciliation. On any serial failure it re-enters the
connect cycle with backoff.
"""
import queue
import threading
import time
from datetime import datetime, timezone

from . import discovery, modeswitch, receive, sim, sms_codec
from .at import ATError, ATPort, ATTimeout


class ModemWorker(threading.Thread):
    def __init__(self, cfg, hub, outbox, logger):
        super().__init__(name="modem-worker", daemon=True)
        self.cfg = cfg
        self.hub = hub
        self.outbox = outbox
        self.log = logger
        self.jobs = queue.Queue()
        self.stop_event = threading.Event()

        self.port = None
        self.assembler = receive.Assembler()
        self.seen_hashes = set()          # message hashes published this run
        self.strategy = None
        self.pdu_mode = True
        self.cmgl_broken = False          # e.g. E1750: CMGL=4 never answers
        self.modem_info = {}
        self.port_info = {}
        self.pin_submissions = 0          # runtime PIN submissions (lifetime cap)
        self._env_pin_tries = 0
        self._runtime_pin = None          # memory only, never logged/persisted
        self._urc_cmt_pending = False     # +CMT: header seen, PDU line follows

        self._health_lock = threading.Lock()
        self._health = {"state": "starting", "sim": "unknown", "registration": None,
                        "operator": None, "signal": {}, "receive_strategy": None,
                        "storage": {}, "last_inbound": None, "last_outbound": None,
                        "last_error": None, "modem": {}, "port": None,
                        "started_at": datetime.now(timezone.utc).isoformat()}

    # -- public (thread-safe) ------------------------------------------------

    def submit_send(self, rec_id):
        self.jobs.put(("send", rec_id))

    def submit_pin(self, pin):
        """-> reply queue; worker puts the resulting sim state string on it."""
        reply = queue.Queue(maxsize=1)
        self.jobs.put(("pin", pin, reply))
        return reply

    def request_delete(self, indices):
        if indices:
            self.jobs.put(("delete", list(indices)))

    def health(self):
        with self._health_lock:
            return dict(self._health)

    def stop(self):
        self.stop_event.set()
        self.jobs.put(("wake",))

    def _set_health(self, **fields):
        changed = False
        with self._health_lock:
            for k, v in fields.items():
                if self._health.get(k) != v:
                    self._health[k] = v
                    changed = True
            snapshot = dict(self._health)
        if changed and ("state" in fields or "sim" in fields):
            self.hub.broadcast({"kind": "health", "health": snapshot})

    # -- main loop -----------------------------------------------------------

    def run(self):
        backoff = 2.0
        while not self.stop_event.is_set():
            try:
                if self._connect():
                    backoff = 2.0
                    self._serve()               # returns on serial failure/stop
            except Exception as e:
                self.log.error("modem cycle failed: %s", self._redact(e))
                self._set_health(state="down", last_error=self._redact(e))
            finally:
                if self.port:
                    self.port.close()
                    self.port = None
            if self.stop_event.is_set():
                return
            self.stop_event.wait(backoff)
            backoff = min(backoff * 2, 60.0)

    def _redact(self, err):
        text = str(err)
        for secret in (self.cfg.str("SIM_PIN"), self._runtime_pin or ""):
            if secret:
                text = text.replace(secret, "****")
        return text

    # -- connect cycle -------------------------------------------------------

    def _connect(self):
        self._set_health(state="starting")
        if self.cfg.bool("MODESWITCH"):
            modeswitch.maybe_switch(self.log)
        dev, info = discovery.find_at_port(self.cfg.str("SERIAL_PORT"),
                                           self.cfg.int("BAUD"), self.log)
        if not dev:
            self._set_health(state="no_modem", last_error="no AT port found")
            return False
        self.port_info = info or {}
        self.port = ATPort(dev, self.cfg.int("BAUD"), self._on_urc, self.log)
        self.port.open()

        self.port.execute("ATE0", timeout=5)             # echo off
        try:
            self.port.execute("AT+CMEE=1", timeout=5)    # numeric CME errors
        except (ATError, ATTimeout):
            pass
        self.modem_info = discovery.identify(self.port)
        self._set_health(port=dev, modem=self.modem_info)

        if not self._unlock_sim():
            return True                                  # serve loop waits for PIN
        self._after_sim_ready()
        return True

    def _unlock_sim(self):
        state = sim.cpin_state(self.port)
        if state == "pin_required":
            env_pin = self.cfg.str("SIM_PIN")
            if env_pin and self._env_pin_tries < self.cfg.int("SIM_PIN_MAX_TRIES"):
                self._env_pin_tries += 1
                self.log.info("submitting configured SIM PIN")
                try:
                    sim.enter_pin(self.port, env_pin)
                except (ATError, ValueError) as e:
                    self.log.error("SIM PIN rejected: %s", self._redact(e))
                time.sleep(3)
                state = sim.cpin_state(self.port)
        self._set_health(sim=state)
        if state == "ready":
            return True
        if state == "pin_required":
            self._set_health(state="sim_pin_required")
            self.log.warning("SIM PIN required — enter via web UI or POST /v1/sim/pin")
        elif state == "puk_required":
            self._set_health(state="sim_puk_required",
                             last_error="SIM is PUK-locked; will not attempt unlock")
            self.log.error("SIM is PUK-locked — manual intervention required")
        else:
            self._set_health(state="down", last_error=f"sim state: {state}")
        return False

    def _after_sim_ready(self):
        self._set_health(state="registering", sim="ready")
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline and not self.stop_event.is_set():
            if sim.registered(self.port):
                break
            time.sleep(2)
        self._refresh_network_health()

        try:
            self.port.execute("AT+CMGF=0", timeout=5)
            self.pdu_mode = True
        except (ATError, ATTimeout):
            self.log.warning("PDU mode unsupported — falling back to text mode "
                             "(GSM7-only, no multipart)")
            self.port.execute("AT+CMGF=1", timeout=5)
            self.pdu_mode = False
        receive.select_storage(self.port, self.log)
        self.strategy = receive.select_cnmi(self.port, self.log)
        self._set_health(state="ready", receive_strategy=self.strategy)
        self._scan_stored()

    def _refresh_network_health(self):
        reg_state, reg_desc = sim.registration(self.port)
        csq, dbm, pct = sim.signal(self.port)
        used, total = receive.storage_usage(self.port)
        self._set_health(registration=reg_desc, operator=sim.operator(self.port),
                         signal={"csq": csq, "dbm": dbm, "percent": pct},
                         storage={"used": used, "total": total})
        if total and used is not None and total - used <= 3:
            self.log.warning("SIM storage nearly full (%s/%s) — connect a "
                             "subscriber or enable the file store", used, total)

    # -- serve loop ----------------------------------------------------------

    def _serve(self):
        last_poll = last_net = time.monotonic()
        while not self.stop_event.is_set():
            try:
                job = self.jobs.get(timeout=0.5)
            except queue.Empty:
                job = None
            try:
                if job:
                    self._handle_job(job)
                else:
                    self.port.drain_urcs(0.2)
                now = time.monotonic()
                sim_ready = self.health()["sim"] == "ready"
                # Always-on stored-message scan: CMTI/CMT are the fast path, the
                # scan is the safety net — a modem with broken notifications can
                # never stall inbound for more than POLL_INTERVAL.
                if sim_ready and now - last_poll >= self.cfg.int("POLL_INTERVAL"):
                    last_poll = now
                    self._scan_stored()
                if now - last_net >= 60:
                    last_net = now
                    if sim_ready:
                        self._refresh_network_health()
                for partial, indices in self.assembler.flush_stale():
                    self._publish(partial, indices)
            except (ATTimeout, OSError) as e:
                self.log.error("serial failure: %s", self._redact(e))
                self._set_health(state="down", last_error=self._redact(e))
                return

    def _handle_job(self, job):
        kind = job[0]
        if kind == "send":
            self._do_send(job[1])
        elif kind == "pin":
            self._do_pin(job[1], job[2])
        elif kind == "delete":
            self._delete_indices(job[1])

    # -- outbound ------------------------------------------------------------

    def _do_send(self, rec_id):
        rec = self.outbox.get(rec_id)
        if rec is None or rec["state"] != "queued":
            return
        if self.health()["sim"] != "ready":
            self.outbox.update(rec_id, state="failed", error="modem not ready")
            return
        self.outbox.update(rec_id, state="sending")
        refs, sent_any = [], False
        for number in rec["to"]:
            try:
                refs.extend(self._send_one(number, rec["text"]))
                sent_any = True
            except ATTimeout:
                # Payload possibly submitted — never retried (PLAN.md 3.7).
                self.outbox.update(rec_id, state="submission_unknown", refs=refs,
                                   error=f"timeout while sending to {number}")
                self._set_health(last_outbound=_now())
                return
            except (ATError, ValueError) as e:
                self.outbox.update(rec_id, state="failed", refs=refs,
                                   error=f"{number}: {self._redact(e)}")
                return
        self.outbox.update(rec_id, state="submitted" if sent_any else "failed",
                           refs=refs)
        self._set_health(last_outbound=_now())

    def _send_one(self, number, text):
        refs = []
        if self.pdu_mode:
            for pdu_hex, cmgs_len in sms_codec.build_submit_pdus(number, text):
                lines = self.port.execute(f"AT+CMGS={cmgs_len}", timeout=10,
                                          payload=pdu_hex.encode("ascii"))
                refs.append(_cmgs_ref(lines))
        else:
            if not sms_codec.is_gsm7(text):
                raise ValueError("text mode fallback supports GSM7 characters only")
            lines = self.port.execute(f'AT+CMGS="{number}"', timeout=10,
                                      payload=text.encode("ascii", errors="replace"))
            refs.append(_cmgs_ref(lines))
        return refs

    # -- runtime PIN ---------------------------------------------------------

    def _do_pin(self, pin, reply):
        self.pin_submissions += 1
        self._runtime_pin = pin
        try:
            sim.enter_pin(self.port, pin)
        except (ATError, ValueError) as e:
            self.log.warning("runtime PIN rejected: %s", self._redact(e))
        time.sleep(3)
        state = sim.cpin_state(self.port)
        self._runtime_pin = None                       # keep it around only briefly
        self._set_health(sim=state)
        if state == "ready":
            self._after_sim_ready()
        elif state == "puk_required":
            self._set_health(state="sim_puk_required")
        try:
            reply.put_nowait(state)
        except queue.Full:
            pass

    # -- inbound -------------------------------------------------------------

    def _on_urc(self, line):
        if self._urc_cmt_pending:
            self._urc_cmt_pending = False
            self._process_pdu(line, index=None)
            return
        cmti = receive.parse_cmti(line)
        if cmti:
            self._read_index(cmti[1])
        elif line.startswith("+CMT:"):
            if self.pdu_mode:
                self._urc_cmt_pending = True
            # text-mode +CMT bodies are picked up by reconciliation instead
        elif line.startswith(("+CREG:", "+CGREG:", "+CEREG:")):
            pass                                        # refreshed periodically
        else:
            self.log.debug("URC: %s", line)

    def _read_index(self, index):
        try:
            if self.pdu_mode:
                lines = self.port.execute(f"AT+CMGR={index}", timeout=10,
                                          collect_extra=lambda l: True)
                pdu = receive.parse_cmgr_pdu(lines)
                if pdu:
                    self._process_pdu(pdu, index)
            else:
                self._scan_stored()                     # text mode: re-list
        except ATError as e:
            self.log.warning("CMGR %s failed: %s", index, e)

    def _process_pdu(self, pdu_hex, index):
        try:
            decoded = sms_codec.decode_deliver(pdu_hex)
        except (ValueError, IndexError) as e:
            self.log.warning("undecodable PDU (index %s): %s", index, e)
            return
        if decoded.get("kind") != "deliver":
            if index is not None:
                self._delete_indices([index])
            return
        result = self.assembler.add(decoded, index)
        if result:
            self._publish(*result)

    def _publish(self, msg, indices):
        h = receive.message_hash(msg["sender"], msg["scts"], msg["text"])
        if h in self.seen_hashes:
            return
        self.seen_hashes.add(h)
        if len(self.seen_hashes) > 5000:
            self.seen_hashes.clear()
        msg["received_at"] = _now()
        msg["hash"] = h
        body = msg["text"] if self.cfg.bool("LOG_BODIES") else f"<{len(msg['text'])} chars>"
        self.log.info("SMS from %s: %s", msg["sender"], body)
        published = self.hub.publish(msg, modem_indices=indices)
        if self.hub.store is not None:
            self._delete_indices(indices)               # persisted -> safe to delete
        self._set_health(last_inbound=msg["received_at"])
        return published

    def _delete_indices(self, indices):
        for index in indices or []:
            try:
                self.port.execute(f"AT+CMGD={index}", timeout=10)
            except (ATError, ATTimeout) as e:
                self.log.warning("CMGD %s failed (will retry via reconcile): %s",
                                 index, e)

    def _scan_stored(self):
        """Process everything in modem storage: CMGL, with a CMGR index sweep as
        fallback (some firmware — e.g. the E1750 — never answers a bare CMGL=4)."""
        if not self.pdu_mode:
            self._list_text_cmgl()
            return
        if not self.cmgl_broken:
            try:
                lines = self.port.execute("AT+CMGL=4", timeout=15,
                                          collect_extra=lambda l: True)
                entries = receive.parse_cmgl_pdu(lines)
                for index, pdu in entries:
                    self._process_pdu(pdu, index)
                if entries:
                    return
            except (ATError, ATTimeout) as e:
                self.cmgl_broken = True
                self.log.warning("CMGL listing unusable on this modem (%s) — "
                                 "switching to CMGR index sweep", e)
        # CMGL yielded nothing: trust CPMS and sweep indexes directly.
        used, total = receive.storage_usage(self.port)
        if not used:
            return
        found = 0
        for index in range(total or 20):
            if found >= used:
                break
            try:
                lines = self.port.execute(f"AT+CMGR={index}", timeout=10,
                                          collect_extra=lambda l: True)
            except ATError:
                continue                                 # empty/invalid slot
            pdu = receive.parse_cmgr_pdu(lines)
            if pdu:
                found += 1
                self._process_pdu(pdu, index)

    def _list_text_cmgl(self):
        try:
            lines = self.port.execute('AT+CMGL="ALL"', timeout=30,
                                      collect_extra=lambda l: True)
        except (ATError, ATTimeout) as e:
            self.log.debug("CMGL failed: %s", e)
            return
        self._process_text_cmgl(lines)

    def _process_text_cmgl(self, lines):
        """Minimal text-mode listing: '+CMGL: idx,stat,"sender",,"ts"' + body line."""
        header = None
        for line in lines:
            if line.startswith("+CMGL:"):
                parts = line.split(",")
                try:
                    index = int(parts[0].split(":")[1].strip())
                    sender = parts[2].strip().strip('"')
                    ts = parts[4].strip().strip('"') if len(parts) > 4 else ""
                    header = (index, sender, ts)
                except (IndexError, ValueError):
                    header = None
            elif header:
                index, sender, ts = header
                header = None
                self._publish({"sender": sender, "text": line, "scts": ts,
                               "partial": False}, [index])


def _cmgs_ref(lines):
    for line in lines:
        if line.startswith("+CMGS:"):
            try:
                return int(line.split(":")[1].strip().split(",")[0])
            except ValueError:
                return None
    return None


def _now():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
