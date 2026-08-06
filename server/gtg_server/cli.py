"""gtg-server CLI: run (default) | fingerprint | probe | send."""
import argparse
import json
import logging
import signal
import sys
import threading

from . import __version__, api, auth as auth_mod, tlsutil
from .config import Config, resolve_binds
from .hub import Hub
from .outbox import Outbox
from .store import FileStore


def _logger(cfg):
    level = getattr(logging, cfg.str("LOG_LEVEL").upper(), logging.INFO)
    logging.basicConfig(level=level,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    return logging.getLogger("gtg")


def cmd_run(cfg):
    log = _logger(cfg)
    log.info("generic-text-gateway %s", __version__)

    tokens_spec = cfg.str("TOKENS")
    if not tokens_spec:
        log.error("GTG_TOKENS is required (e.g. GTG_TOKENS=all:$(openssl rand -hex 24))")
        return 2
    tokens = auth_mod.parse_tokens(tokens_spec)
    auth = auth_mod.Auth(tokens, cfg.str("WEBUI_USER"), cfg.str("WEBUI_PASS"),
                         cfg.str("WEBUI_PASS_HASH"))

    store = FileStore(cfg.str("STORE_DIR")) if cfg.str("STORE_DIR") else None
    if store:
        log.info("file store enabled: %s (durable stream %s)",
                 cfg.str("STORE_DIR"), store.stream()[0])
    else:
        log.info("file store disabled — messages are not persisted")

    from .modem.worker import ModemWorker      # lazy: needs pyserial
    hub = Hub(ring_size=cfg.int("RING_SIZE"), store=store)
    outbox = Outbox(store=store)
    worker = ModemWorker(cfg, hub, outbox, log.getChild("modem"))
    hub.on_deliverable = worker.request_delete

    binds = resolve_binds(cfg.listen_addrs(), log)
    api.check_plaintext_binds(cfg, binds)
    ctx = None
    fp = None
    if cfg.str("TLS") != "off":
        if cfg.str("TLS_CERT") and cfg.str("TLS_KEY"):
            cert, key = cfg.str("TLS_CERT"), cfg.str("TLS_KEY")
        else:
            sans = cfg.list("TLS_SANS") or tlsutil.default_sans()
            cert, key = tlsutil.ensure_cert(cfg.str("DATA_DIR"), sans, log)
        fp = tlsutil.fingerprint(cert)
        log.info("TLS certificate SHA-256 fingerprint (pin this in clients): %s", fp)
        ctx = tlsutil.build_context(cert, key)

    state = api.ApiState(cfg, hub, outbox, worker, auth,
                         auth_mod.Backoff(), auth_mod.RateLimit(cfg.str("SEND_RATE")),
                         store, log.getChild("api"), fp)
    servers = api.serve(state, binds, ctx, log)
    worker.start()

    stop = threading.Event()

    def _sig(_num, _frame):
        stop.set()
    signal.signal(signal.SIGTERM, _sig)
    signal.signal(signal.SIGINT, _sig)
    stop.wait()
    log.info("shutting down")
    worker.stop()
    for srv in servers:
        srv.shutdown()
    return 0


def cmd_fingerprint(cfg):
    log = _logger(cfg)
    if cfg.str("TLS_CERT"):
        cert = cfg.str("TLS_CERT")
    else:
        sans = cfg.list("TLS_SANS") or tlsutil.default_sans()
        cert, _ = tlsutil.ensure_cert(cfg.str("DATA_DIR"), sans, log)
    print(tlsutil.fingerprint(cert))
    return 0


def cmd_probe(cfg):
    log = _logger(cfg)
    from .modem import discovery, modeswitch
    from .modem.at import ATPort
    report = {"storage_mode_devices":
              [f"{v:04x}:{p:04x}" for v, p in modeswitch.storage_mode_devices()],
              "candidates": [], "at_port": None}
    if report["storage_mode_devices"] and cfg.bool("MODESWITCH"):
        log.info("switching storage-mode devices first...")
        modeswitch.maybe_switch(log)
    for cand in discovery.candidates():
        ok = discovery.probe_port(cand["device"], cfg.int("BAUD"), log)
        cand["answers_at"] = ok
        report["candidates"].append(cand)
        if ok and report["at_port"] is None:
            port = ATPort(cand["device"], cfg.int("BAUD"), lambda l: None, log)
            try:
                port.open()
                port.execute("ATE0", timeout=5)
                report["identity"] = discovery.identify(port)
                for probe_cmd in ("AT+CMGF=?", "AT+CPMS=?", "AT+CNMI=?", "AT+CPIN?"):
                    try:
                        report.setdefault("capabilities", {})[probe_cmd] = \
                            " ".join(port.execute(probe_cmd, timeout=5))
                    except Exception as e:
                        report.setdefault("capabilities", {})[probe_cmd] = f"error: {e}"
                report["at_port"] = cand["device"]
            finally:
                port.close()
    print(json.dumps(report, indent=2))
    return 0


def cmd_send(cfg, to, text):
    """One-shot test send, straight through the modem (no API)."""
    log = _logger(cfg)
    from .hub import Hub as _Hub
    from .modem.worker import ModemWorker
    hub = _Hub(ring_size=10)
    outbox = Outbox()
    worker = ModemWorker(cfg, hub, outbox, log.getChild("modem"))
    hub.on_deliverable = worker.request_delete
    worker.start()
    import time
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        state = worker.health()["state"]
        if state == "ready":
            break
        if state in ("sim_pin_required", "sim_puk_required", "no_modem"):
            log.error("cannot send: %s", state)
            worker.stop()
            return 1
        time.sleep(1)
    rec, _ = outbox.create([to], text)
    worker.submit_send(rec["id"])
    while time.monotonic() < deadline:
        rec = outbox.get(rec["id"])
        if rec["state"] not in ("queued", "sending"):
            break
        time.sleep(0.5)
    print(json.dumps(outbox.public(rec), indent=2))
    worker.stop()
    return 0 if rec["state"] == "submitted" else 1


def cmd_hash_password():
    """Interactive: print a GTG_WEBUI_PASS_HASH value (nothing echoed/stored)."""
    import getpass

    from . import auth as auth_mod
    pw = getpass.getpass("Password: ")
    if pw != getpass.getpass("Repeat:   "):
        print("passwords do not match", file=sys.stderr)
        return 1
    # Single quotes included: the hash contains '$', which double quotes or no
    # quotes would let the shell expand away when the config is sourced.
    print("export GTG_WEBUI_PASS_HASH='" + auth_mod.hash_password(pw) + "'")
    return 0


def cmd_hash_token():
    """Read a token on stdin, print its GTG_TOKENS sha256 form."""
    from . import auth as auth_mod
    token = sys.stdin.readline().strip()
    if not token:
        print("provide the token on stdin", file=sys.stderr)
        return 1
    print("sha256:" + auth_mod.hash_token(token))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(prog="gtg-server",
                                     description="generic-text-gateway server")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("run", help="run the gateway (default)")
    sub.add_parser("fingerprint", help="print the TLS cert SHA-256 fingerprint")
    sub.add_parser("probe", help="probe modems and print a JSON report")
    sub.add_parser("hash-password", help="hash a web UI password for GTG_WEBUI_PASS_HASH")
    sub.add_parser("hash-token", help="stdin token -> scope:sha256:<hex> form for GTG_TOKENS")
    send_p = sub.add_parser("send", help="one-shot test send via the modem")
    send_p.add_argument("--to", required=True)
    send_p.add_argument("--text", required=True)
    args = parser.parse_args(argv)

    cfg = Config()
    command = args.command or "run"
    if command == "run":
        return cmd_run(cfg)
    if command == "fingerprint":
        return cmd_fingerprint(cfg)
    if command == "probe":
        return cmd_probe(cfg)
    if command == "hash-password":
        return cmd_hash_password()
    if command == "hash-token":
        return cmd_hash_token()
    if command == "send":
        return cmd_send(cfg, args.to, args.text)
    parser.error("unknown command")


if __name__ == "__main__":
    sys.exit(main())
