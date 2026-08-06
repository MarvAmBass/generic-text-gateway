"""gtg-client CLI: run the HA relay + local send API."""
import argparse
import logging
import signal
import sys
import threading

from . import __version__, relay, sendapi
from .config import Config
from .pinned_http import ServerConnection
from .state import State


def main(argv=None):
    parser = argparse.ArgumentParser(prog="gtg-client",
                                     description="generic-text-gateway client")
    parser.add_argument("--version", action="version", version=__version__)
    parser.parse_args(argv)

    cfg = Config()
    level = getattr(logging, cfg.str("LOG_LEVEL").upper(), logging.INFO)
    logging.basicConfig(level=level,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    log = logging.getLogger("gtc")
    log.info("generic-text-client %s", __version__)

    for key in ("SERVER_URL", "SERVER_TOKEN"):
        if not cfg.str(key):
            log.error("GTC_%s is required", key)
            return 2

    server = ServerConnection(cfg)
    sendapi.serve(cfg, server, log.getChild("send"))

    stop = threading.Event()

    def _sig(_num, _frame):
        stop.set()
    signal.signal(signal.SIGTERM, _sig)
    signal.signal(signal.SIGINT, _sig)

    if cfg.str("HA_URL") and cfg.str("HA_TOKEN"):
        state = State(cfg.str("STATE_DIR"))
        ha = relay.HAPoster(cfg, log.getChild("ha"))
        relay.run_inbound(cfg, server, state, ha, log.getChild("sse"), stop)
    else:
        log.warning("GTC_HA_URL/GTC_HA_TOKEN unset — send-only mode, "
                    "no inbound relay")
        stop.wait()
    return 0


if __name__ == "__main__":
    sys.exit(main())
