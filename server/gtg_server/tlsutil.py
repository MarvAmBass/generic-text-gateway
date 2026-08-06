"""TLS: auto self-signed cert via the openssl CLI, fingerprints, SSL context."""
import base64
import hashlib
import os
import socket
import ssl
import subprocess

CERT_NAME = "server.crt"
KEY_NAME = "server.key"


def default_sans():
    sans = {"localhost", "127.0.0.1", "::1"}
    try:
        sans.add(socket.gethostname())
    except OSError:
        pass
    try:                                   # best-effort primary LAN IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("192.0.2.1", 80))       # no packets sent (UDP)
        sans.add(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    return sorted(sans)


def _san_string(sans):
    parts = []
    for san in sans:
        stripped = san.strip()
        try:
            socket.inet_pton(socket.AF_INET, stripped)
            parts.append(f"IP:{stripped}")
            continue
        except OSError:
            pass
        try:
            socket.inet_pton(socket.AF_INET6, stripped)
            parts.append(f"IP:{stripped}")
            continue
        except OSError:
            pass
        parts.append(f"DNS:{stripped}")
    return ",".join(parts)


def ensure_cert(data_dir, sans, logger):
    """Generate a self-signed EC P-256 cert once; reuse forever (stable pin)."""
    cert = os.path.join(data_dir, CERT_NAME)
    key = os.path.join(data_dir, KEY_NAME)
    if os.path.isfile(cert) and os.path.isfile(key):
        return cert, key
    os.makedirs(data_dir, exist_ok=True)
    logger.info("generating self-signed TLS certificate in %s", data_dir)
    old_umask = os.umask(0o077)          # key must never exist world-readable
    try:
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "ec",
             "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
             "-keyout", key, "-out", cert, "-days", "3650",
             "-subj", "/CN=generic-text-gateway",
             "-addext", f"subjectAltName={_san_string(sans)}"],
            check=True, capture_output=True)
    finally:
        os.umask(old_umask)
    os.chmod(key, 0o600)
    os.chmod(cert, 0o644)
    return cert, key


def fingerprint(cert_path):
    """SHA-256 hex of the DER certificate (what clients pin)."""
    with open(cert_path) as f:
        pem = f.read()
    body = pem.split("-----BEGIN CERTIFICATE-----")[1].split("-----END")[0]
    der = base64.b64decode(body)
    return hashlib.sha256(der).hexdigest()


def build_context(cert_path, key_path):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert_path, key_path)
    return ctx
