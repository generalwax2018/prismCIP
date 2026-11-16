"""Time-based one-time passwords (RFC 6238, SHA-1, 6 digits, 30 s), standard library only.

The shared secret is sealed before it is stored: XOR with an HMAC-SHA256 keystream derived from the server key and
a random nonce, plus an HMAC tag, so a copy of the database alone does not give out anyone's second factor.
"""
import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

from .db import server_key

STEP, DIGITS = 30, 6


def new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _code(secret: str, step: int) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    mac = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    n = (struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % 10 ** DIGITS
    return str(n).zfill(DIGITS)


def now_code(secret: str, at: float | None = None) -> str:
    return _code(secret, int((at or time.time()) // STEP))


def verify(secret: str, code: str, last_step: int | None = None, at: float | None = None) -> int | None:
    """Return the matching time step (to store as last used), or None. Accepts one step of clock drift."""
    code = "".join(ch for ch in (code or "") if ch.isdigit())
    if len(code) != DIGITS:
        return None
    cur = int((at or time.time()) // STEP)
    for step in (cur - 1, cur, cur + 1):
        if last_step is not None and step <= last_step:
            continue
        if hmac.compare_digest(_code(secret, step), code):
            return step
    return None


def uri(secret: str, account: str, issuer: str = "PrismCIP") -> str:
    return (f"otpauth://totp/{quote(issuer)}:{quote(account)}?secret={secret}&issuer={quote(issuer)}"
            f"&algorithm=SHA1&digits={DIGITS}&period={STEP}")


def _keys() -> tuple[bytes, bytes]:
    root = hashlib.sha256(("prismcip-totp|" + server_key()).encode()).digest()
    return hmac.new(root, b"enc", hashlib.sha256).digest(), hmac.new(root, b"mac", hashlib.sha256).digest()


def seal(secret: str) -> str:
    enc, mac = _keys()
    nonce = secrets.token_bytes(16)
    data = secret.encode()
    stream = b"".join(hmac.new(enc, nonce + struct.pack(">I", i), hashlib.sha256).digest()
                      for i in range(len(data) // 32 + 1))
    ct = bytes(a ^ b for a, b in zip(data, stream))
    tag = hmac.new(mac, nonce + ct, hashlib.sha256).digest()[:16]
    return "v1:" + base64.urlsafe_b64encode(nonce + ct + tag).decode()


def unseal(sealed: str) -> str | None:
    if not sealed or not sealed.startswith("v1:"):
        return None
    raw = base64.urlsafe_b64decode(sealed[3:])
    nonce, ct, tag = raw[:16], raw[16:-16], raw[-16:]
    enc, mac = _keys()
    if not hmac.compare_digest(hmac.new(mac, nonce + ct, hashlib.sha256).digest()[:16], tag):
        return None
    stream = b"".join(hmac.new(enc, nonce + struct.pack(">I", i), hashlib.sha256).digest()
                      for i in range(len(ct) // 32 + 1))
    return bytes(a ^ b for a, b in zip(ct, stream)).decode()


def qr_svg(text: str) -> str:
    from .qrcodegen import QrCode
    qr = QrCode.encode_text(text, QrCode.Ecc.MEDIUM)
    n, border = qr.get_size(), 2
    parts = [f"M{x + border},{y + border}h1v1h-1z" for y in range(n) for x in range(n) if qr.get_module(x, y)]
    size = n + border * 2
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {size} {size}" class="qr" role="img" '
            f'aria-label="QR code for your authenticator app"><rect width="100%" height="100%" fill="#fff"/>'
            f'<path d="{" ".join(parts)}" fill="#000"/></svg>')
