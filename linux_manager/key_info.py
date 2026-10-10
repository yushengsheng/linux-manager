"""Read only a private key's format header, never return key material."""
import base64
from pathlib import Path
import struct


def encrypted_key(path):
    try:
        raw = Path(path).expanduser().read_bytes()
        if b"-----BEGIN OPENSSH PRIVATE KEY-----" in raw:
            body = base64.b64decode(b"".join(raw.splitlines()[1:-1]), validate=True)
            marker = b"openssh-key-v1\x00"
            if not body.startswith(marker): return None
            offset = len(marker)
            length = struct.unpack(">I", body[offset:offset + 4])[0]
            cipher = body[offset + 4:offset + 4 + length]
            return cipher != b"none" if cipher else None
        if b"BEGIN ENCRYPTED PRIVATE KEY" in raw or b"Proc-Type: 4,ENCRYPTED" in raw:
            return True
        if b"BEGIN RSA PRIVATE KEY" in raw or b"BEGIN EC PRIVATE KEY" in raw or b"BEGIN PRIVATE KEY" in raw:
            return False
    except (OSError, ValueError, struct.error):
        pass
    return None
