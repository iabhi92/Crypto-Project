import hashlib
import utils

BIG_ENDIAN = "big"
FOUR_BYTE = 4

# Tweakable hash function H(tweak, *data) using the backend set in utils.HASH_BACKEND.
# Defaults to SHA-256; set utils.HASH_BACKEND = 'blake2b' for a faster alternative.
# Both backends produce 32 bytes of output, truncated to N_BYTES by callers.
def hash_lms(tweak: tuple, *data: bytes) -> bytes:
    if utils.HASH_BACKEND == 'blake2b':
        h = hashlib.blake2b(digest_size=32)
    else:
        h = hashlib.sha256()

    for t in tweak:
        if isinstance(t, int):
            h.update(t.to_bytes(FOUR_BYTE, BIG_ENDIAN))
        else:
            h.update(t)

    for d in data:
        h.update(d)

    return h.digest()
