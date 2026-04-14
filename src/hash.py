import hashlib

BIG_ENDIAN = "big"
FOUR_BYTE = 4

# Prepends the tweak and all data fields, then SHA-256s the result.

# Parameters
# tweak : Tuple of integers
# data: Tuple of byte strings

# Returns
# 32-byte SHA-256 Output
def hash_lms(tweak: tuple, *data: bytes) -> bytes:

    h = hashlib.sha256()
 
    for t in tweak:
        if isinstance(t, int):
            h.update(t.to_bytes(FOUR_BYTE, BIG_ENDIAN))
        else:
            h.update(t)
 
    for d in data:
        h.update(d)
 
    return h.digest()