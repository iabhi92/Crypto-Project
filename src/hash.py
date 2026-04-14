import hashlib

BIG_ENDIAN = "big"
FOUR_BYTE = 4

# Prepends the tweak and all data fields, then SHA-256s the result.

# Parameters
# tweak : Integer that corresponds to a namespace for this particular hash call
# data: Tuple of byte strings

# Returns
# 32-byte SHA-256 Output
def hash_tweak(tweak, *data):

    h = hashlib.sha256()
 
    if isinstance(tweak, tuple):
        for t in tweak:
            if isinstance(t, int):
                h.update(t.to_bytes(FOUR_BYTE, BIG_ENDIAN))
            else:
                h.update(t)
    else:
        h.update(tweak.to_bytes(FOUR_BYTE, BIG_ENDIAN))
 
    for d in data:
        h.update(d)
 
    return h.digest()