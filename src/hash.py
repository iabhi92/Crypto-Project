import hashlib
import utils


def hash_lms(tweak, *data):
    if utils.HASH_BACKEND == "blake2b":
        h = hashlib.blake2b(digest_size=32)
    else:
        h = hashlib.sha256()

    for t in tweak:
        if isinstance(t, int):
            h.update(t.to_bytes(4, "big"))
        else:
            h.update(t)

    for d in data:
        h.update(d)

    return h.digest()
