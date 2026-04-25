from utils import CPK, randomBits

from lamport import Gen, Verify, WINTER, N_BYTES, A, C, CHAIN_LEN
from merkle_tree import MT_Construct, MT_Verify, MT_MakePath, MT_Extract
from hash import hash_lms

csk = None
cpk = None

_KEY_IDS = {}
keyIDs = _KEY_IDS  # tests access this directly to reset key state


def StatefulGen(d):
    global cpk, csk, _KEY_IDS

    pk = []
    sk = []

    for keyID in range(d):
        p, s = Gen(keyID)
        pk.append(p)
        sk.append(s)

    cpk = CPK()
    cpk.ROOT = MT_Construct(pk)[1]
    csk = sk

    _KEY_IDS.clear()
    for index in range(d):
        _KEY_IDS[index] = False

    return (cpk, csk)


def StatefulSign(keyID, m):
    if keyID in _KEY_IDS:
        if not _KEY_IDS[keyID]:
            _KEY_IDS[keyID] = True
        else:
            return ()  # key already used

    r = randomBits()
    r_bytes = r.to_bytes(N_BYTES, "big")

    h = hash_lms((1, keyID), r_bytes, m)
    z = WINTER(h, csk[keyID])

    pk = []
    for index in range(len(_KEY_IDS)):
        tips = [csk[index][i][CHAIN_LEN - 1] for i in range(A + C)]
        pk.append(hash_lms((0, index), *tips)[:N_BYTES])

    path = MT_MakePath(pk, keyID)

    return (r, path, z)


def StatefulVerify(m, r, path, z):
    keyID = MT_Extract(path)
    pk_prime = Verify(r, z, m, keyID)
    return MT_Verify(path, pk_prime) == cpk.ROOT
