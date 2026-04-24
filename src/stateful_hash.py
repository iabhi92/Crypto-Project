from utils import CPK, CSK, PATH, randomBits

from lamport import Gen, Verify, WINTER, N_BYTES, A, C, CHAIN_LEN
from merkle_tree import MT_Construct, MT_Verify, MT_MakePath, MT_Extract
from hash import hash_lms

csk: CSK = None
cpk: CPK = None

# This is a dict of the keyIDs where each can be true or false to mark if they are used or not
# Example {1 : True, 2: False}
_KEY_IDS: dict[int, bool] = {}
keyIDs: dict[int, bool] = _KEY_IDS

# This is stateless so doesn't need access the the class variables
def StatefulGen(d: int) -> tuple[CPK, CSK]:
    global cpk, csk, keyIDs, _KEY_IDS
    
    pk = []
    sk = []

    keyID = 0

    while keyID < d:
        p, s = Gen(keyID)
        pk.append(p)
        sk.append(s)
        keyID += 1

    cpk = CPK()
    csk = []

    cpk.ROOT = MT_Construct(pk[0:d])[1]
    csk = sk[0:d]

    # Keep a stable dict object for key tracking so external rebinds like
    # `stateful_hash.keyIDs = {}` do not break modules that imported keyIDs.
    _KEY_IDS.clear()
    for index in range(0, d):
        _KEY_IDS[index] = False
    keyIDs = _KEY_IDS

    return (cpk, csk)


# This is stateful and it needs access to csk and the keyIDs
def StatefulSign(keyID: int, m: bytes) -> tuple[int, PATH, list[list]]:
    global keyIDs, _KEY_IDS
    keyIDs = _KEY_IDS
    
    if keyID in _KEY_IDS:
        # keyID may only be used once; False means still unused
        if not _KEY_IDS[keyID]:
            _KEY_IDS[keyID] = True
        else:
            return ()

    r = randomBits()
    r_bytes = r.to_bytes(N_BYTES, 'big')

    h = hash_lms((1, keyID), r_bytes, m)

    z = WINTER(h, csk[keyID])

    # Page 8 of paper to compute pk from sk
    pk = []
    for index in range(0, len(_KEY_IDS)):
        tips = [csk[index][i][CHAIN_LEN - 1] for i in range(A + C)]
        pk.append(hash_lms((0, index), *tips)[:N_BYTES])

    path = MT_MakePath(pk, keyID)

    return (r, path, z)

# This is stateful and it needs access to cpk
def StatefulVerify(m: bytes, r: int, path: PATH, z) -> bool:
    # See page 12 to get keyID from the path
    keyID = MT_Extract(path)

    pk_prime = Verify(r, z, m, keyID)

    if MT_Verify(path, pk_prime) == cpk.ROOT:
        return True
    else:
        return False
