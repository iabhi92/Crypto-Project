from hash import hash_lms
from utils import N_BYTES, CRV, A, C, CHAIN_LEN
from lamport import WINTER

# global state per trustee
K = {}
used_keys = {}
current = {}
trustee_path_lens = {}

PRF_R_TWEAK = (30,)
PRF_CHK_TWEAK = (31,)
PRF_AUTH_TWEAK = (32,)
PRF_PATH_TWEAK = (33,)
PRF_CHAIN_TWEAK = (34,)


def _to_n_bytes(v):
    if isinstance(v, int):
        return v.to_bytes(N_BYTES, "big")
    return bytes(v)


def _xor_many(values):
    # int XOR is ~6x faster than byte-by-byte in CPython
    if not values:
        return b""
    n = len(values[0])
    acc = int.from_bytes(values[0], "big")
    for v in values[1:]:
        if len(v) != n:
            raise ValueError("length mismatch")
        acc ^= int.from_bytes(v, "big")
    return acc.to_bytes(n, "big")


def PRF_R(seed, key_id, out_len):
    return hash_lms(PRF_R_TWEAK + (key_id,), seed, out_len.to_bytes(4, "big"))[:out_len]


def PRF_Chk(seed, key_id, out_len):
    return hash_lms(PRF_CHK_TWEAK + (key_id,), seed, out_len.to_bytes(4, "big"))[:out_len]


def PRF_Auth(seed, key_id, r):
    if isinstance(r, int):
        r = r.to_bytes(N_BYTES, "big")
    r = bytes(r)
    return hash_lms(PRF_AUTH_TWEAK + (key_id,), seed, r)[:N_BYTES]


def PRF_Path(seed, key_id, node_idx, out_len):
    return hash_lms(PRF_PATH_TWEAK + (key_id, node_idx), seed, out_len.to_bytes(4, "big"))[:out_len]


def PRF_Chain(seed, key_id, i, j, out_len):
    return hash_lms(PRF_CHAIN_TWEAK + (key_id, i, j), seed, out_len.to_bytes(4, "big"))[:out_len]


def KK_SetupContribution(seed, KeyID, R, path_lens, sk_shape):
    if isinstance(R, int):
        R = R.to_bytes(N_BYTES, "big")
    R = bytes(R)
    rows, cols = sk_shape
    return {
        "Rt":    PRF_R(seed, KeyID, N_BYTES),
        "CHKt":  PRF_Chk(seed, KeyID, N_BYTES),
        "Auth":  PRF_Auth(seed, KeyID, R),
        "PATHt": [PRF_Path(seed, KeyID, idx, node_len) for idx, node_len in enumerate(path_lens)],
        "SKt":   [[PRF_Chain(seed, KeyID, i, j, N_BYTES) for j in range(cols)] for i in range(rows)],
    }


def KK_Setup(trustee_contribs, KeyID, SK, R, PATH):
    crv = CRV()
    crv.key_id = KeyID

    if isinstance(R, int):
        R = R.to_bytes(N_BYTES, "big")
    R = bytes(R)

    path_nodes = [bytes(node) for node in PATH[:-1]]
    path_keyid = PATH[-1]
    path_lens = [len(node) for node in path_nodes]

    trustees = sorted(trustee_contribs.keys())

    crv.R = _xor_many([R] + [trustee_contribs[t]["Rt"] for t in trustees])

    crv.CHK = {}
    for t in trustees:
        crv.CHK[t] = _xor_many(
            [trustee_contribs[t]["Auth"]] + [trustee_contribs[s]["CHKt"] for s in trustees]
        )

    crv.PATH = [
        _xor_many([node] + [trustee_contribs[t]["PATHt"][idx] for t in trustees])
        for idx, node in enumerate(path_nodes)
    ] + [path_keyid]

    crv.SK = [
        [
            _xor_many([_to_n_bytes(SK[i][j])] + [_to_n_bytes(trustee_contribs[t]["SKt"][i][j]) for t in trustees])
            for j in range(len(SK[i]))
        ]
        for i in range(len(SK))
    ]

    crv.k = len(trustees)
    crv.trustees = trustees
    crv.path_lens = path_lens
    return crv


def KK_Aggregator_Sign(M, CRV, KeyID):
    trustees = getattr(CRV, "trustees", sorted(CRV.CHK.keys()))

    round1 = {}
    for t in trustees:
        result = KK_Sign1(t, KeyID, M)
        if result is None:
            return None
        round1[t] = result

    R = _xor_many([CRV.R] + [round1[t][0] for t in trustees])

    chk_per_trustee = {
        t: _xor_many([CRV.CHK[t]] + [round1[s][1] for s in trustees])
        for t in trustees
    }

    round2 = {}
    for t in trustees:
        result = KK_Sign2(t, R, chk_per_trustee[t])
        if result is None:
            return None
        round2[t] = result

    h = hash_lms((1, KeyID), R, M)
    crv_z = WINTER(h, CRV.SK)

    Z = [
        _xor_many([_to_n_bytes(crv_z[i])] + [_to_n_bytes(round2[t][1][i]) for t in trustees])
        for i in range(len(crv_z))
    ]

    path_nodes = CRV.PATH[:-1]
    PATH = [
        _xor_many([bytes(node)] + [_to_n_bytes(round2[t][0][idx]) for t in trustees])
        for idx, node in enumerate(path_nodes)
    ] + [CRV.PATH[-1]]

    return R, PATH, Z


def KK_Sign1(t, KeyID, M):
    if t not in K:
        return None
    if t not in used_keys:
        used_keys[t] = set()
    if KeyID in used_keys[t]:
        return None
    current[t] = (KeyID, M)
    used_keys[t].add(KeyID)
    return KK_GenSig1(K[t], KeyID)


def KK_GenSig1(Kt, KeyID):
    Rt = PRF_R(Kt, KeyID, N_BYTES)
    CHKt = PRF_Chk(Kt, KeyID, N_BYTES)
    return Rt, CHKt


def KK_Sign2(t, R_Prime, CHK_Prime):
    if t not in current or current[t] is None:
        return None
    KeyID, M = current[t]
    current[t] = None
    if t not in K:
        return None
    if t not in trustee_path_lens or KeyID not in trustee_path_lens[t]:
        return None
    if KK_Auth(K[t], KeyID, R_Prime, CHK_Prime):
        h = hash_lms((1, KeyID), R_Prime, M)
        return KK_GenSig2(K[t], KeyID, h, trustee_path_lens[t][KeyID])
    return None


def KK_GenSig2(Kt, KeyID, h, path_lens):
    SK_share = [
        [PRF_Chain(Kt, KeyID, i, j, N_BYTES) for j in range(CHAIN_LEN)]
        for i in range(A + C)
    ]
    Zt = WINTER(h, SK_share)
    PATHt = [PRF_Path(Kt, KeyID, idx, node_len) for idx, node_len in enumerate(path_lens)]
    return PATHt, Zt


def KK_Auth(Kt, KeyID, R_Prime, CHK_Prime):
    if isinstance(R_Prime, int):
        R_Prime = R_Prime.to_bytes(N_BYTES, "big")
    return PRF_Auth(Kt, KeyID, R_Prime) == CHK_Prime
