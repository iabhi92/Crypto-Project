from hash import hash_lms
from utils import N, N_BYTES, CRV, A, C, CHAIN_LEN
from lamport import WINTER


# minimal project K[t][KeyID]={ "Rt":"","CHKt":"","Expect_CHK":"","PATHt":"","SKt":""}
# full project stores only trustee PRF seeds:
# K[t] = seed
# Rt, CHKt, PATHt, and SKt are generated on the fly using PRF calls.
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


def _xor_bytes(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def _xor_many(values: list[bytes]) -> bytes:
    if not values:
        return b""
    out = bytearray(values[0])
    for v in values[1:]:
        v = bytes(v)
        if len(v) != len(out):
            raise ValueError("Cannot XOR byte strings with different lengths")
        for i in range(len(out)):
            out[i] ^= v[i]
    return bytes(out)


def _serialize_len(n: int) -> bytes:
    return n.to_bytes(4, "big")


def PRF_R(seed: bytes, key_id: int, out_len: int) -> bytes:
    return hash_lms(PRF_R_TWEAK + (key_id,), seed, _serialize_len(out_len))[:out_len]


def PRF_Chk(seed: bytes, key_id: int, out_len: int) -> bytes:
    return hash_lms(PRF_CHK_TWEAK + (key_id,), seed, _serialize_len(out_len))[:out_len]


def PRF_Auth(seed: bytes, key_id: int, r: bytes) -> bytes:
    return hash_lms(PRF_AUTH_TWEAK + (key_id,), seed, r)[:N_BYTES]


def PRF_Path(seed: bytes, key_id: int, node_idx: int, out_len: int) -> bytes:
    return hash_lms(PRF_PATH_TWEAK + (key_id, node_idx), seed, _serialize_len(out_len))[:out_len]


def PRF_Chain(seed: bytes, key_id: int, i: int, j: int, out_len: int) -> bytes:
    return hash_lms(PRF_CHAIN_TWEAK + (key_id, i, j), seed, _serialize_len(out_len))[:out_len]


# def _is_seed_mode(sk_shares) -> bool:
#     return bool(sk_shares) and isinstance(sk_shares[0], (bytes, bytearray))


def KK_Setup(
    trustee_seeds: dict[int, bytes],
    KeyID: int,
    SK,
    R: bytes,
    PATH,
) -> CRV:
    crv = CRV()

    if isinstance(R, int):
        R = R.to_bytes(N_BYTES, "big")
    R = bytes(R)

    path_nodes = [bytes(node) for node in PATH[:-1]]
    path_keyid = PATH[-1]
    path_lens = [len(node) for node in path_nodes]

    trustee_ids = sorted(trustee_seeds.keys())

    Rt_list = {}
    CHKt_list = {}
    Auth_list = {}
    PATHt_list = {}
    SKt_list = {}

    for t in trustee_ids:
        seed = bytes(trustee_seeds[t])

        Rt_list[t] = PRF_R(seed, KeyID, N_BYTES)
        CHKt_list[t] = PRF_Chk(seed, KeyID, N_BYTES)
        Auth_list[t] = PRF_Auth(seed, KeyID, R)

        PATHt_list[t] = [
            PRF_Path(seed, KeyID, node_idx, node_len)
            for node_idx, node_len in enumerate(path_lens)
        ]

        skt = []
        for i in range(len(SK)):
            row = []
            for j in range(len(SK[i])):
                row.append(PRF_Chain(seed, KeyID, i, j, N_BYTES))
            skt.append(row)
        SKt_list[t] = skt

    crv.R = _xor_many([R] + [Rt_list[t] for t in trustee_ids])

    crv.CHK = {}
    for target_t in trustee_ids:
        crv.CHK[target_t] = _xor_many(
            [Auth_list[target_t]] + [CHKt_list[t] for t in trustee_ids]
        )

    crv_path_nodes = []
    for node_idx, node in enumerate(path_nodes):
        value = bytearray(node)
        for t in trustee_ids:
            share = PATHt_list[t][node_idx]
            for x in range(len(value)):
                value[x] ^= share[x]
        crv_path_nodes.append(bytes(value))

    crv.PATH = crv_path_nodes + [path_keyid]

    crv_SK = []
    for i in range(len(SK)):
        row = []
        for j in range(len(SK[i])):
            value = bytearray(_to_n_bytes(SK[i][j]))
            for t in trustee_ids:
                share = _to_n_bytes(SKt_list[t][i][j])
                for x in range(len(value)):
                    value[x] ^= share[x]
            row.append(bytes(value))
        crv_SK.append(row)
    crv.SK = crv_SK
    crv.k = len(trustee_ids)
    crv.trustees = trustee_ids
    crv.path_lens = path_lens
    return crv


def KK_Aggregator_Sign(M, CRV, KeyID: int):
    trustees = getattr(CRV, "trustees", sorted(CRV.CHK.keys()))
    # round 1
    Rt_values = {}
    CHKt_values = {}
    for t in trustees:
        result = KK_Sign1(t, KeyID, M)
        if result is None:
            return None
        Rt_values[t], CHKt_values[t] = result

    R = bytearray(CRV.R)
    for t in trustees:
        for i in range(len(R)):
            R[i] ^= Rt_values[t][i]
    R = bytes(R)

    CHK_values = {}

    for target_t in trustees:
        chk = bytearray(CRV.CHK[target_t])
        for t in trustees:
            for i in range(len(chk)):
                chk[i] ^= CHKt_values[t][i]
        CHK_values[target_t] = bytes(chk)

    # Round 2
    Zt_values = {}
    path_shares = {}
    for t in trustees:
        result = KK_Sign2(t, R, CHK_values[t])
        if result is None:
            return None
        path_t, Zt = result
        path_shares[t] = [_to_n_bytes(node) for node in path_t]
        Zt_values[t] = Zt

    h = hash_lms((1, KeyID), R, M)
    CRVt = WINTER(h, CRV.SK)
    Z = []
    for i in range(len(CRVt)):
        if isinstance(CRVt[i], int):
            value = bytearray(CRVt[i].to_bytes(N_BYTES, "big"))
        else:
            value = bytearray(CRVt[i])
        for t in trustees:
            share = Zt_values[t][i]
            if isinstance(share, int):
                share = share.to_bytes(N_BYTES, "big")
            for j in range(len(value)):
                value[j] ^= share[j]
        Z.append(bytes(value))
    crv_path_nodes = CRV.PATH[:-1]
    path_keyid = CRV.PATH[-1]
    PATH = []
    for idx, node in enumerate(crv_path_nodes):
        value = bytearray(node)
        for t in trustees:
            share = path_shares[t][idx]
            for j in range(len(value)):
                value[j] ^= share[j]
        PATH.append(bytes(value))
    PATH.append(path_keyid)
    return R, PATH, Z


# def KK_Sign1(t, KeyID: int, M):
#     if t not in K:
#         return None
#     if KeyID not in K[t]:
#         return None
#     if KeyID in used_keys[t]:
#         return None
#     current[t] = (KeyID, M)
#     used_keys[t].add(KeyID)
#     Kt=K[t][KeyID]["Kt"]
#     return KK_GenSig1(Kt, KeyID)
def KK_Sign1(t, KeyID: int, M):
    if t not in K:
        return None
    if t not in used_keys:
        used_keys[t] = set()
    if KeyID in used_keys[t]:
        return None
    current[t] = (KeyID, M)
    used_keys[t].add(KeyID)
    return KK_GenSig1(K[t], KeyID)


def KK_GenSig1(Kt: bytes, KeyID: int):
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
    if t not in trustee_path_lens:
        return None
    if KeyID not in trustee_path_lens[t]:
        return None
    if KK_Auth(K[t], KeyID, R_Prime, CHK_Prime):
        h = hash_lms((1, KeyID), R_Prime, M)
        return KK_GenSig2(K[t], KeyID, h, trustee_path_lens[t][KeyID])
    return None



# def KK_GenSig2(Kt, KeyID: int, h):
#     PATHt = Kt[KeyID]["PATHt"]
#     SKt = Kt[KeyID]["SKt"]
#     Zt = WINTER(h, SKt)
#     return PATHt, Zt
def KK_GenSig2(Kt: bytes, KeyID: int, h, path_lens):
    SK_share = []

    for i in range(A + C):
        row = []
        for j in range(CHAIN_LEN):
            row.append(PRF_Chain(Kt, KeyID, i, j, N_BYTES))
        SK_share.append(row)
    Zt = WINTER(h, SK_share)
    PATHt = [
        PRF_Path(Kt, KeyID, node_idx, node_len)
        for node_idx, node_len in enumerate(path_lens)
    ]
    return PATHt, Zt



# minimal project
# def KK_Auth(KeyID: int, R_Prime, CHK_Prime):
#     expectCHK = hash_lms((20, KeyID), R_Prime)
#     return CHK_Prime == expectCHK
def KK_Auth(Kt: bytes, KeyID: int, R_Prime: bytes, CHK_Prime: bytes):
    if isinstance(R_Prime, int):
        R_Prime = R_Prime.to_bytes(N_BYTES, "big")
    return PRF_Auth(Kt, KeyID, R_Prime) == CHK_Prime
