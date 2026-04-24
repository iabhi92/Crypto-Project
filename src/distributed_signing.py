from hash import hash_lms
from utils import N, N_BYTES, CRV
from lamport import WINTER
import secrets

# K[t][KeyID]={ "Rt":"","CHKt":"","Expect_CHK":"","PATHt":"","SKt":""}
K = {}
used_keys = {}
current = {}

PRF_R_TWEAK = (30,)
PRF_CHK_TWEAK = (31,)
PRF_AUTH_TWEAK = (32,)
PRF_PATH_TWEAK = (33,)
PRF_CHAIN_TWEAK = (34,)


def _to_n_bytes(v):
    if isinstance(v, int):
        return v.to_bytes((N + 7) // 8, "big")
    return bytes(v)


def _xor_bytes(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def _serialize_len(n: int) -> bytes:
    return n.to_bytes(4, "big")


def PRF_R(seed: bytes, key_id: int, out_len: int) -> bytes:
    return hash_lms(PRF_R_TWEAK + (key_id,), seed, _serialize_len(out_len))[:out_len]


def PRF_Chk(seed: bytes, key_id: int, out_len: int) -> bytes:
    return hash_lms(PRF_CHK_TWEAK + (key_id,), seed, _serialize_len(out_len))[:out_len]


def PRF_Auth(seed: bytes, key_id: int, r: bytes) -> bytes:
    return hash_lms(PRF_AUTH_TWEAK + (key_id,), seed, r)


def PRF_Path(seed: bytes, key_id: int, node_idx: int, out_len: int) -> bytes:
    return hash_lms(PRF_PATH_TWEAK + (key_id, node_idx), seed, _serialize_len(out_len))[:out_len]


def PRF_Chain(seed: bytes, key_id: int, i: int, j: int, out_len: int) -> bytes:
    return hash_lms(PRF_CHAIN_TWEAK + (key_id, i, j), seed, _serialize_len(out_len))[:out_len]


def _is_seed_mode(sk_shares) -> bool:
    return bool(sk_shares) and isinstance(sk_shares[0], (bytes, bytearray))


def KK_Setup(SK_shares, k, KeyID: int, SK, R, PATH):
    global K, used_keys, current
    crv = CRV()
    Rt_list = {}
    CHKt_list = {}
    PATHt_list = {}
    SKt_list = {}
    if isinstance(R, int):
        R = R.to_bytes((N + 7) // 8, "big")
    R = bytes(R)
    for t in range(1, k + 1):
        if t not in K:
            K[t] = {}
        if t not in used_keys:
            used_keys[t] = set()
        if t not in current:
            current[t] = None

    seed_mode = _is_seed_mode(SK_shares)
    path_as_bytes = [_to_n_bytes(node) for node in PATH]

    chk_len = len(hash_lms((20, KeyID), R))
    for t in range(1, k + 1):
        if seed_mode:
            seed = bytes(SK_shares[t - 1])
            Rt_list[t] = PRF_R(seed, KeyID, len(R))
            CHKt_list[t] = PRF_Chk(seed, KeyID, chk_len)
            PATHt_list[t] = [PRF_Path(seed, KeyID, idx, len(node)) for idx, node in enumerate(path_as_bytes)]

            skt = []
            for i in range(len(SK)):
                row = []
                for j in range(len(SK[i])):
                    row.append(PRF_Chain(seed, KeyID, i, j, N_BYTES))
                skt.append(row)
            SKt_list[t] = skt
        else:
            Rt_list[t] = secrets.token_bytes(len(R))
            CHKt_list[t] = secrets.token_bytes(chk_len)
            # Backward-compatible share mode: keep CRV.PATH equal to input PATH.
            # Use zero path shares so aggregator recombination leaves PATH unchanged.
            PATHt_list[t] = [b"\x00" * len(node) for node in path_as_bytes]
            SKt_list[t] = SK_shares[t - 1]

    crv_R = bytearray(R)
    for t in range(1, k + 1):
        for i in range(len(R)):
            crv_R[i] ^= Rt_list[t][i]
    crv.R = bytes(crv_R)

    CHK = hash_lms((20, KeyID), R)
    crv_CHK = bytearray(CHK)
    for t in range(1, k + 1):
        for i in range(len(CHK)):
            crv_CHK[i] ^= CHKt_list[t][i]
    crv.CHK = bytes(crv_CHK)

    if seed_mode:
        crv_path = [bytearray(node) for node in path_as_bytes]
        for t in range(1, k + 1):
            for node_idx in range(len(crv_path)):
                for i in range(len(crv_path[node_idx])):
                    crv_path[node_idx][i] ^= PATHt_list[t][node_idx][i]
        crv.PATH = [bytes(node) for node in crv_path]
    else:
        crv.PATH = [bytes(node) for node in path_as_bytes]

    crv_SK = []
    for i in range(len(SK)):
        row = []
        for j in range(len(SK[i])):
            value = bytearray(_to_n_bytes(SK[i][j]))
            for t in range(1, k + 1):
                share = _to_n_bytes(SKt_list[t][i][j])
                for x in range(len(value)):
                    value[x] ^= share[x]
            row.append(bytes(value))
        crv_SK.append(row)
    crv.SK = crv_SK

    for t in range(1, k + 1):
        K[t][KeyID] = {
            "Rt": Rt_list[t],
            "CHKt": CHKt_list[t],
            "Expect_CHK": CHK,
            "PATHt": [bytes(node) for node in PATHt_list[t]],
            "SKt": SKt_list[t]
        }
    return crv


def KK_Aggregator_Sign(M, CRV, KeyID: int):
    trustees = []
    for t in K:
        if KeyID in K[t]:
            trustees.append(t)
    trustees.sort()
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

    CHK = bytearray(CRV.CHK)
    for t in trustees:
        for i in range(len(CHK)):
            CHK[i] ^= CHKt_values[t][i]
    CHK = bytes(CHK)

    # Round 2
    Zt_values = {}
    path_shares = {}
    for t in trustees:
        result = KK_Sign2(t, R, CHK)
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
            value = bytearray(CRVt[i].to_bytes((N + 7) // 8, "big"))
        else:
            value = bytearray(CRVt[i])
        for t in trustees:
            share = Zt_values[t][i]
            if isinstance(share, int):
                share = share.to_bytes((N + 7) // 8, "big")
            for j in range(len(value)):
                value[j] ^= share[j]
        Z.append(bytes(value))
    path_acc = [bytearray(_to_n_bytes(node)) for node in CRV.PATH]
    for t in trustees:
        for idx in range(len(path_acc)):
            for j in range(len(path_acc[idx])):
                path_acc[idx][j] ^= path_shares[t][idx][j]
    PATH = [bytes(node) for node in path_acc]
    return R, PATH, Z


def KK_Sign1(t, KeyID: int, M):
    if t not in K:
        return None
    if KeyID not in K[t]:
        return None
    if KeyID in used_keys[t]:
        return None
    current[t] = (KeyID, M)
    used_keys[t].add(KeyID)
    return KK_GenSig1(K[t], KeyID)


def KK_GenSig1(Kt, KeyID: int):
    Rt = Kt[KeyID]["Rt"]
    CHKt = Kt[KeyID]["CHKt"]
    return Rt, CHKt


def KK_Sign2(t, R_Prime, CHK_Prime):
    if t not in current or current[t] is None:
        return None
    else:
        KeyID, M = current[t]
        current[t] = None
        if KK_Auth(KeyID, R_Prime, CHK_Prime):
            h = hash_lms((1, KeyID), R_Prime, M)
            return KK_GenSig2(K[t], KeyID, h)
        else:
            return None


def KK_GenSig2(Kt, KeyID: int, h):
    PATHt = Kt[KeyID]["PATHt"]
    SKt = Kt[KeyID]["SKt"]
    Zt = WINTER(h, SKt)
    return PATHt, Zt


# def KK_Auth(Kt, KeyID: int, R_Prime, CHK_Prime):
def KK_Auth(KeyID: int, R_Prime, CHK_Prime):
    expectCHK = hash_lms((20, KeyID), R_Prime)
    return CHK_Prime == expectCHK
