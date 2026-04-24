import distributed_signing as ds
from stateful_hash import StatefulGen, StatefulVerify
from merkle_tree import MT_MakePath
from lamport import WINTER
from utils import randomBits, N_BYTES, CHAIN_LEN, A, C, CPK, CRV, PATH, CL
from hash import hash_lms
import stateful_hash

keylist = {}

"""
Aggregator/Dealer functions
"""

cl_s: CL = []


# This sets up distributed signature scheme for each coalition in cl
def ShardSetup(d: int, n: int, cl: CL) -> tuple[CPK, list[CRV], dict]:
    global cl_s
    cl_s = cl
    trustee_init = {}
    for t in range(1, n + 1):
        trustee_init[t] = {
            "seed": randomBits().to_bytes(N_BYTES, "big"),
            "allowed_keyids": set(),
            "path_lens": {},
        }

    crvs = [0] * d
    cpk, csk = StatefulGen(d)
    pk = []
    for index in range(d):
        tips = [csk[index][i][CHAIN_LEN - 1] for i in range(A + C)]
        pk.append(hash_lms((0, index), *tips)[:N_BYTES])
    for keyID in range(d):
        r = randomBits().to_bytes(N_BYTES, "big")
        path = MT_MakePath(pk, keyID)
        sk = csk[keyID]
        coalition = cl[keyID]
        keys = {}
        for t in coalition:
            keys[t] = trustee_init[t]["seed"]
        crvs[keyID] = ds.KK_Setup(keys, keyID, sk, r, path)
        for t in coalition:
            trustee_init[t]["allowed_keyids"].add(keyID)
            trustee_init[t]["path_lens"][keyID] = crvs[keyID].path_lens
    stateful_hash.csk = None
    return cpk, crvs, trustee_init


# This makes the keylist for c, which is one of the coalitions in cl_s
def MakeKeyList(ks: dict, c: list) -> dict:
    keys = {}
    for t in c:
        if t not in ks:
            raise ValueError(f"Trustee {t} is not in the generated key store")
        keys[t] = ks[t]
    return keys


# This signs a message using the trustees for the coalition in cl_s[keyID]
def AggregatorSign(m: bytes, crv: list[CRV], keyID: int):
    if keyID < 0 or keyID >= len(crv):
        return None
    if keyID >= len(cl_s):
        return None
    c = cl_s[keyID]
    r_ts = []
    chk_ts = []
    # Round 1: ask each trustee in the coalition to produce Rt and CHKt
    for t in c:
        result = ShardSign1(t, keyID, m)
        if result is None:
            return None

        r_t, chk_t = result
        r_ts.append(r_t)
        chk_ts.append(chk_t)
    # Recover R = CRV.R xor all Rt
    r = ds._xor_many([crv[keyID].R] + r_ts)
    # Recover each trustee's own CHK value
    chk_values = {}
    for target_t in c:
        chk = bytearray(crv[keyID].CHK[target_t])
        for chk_t in chk_ts:
            for i in range(len(chk)):
                chk[i] ^= chk_t[i]
        chk_values[target_t] = bytes(chk)

    path_ts = []
    z_ts = []

    # Round 2: ask each trustee to authenticate R and produce PATHt, Zt
    for t in c:
        result = ShardSign2(t, r, chk_values[t])
        if result is None:
            return None

        path_t, z_t = result
        path_ts.append(path_t)
        z_ts.append(z_t)

    h = hash_lms((1, keyID), r, m)
    z_crv = WINTER(h, crv[keyID].SK)
    # Recover Z = Z_CRV xor all Zt
    z = []
    for i in range(len(z_crv)):
        value = bytearray(ds._to_n_bytes(z_crv[i]))
        for z_t in z_ts:
            share = ds._to_n_bytes(z_t[i])
            for j in range(len(value)):
                value[j] ^= share[j]
        z.append(bytes(value))
    # Recover PATH = PATH_CRV xor all PATHt
    crv_path_nodes = crv[keyID].PATH[:-1]
    path_keyid = crv[keyID].PATH[-1]
    path = []
    for idx, node in enumerate(crv_path_nodes):
        value = bytearray(node)
        for path_t in path_ts:
            share = path_t[idx]
            for j in range(len(value)):
                value[j] ^= share[j]
        path.append(bytes(value))
    path.append(path_keyid)
    return r, path, z


# This is not in the paper but made this so it was clear
def AggregatorVerify(m: bytes, r: bytes, path: PATH, z) -> bool:
    return StatefulVerify(m, r, path, z)


def TrusteeSetup(
    trustee_id: int,
    seed: bytes,
    allowed_keyids: set[int],
    path_lens: dict[int, list[int]],
) -> None:
    global keylist

    ds.K[trustee_id] = bytes(seed)
    ds.used_keys[trustee_id] = set()
    ds.current[trustee_id] = None
    ds.trustee_path_lens[trustee_id] = path_lens
    keylist[trustee_id] = set(allowed_keyids)


def ShardSign1(t, KeyID, M):
    global keylist
    if t not in keylist:
        return None
    if t not in ds.K:
        return None
    if t not in ds.current:
        return None
    if KeyID not in keylist[t]:
        return None
    else:
        keylist[t].remove(KeyID)
        ds.current[t] = (KeyID, M)
        return ds.KK_GenSig1(ds.K[t], KeyID)


def ShardSign2(t, R_Prime, CHK_Prime):
    if t not in keylist:
        return None
    if t not in ds.K:
        return None
    if t not in ds.current:
        return None
    if ds.current[t] is None:
        return None
    else:
        KeyID, M = ds.current[t]
        ds.current[t] = None
        if t not in ds.trustee_path_lens:
            return None
        if KeyID not in ds.trustee_path_lens[t]:
            return None
        if ds.KK_Auth(ds.K[t], KeyID, R_Prime, CHK_Prime):
            h = hash_lms((1, KeyID), R_Prime, M)
            path_lens=ds.trustee_path_lens[t][KeyID]
            return ds.KK_GenSig2(ds.K[t], KeyID, h, path_lens)
        else:
            return None
