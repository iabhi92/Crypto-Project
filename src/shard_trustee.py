import distributed_signing as ds
from stateful_hash import StatefulGen, StatefulVerify
from merkle_tree import MT_MakePath
from lamport import WINTER
from utils import randomBits, N_BYTES, CHAIN_LEN, A, C
from hash import hash_lms
import stateful_hash

keylist = {}
cl_s = []


def ShardSetup(d, n, cl, contribution_provider):
    global cl_s
    cl_s = cl

    trustee_init = {}
    for t in range(1, n + 1):
        trustee_init[t] = {"allowed_keyids": set(), "path_lens": {}}

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

        path_lens = [len(node) for node in path[:-1]]
        sk_shape = (len(sk), len(sk[0]))

        trustee_contribs = {
            t: contribution_provider(t, keyID, r, path_lens, sk_shape)
            for t in coalition
        }

        crvs[keyID] = ds.KK_Setup(trustee_contribs, keyID, sk, r, path)

        for t in coalition:
            trustee_init[t]["allowed_keyids"].add(keyID)
            trustee_init[t]["path_lens"][keyID] = crvs[keyID].path_lens

    # wipe the full secret key ,from here only trustees hold shares
    stateful_hash.csk = None
    return cpk, crvs, trustee_init


def AggregatorSign(m, crv, keyID):
    if keyID < 0 or keyID >= len(crv):
        return None
    if keyID >= len(cl_s):
        return None

    coalition = cl_s[keyID]

    # round 1: collect (Rt, CHKt) from each trustee
    r_shares = []
    chk_shares = []
    for t in coalition:
        result = ShardSign1(t, keyID, m)
        if result is None:
            return None
        r_t, chk_t = result
        r_shares.append(r_t)
        chk_shares.append(chk_t)

    r = ds._xor_many([crv[keyID].R] + r_shares)

    chk_for = {
        t: ds._xor_many([crv[keyID].CHK[t]] + chk_shares)
        for t in coalition
    }

    # round 2: send R and auth tag, collect (path share, Z share)
    path_shares = []
    z_shares = []
    for t in coalition:
        result = ShardSign2(t, r, chk_for[t])
        if result is None:
            return None
        path_t, z_t = result
        path_shares.append(path_t)
        z_shares.append(z_t)

    h = hash_lms((1, keyID), r, m)
    z_crv = WINTER(h, crv[keyID].SK)
    z = [
        ds._xor_many([ds._to_n_bytes(z_crv[i])] + [ds._to_n_bytes(z_t[i]) for z_t in z_shares])
        for i in range(len(z_crv))
    ]

    path = [
        ds._xor_many([bytes(node)] + [path_t[idx] for path_t in path_shares])
        for idx, node in enumerate(crv[keyID].PATH[:-1])
    ] + [crv[keyID].PATH[-1]]

    return r, path, z


def AggregatorVerify(m, r, path, z):
    return StatefulVerify(m, r, path, z)


def TrusteeSetup(trustee_id, seed, allowed_keyids, path_lens):
    ds.K[trustee_id] = bytes(seed)
    ds.used_keys[trustee_id] = set()
    ds.current[trustee_id] = None
    ds.trustee_path_lens[trustee_id] = path_lens
    keylist[trustee_id] = set(allowed_keyids)


def ShardSign1(t, KeyID, M):
    if t not in keylist or t not in ds.K or t not in ds.current:
        return None
    if KeyID not in keylist[t]:
        return None
    keylist[t].remove(KeyID)
    ds.current[t] = (KeyID, M)
    return ds.KK_GenSig1(ds.K[t], KeyID)


def ShardSign2(t, R_Prime, CHK_Prime):
    if t not in keylist or t not in ds.K or t not in ds.current:
        return None
    if ds.current[t] is None:
        return None
    KeyID, M = ds.current[t]
    ds.current[t] = None
    if t not in ds.trustee_path_lens or KeyID not in ds.trustee_path_lens[t]:
        return None
    if ds.KK_Auth(ds.K[t], KeyID, R_Prime, CHK_Prime):
        h = hash_lms((1, KeyID), R_Prime, M)
        path_lens = ds.trustee_path_lens[t][KeyID]
        return ds.KK_GenSig2(ds.K[t], KeyID, h, path_lens)
    return None
