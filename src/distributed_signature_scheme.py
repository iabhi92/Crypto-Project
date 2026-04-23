from distributed_signing import KK_Setup
from stateful_hash import StatefulGen
from merkle_tree import MT_MakePath
from lamport import WINTER
from utils import randomBits, N_BYTES, CHAIN_LEN, A, C, CPK, CRV, PATH, CL
from hash import hash_lms

cl_s: CL = []

# This sets up distributed signature scheme for each coalition in cl
def ShardSetup(d: int, k: int, cl: CL) -> tuple[CPK, CRV, list[int]]:
    # Setting cl_s here to be used by other functions in this file
    global cl_s
    cl_s = cl

    ks = [0] * k
    crvs = [0] * d
    
    for i in range(0, k):
        ks[i] = randomBits().to_bytes(N_BYTES, 'big')

    cpk, csk = StatefulGen(d)

    for keyID in range(0, d):
        r = randomBits().to_bytes(N_BYTES, 'big')

        pk = []
        for index in range(0, d):
            tips = [csk[index][i][CHAIN_LEN - 1] for i in range(A + C)]
            pk.append(hash_lms((0, index), *tips)[:N_BYTES])

        path = MT_MakePath(pk[0:d], keyID)
        sk = csk[keyID]
        k_prime = len(cl[keyID])
        keys = MakeKeyList(ks, cl[keyID])

        crvs[keyID] = KK_Setup(keys, k_prime, keyID, sk, r, path)

    return (cpk, crvs, ks)


# This makes the keylist for c, which is one of the coalitions in cl_s
def MakeKeyList(ks: list, c: list) -> list:
    keylist = [0] * len(c)

    for i in range(0, len(c)):
        keylist[i] = ks[c[i]]

    return keylist


# This signs a message using the trustees for the coalition in cl_s[keyID]
def AggregatorSign(m, crv: list[CRV], keyID: int) -> tuple[PATH, int, int]:
    c = cl_s[keyID]
    
    r_ts = [0] * len(c)
    chk_ts = [0] * len(c)
    path_ts = [0] * len(c)
    z_ts = [0] * len(c)

    for t in c:
        # This needs to get the result of shardsign1 when called by that trustee
        # So this needs to communicate with the program running on that trustee
        r_t, chk_t = ShardSign1(t, keyID, m)

        r_ts.append(r_t)
        chk_ts.append(chk_t)

    r = crv[keyID].R
    for r_t in r_ts: r ^= r_t

    chk = crv[keyID].CHK
    for chk_t in chk_ts: chk ^= chk_t

    i = 0
    for t in c:
        # This needs to get the result of shardsign2 when called by that trustee
        # So this needs to communicate with the program running on that trustee
        path_t, z_t = ShardSign2(t, r, chk[i])
        i += 1

    h = hash_lms((1, keyID), r, m)
    z_crv = WINTER(h, crv[keyID].SK)
    
    # Im assuming there was a typo in the paper here
    # See page 24 https://cic.iacr.org/p/2/2/24/pdf
    path = crv[keyID].PATH
    for path_t in path_ts: path ^= path_t

    z = z_crv
    for z_t in z_ts: z ^= z_t

    return path, r, z


def TrusteeSetup(cl, ks, k):
    return


def ShardSign1(t, keyID, m):
    return


def ShardSign2(t, r_prime, chk_prime_t):
    return

