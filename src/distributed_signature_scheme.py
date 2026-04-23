from distributed_signing import KK_Setup, KK_GenSig1, KK_GenSig2, KK_Auth
from stateful_hash import StatefulGen, StatefulVerify
from merkle_tree import MT_MakePath
from lamport import WINTER
from utils import randomBits, N_BYTES, CHAIN_LEN, A, C, CPK, CRV, PATH, CL
from hash import hash_lms

"""
Aggregator/Dealer functions
"""

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
def AggregatorSign(m: bytes, crv: list[CRV], keyID: int) -> tuple[PATH, int, list[int]]:
    c = cl_s[keyID]
    
    r_ts = []
    chk_ts = []
    path_ts = []
    z_ts = []

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

        path_ts.append(path_t)
        z_ts.append(z_t)
        i += 1

    h = hash_lms((1, keyID), r, m)
    z_crv = WINTER(h, crv[keyID].SK)
    
    # Im assuming there was a typo in the paper here
    # See page 24 https://cic.iacr.org/p/2/2/24/pdf
    path = crv[keyID].PATH
    for path_t in path_ts: path ^= path_t

    # This could be wrong. Right now this expects z_ts to be something like this
    # [
    #   [a, b, c],
    #   [c, d, e],
    #   [f, g, h]
    # ]
    # It should then give z as
    # [(z_crv[0] ^ a ^ c ^ f), (z_crv[1] ^ b ^ d ^ g), (z_crv[2] ^ c ^ e ^ h)]
    z = z_crv
    for i in range(0, len(z_ts[0])):
        z_i = z_ts[0][i]

        for x in range(0, len(z_ts)):
            z_i ^= z_ts[x][i]

        z[i] ^= z_i

    return (path, r, z)


# This is not in the paper but made this so it was clear
def AggregatorVerify(m: bytes, r: int, path: PATH, z) -> bool:
    return StatefulVerify(m, r, path, z)

""" 
Trustee setup function
"""

keylist: list[list] = []
current: list[tuple] = []
k_t = None

# I think the dealer runs this and gives the keylist, current 
# and k[t] to trustee t
def TrusteeSetup(cl: CL, ks: list, k: int):
    global keylist, current
    
    keylist = [0] * k
    current = [0] * k

    for t in range(0, k):
        keylist[t] = []

        # Not sure where d comes from
        for keyID in range(0, d):
            if t in cl[keyID]:
                keylist[t].append(keyID)
        
        current[t] = None

    # Returning this so the dealer can distribute the lists to each trustee
    return (keylist, current, ks)


"""
Functions that run on the trustee
"""

def ShardSign1(t, keyID, m):
    global keylist, current
    
    if keyID not in keylist[t]:
        return None
    else:
        keylist[t].remove(keyID)
        current[t] = (keyID, m)
        
        return KK_GenSig1(k_t, keyID)


def ShardSign2(t, r_prime, chk_prime_t):
    if current is None:
        return None
    else:
        keyID, m = current[t]
        current[t] = None

        if KK_Auth(k_t, keyID, r_prime, chk_prime_t):
            # Don't know how to get r from r_prime
            # Could be a typo, assuming it is r_prime instead of r
            # page 25
            h = hash_lms((1, keyID), r_prime, m)
            
            return KK_GenSig2(k_t, keyID, h)
        else:
            return None


