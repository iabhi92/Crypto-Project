from distributed_signing import KK_Setup
from stateful_hash import StatefulGen, keyIDs
from merkle_tree import MT_MakePath
from utils import randomBits, N_BYTES, CHAIN_LEN, A, C, CPK, CRV
from hash import hash_lms

def ShardSetup(d: int, k: int, cl) -> tuple[CPK, CRV, list[int]]:
    ks = [0] * k
    crv = [0] * d
    
    for i in range(0, k):
        ks[i] = randomBits().to_bytes(N_BYTES, 'big')

    cpk, csk = StatefulGen(d)

    for keyID in range(0, d):
        r = randomBits().to_bytes(N_BYTES, 'big')

        pk = []
        for index in range(0, len(keyIDs)):
            tips = [csk[index][i][CHAIN_LEN - 1] for i in range(A + C)]
            pk.append(hash_lms((0, index), *tips)[:N_BYTES])

        path = MT_MakePath(pk[0:d], keyID)
        sk = csk[keyID]
        k_prime = len(cl[keyID])
        keys = MakeKeyList(ks, cl[keyID])

        crv[keyID] = KK_Setup(keys, k_prime, keyID, sk, r, path)

    return (cpk, crv, ks)


def MakeKeyList(ks: list, c: list) -> list:
    keylist = [0] * len(c)

    for i in range(0, len(c)):
        keylist[i] = ks[c[i]]

    return keylist


def AggregatorSign():
    return