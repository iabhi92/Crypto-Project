import distributed_signing as ds
from hash import hash_lms

keylist = {}


def TrusteeSetup(CL, K_store, k):
    global keylist
    keylist = {}
    ds.K = K_store
    for t in range(1, k + 1):
        if t not in ds.K:
            raise ValueError(f"Missing key material for trustee {t}")
        keylist[t] = set()
        for KeyID in range(len(CL)):
            if t in CL[KeyID]:
                keylist[t].add(KeyID)
        ds.current[t] = None


def ShardSign1(t, KeyID, M):
    global keylist
    if t not in keylist:
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
    if t not in ds.current:
        return None
    if ds.current[t] is None:
        return None
    else:
        KeyID, M = ds.current[t]
        ds.current[t] = None
        # if ds.KK_Auth(K[t],KeyID,R_Prime,CHK_Prime):
        if ds.KK_Auth(KeyID, R_Prime, CHK_Prime):
            h = hash_lms((1, KeyID), R_Prime, M)
            return ds.KK_GenSig2(ds.K[t], KeyID, h)
        else:
            return None
