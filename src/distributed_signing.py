from hash import hash_lms
from utils import N, CRV
from lamport import WINTER
import secrets

# K[t][KeyID]={ "Rt":"","CHKt":"","Expect_CHK":"","PATHt":"","SKt":""}
K = {}
used_keys = {}
current = {}


def KK_Setup(SK_shares, k, KeyID: int, SK, R, PATH):
    global K, used_keys, current
    crv = CRV()
    Rt_list = {}
    CHKt_list = {}
    if isinstance(R, int):
        R = R.to_bytes((N + 7) // 8, "big")
    for t in range(1, k + 1):
        if t not in K:
            K[t] = {}
        if t not in used_keys:
            used_keys[t] = set()
        if t not in current:
            current[t] = None

    for t in range(1, k + 1):
        Rt_list[t] = secrets.token_bytes(len(R))
    crv_R = bytearray(R)
    for t in range(1, k + 1):
        for i in range(len(R)):
            crv_R[i] ^= Rt_list[t][i]
    crv.R = bytes(crv_R)

    CHK = hash_lms((20, KeyID), R)
    for t in range(1, k + 1):
        CHKt_list[t] = secrets.token_bytes(len(CHK))
    crv_CHK = bytearray(CHK)
    for t in range(1, k + 1):
        for i in range(len(CHK)):
            crv_CHK[i] ^= CHKt_list[t][i]
    crv.CHK = bytes(crv_CHK)
    crv.PATH = PATH
    crv_SK = []
    for i in range(len(SK)):
        row = []
        for j in range(len(SK[i])):
            if isinstance(SK[i][j], int):
                value = SK[i][j].to_bytes((N + 7) // 8, "big")
            else:
                value = bytearray(SK[i][j])
            for t in range(1, k + 1):
                share = SK_shares[t - 1][i][j]
                if isinstance(share, int):
                    share = share.to_bytes((N + 7) // 8, "big")
                for x in range(len(value)):
                    value[x] ^= share[x]
            row.append(bytes(value))
        crv_SK.append(row)
    crv.SK = crv_SK

    for t in range(1, k + 1):
        K[t][KeyID] = {
            "Rt": Rt_list[t],
            "CHKt": CHKt_list[t],
            # "Expect_CHK": CHK,
            "PATHt": PATH,
            "SKt": SK_shares[t - 1]
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
    for t in trustees:
        result = KK_Sign2(t, R, CHK)
        if result is None:
            return None
        _, Zt = result
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
    PATH = CRV.PATH
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
