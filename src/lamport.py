import os
import math

from hash import hash_lms
from utils import N_BYTES, W, A, C, CHAIN_LEN


def _split_w(data, count):
    chunks = []
    for byte in data:
        if W == 8:
            chunks.append(byte)
        elif W == 4:
            chunks.append((byte >> 4) & 0x0F)
            chunks.append(byte & 0x0F)
        elif W == 2:
            for shift in (6, 4, 2, 0):
                chunks.append((byte >> shift) & 0x03)
        else:
            for shift in range(7, -1, -1):
                chunks.append((byte >> shift) & 0x01)
        if len(chunks) >= count:
            break
    return chunks[:count]


def _build_chain(seed, i, key_id):
    chain = [seed]
    for j in range(1, CHAIN_LEN):
        nxt = hash_lms((2, i, j, key_id), chain[j - 1])[:N_BYTES]
        chain.append(nxt)
    return chain


def _chain_element(seed, i, j, key_id):
    # walk j steps from seed without storing intermediate values
    val = seed
    for step in range(1, j + 1):
        val = hash_lms((2, i, step, key_id), val)[:N_BYTES]
    return val


def Gen(KeyID):
    SK = []
    for i in range(A + C):
        seed = os.urandom(N_BYTES)
        chain = _build_chain(seed, i, KeyID)
        SK.append(chain)

    Y = [SK[i][CHAIN_LEN - 1] for i in range(A + C)]
    PK = hash_lms((0, KeyID), *Y)[:N_BYTES]
    return PK, SK


def GenLazy(KeyID):
    # seeds only — chain elements recomputed at signing time
    seeds = [os.urandom(N_BYTES) for _ in range(A + C)]
    Y = [_chain_element(seeds[i], i, CHAIN_LEN - 1, KeyID) for i in range(A + C)]
    PK = hash_lms((0, KeyID), *Y)[:N_BYTES]
    return PK, seeds


def WINTERLazy(h, seeds, KeyID):
    if isinstance(h, int):
        h = h.to_bytes(N_BYTES, "big")

    b = _split_w(h, A)
    csum = A * (CHAIN_LEN - 1) - sum(b)
    csum_bytes = csum.to_bytes(math.ceil(C * W / 8), "big")
    b_csum = _split_w(csum_bytes, C)
    b_all = b + b_csum

    return [_chain_element(seeds[i], i, b_all[i], KeyID) for i in range(A + C)]


def SignLazy(M, R, KeyID, seeds=None):
    if seeds is None:
        raise ValueError("seeds required")
    if isinstance(R, int):
        R = R.to_bytes(N_BYTES, "big")
    h = hash_lms((1, KeyID), R, M)[:N_BYTES]
    return R, WINTERLazy(h, seeds, KeyID)


def WINTER(h, SK):
    if isinstance(h, int):
        h = h.to_bytes(N_BYTES, "big")

    b = _split_w(h, A)
    # checksum makes digit-increment forgery impossible
    csum = A * (CHAIN_LEN - 1) - sum(b)
    csum_bytes = csum.to_bytes(math.ceil(C * W / 8), "big")
    b_csum = _split_w(csum_bytes, C)

    b_all = b + b_csum
    return [SK[i][b_all[i]] for i in range(A + C)]


def Sign(M, R, KeyID, SK=None):
    if SK is None:
        raise ValueError("SK required")
    if isinstance(R, int):
        R = R.to_bytes(N_BYTES, "big")
    h = hash_lms((1, KeyID), R, M)[:N_BYTES]
    return R, WINTER(h, SK)


def Verify(R, Z, M, KeyID):
    if isinstance(R, int):
        R = R.to_bytes(N_BYTES, "big")

    h = hash_lms((1, KeyID), R, M)[:N_BYTES]
    b = _split_w(h, A)
    csum = A * (CHAIN_LEN - 1) - sum(b)
    csum_bytes = csum.to_bytes(math.ceil(C * W / 8), "big")
    b_csum = _split_w(csum_bytes, C)
    b_all = b + b_csum

    Y_prime = []
    for i in range(A + C):
        u = Z[i]
        if isinstance(u, int):
            u = u.to_bytes(N_BYTES, "big")
        for j in range(b_all[i] + 1, CHAIN_LEN):
            u = hash_lms((2, i, j, KeyID), u)[:N_BYTES]
        Y_prime.append(u)

    return hash_lms((0, KeyID), *Y_prime)[:N_BYTES]
