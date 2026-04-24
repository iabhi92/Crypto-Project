import os
import math

from hash import hash_lms
from utils import N_BYTES, W, A, C, CHAIN_LEN


def _split_w(data: bytes, count: int) -> list[int]:
    # need to split bytes into W-bit chunks - the way you do it changes based on W
    chunks = []
    for byte in data:
        if W == 8:
            chunks.append(byte)
        elif W == 4:
            # grab the top 4 bits then the bottom 4 bits
            chunks.append((byte >> 4) & 0x0F)
            chunks.append(byte & 0x0F)
        elif W == 2:
            # 4 two-bit values packed into one byte
            for shift in (6, 4, 2, 0):
                chunks.append((byte >> shift) & 0x03)
        else:
            # W=1 so just pull out each bit one at a time
            for shift in range(7, -1, -1):
                chunks.append((byte >> shift) & 0x01)
        if len(chunks) >= count:
            break
    return chunks[:count]


def Gen(KeyID: int):
    # generate A+C chains (A chains for message digits, C extra for the checksum)
    SK = []
    for i in range(A + C):
        seed = os.urandom(N_BYTES)
        chain = [seed]
        # build up the chain by repeatedly hashing the previous value
        for j in range(1, CHAIN_LEN):
            nxt = hash_lms((2, i, j, KeyID), chain[j - 1])[:N_BYTES]
            chain.append(nxt)
        SK.append(chain)

    # the public key is just a hash over all the end-of-chain values
    Y = []
    for i in range(A + C):
        Y.append(SK[i][CHAIN_LEN - 1])
    PK = hash_lms((0, KeyID), *Y)[:N_BYTES]
    return PK, SK


def WINTER(h, SK) -> list:
    # sometimes h comes in as an int so just convert it
    if isinstance(h, int):
        h = h.to_bytes(N_BYTES, 'big')

    # get the W-bit digits of h - these tell us how far along each chain to go
    b = _split_w(h, A)

    # the checksum is needed so you can't just flip digits to forge a signature
    csum = A * (CHAIN_LEN - 1) - sum(b)
    csum_bytes = csum.to_bytes(math.ceil(C * W / 8), 'big')
    b_csum = _split_w(csum_bytes, C)

    # stick the message digits and checksum digits together
    b_all = b + b_csum
    Z = []
    for i in range(A + C):
        # the signature piece for chain i is just the element at index b_all[i]
        Z.append(SK[i][b_all[i]])
    return Z


def Sign(M: bytes, R, KeyID: int, SK=None):
    if SK is None:
        raise ValueError("SK must be provided")

    # R is the randomiser - convert to bytes if it came in as an int
    if isinstance(R, int):
        R = R.to_bytes(N_BYTES, 'big')

    # hash R and M together so the signature is tied to both
    h = hash_lms((1, KeyID), R, M)[:N_BYTES]
    Z = WINTER(h, SK)
    return R, Z


def Verify(R, Z, M: bytes, KeyID: int) -> bytes:
    if isinstance(R, int):
        R = R.to_bytes(N_BYTES, 'big')

    # redo the same hash the signer did to get the same h
    h = hash_lms((1, KeyID), R, M)[:N_BYTES]
    b = _split_w(h, A)
    csum = A * (CHAIN_LEN - 1) - sum(b)
    csum_bytes = csum.to_bytes(math.ceil(C * W / 8), 'big')
    b_csum = _split_w(csum_bytes, C)
    b_all = b + b_csum

    # for each chain, hash the signature piece the rest of the way to the tip
    Y_prime = []
    for i in range(A + C):
        u = Z[i]
        if isinstance(u, int):
            u = u.to_bytes(N_BYTES, 'big')
        for j in range(b_all[i] + 1, CHAIN_LEN):
            u = hash_lms((2, i, j, KeyID), u)[:N_BYTES]
        Y_prime.append(u)

    # recompute the public key - if it matches then the signature is valid
    PK_prime = hash_lms((0, KeyID), *Y_prime)[:N_BYTES]
    return PK_prime
