import secrets
import math

N = 128
N_BYTES = N // 8
W = 8           # bigger W = shorter sigs, slower keygen (chain length = 2^W)
A = N // W
C = math.ceil(math.log2(A * (2**W - 1)) / W)
CHAIN_LEN = 2**W

HASH_BACKEND = "sha256"  # set to 'blake2b' for ~1.2x speedup


class CPK:
    pass


class CRV:
    pass


def randomBits(bits=N):
    return secrets.randbits(bits)
