import os
import random

from hash import hash_lms
from utils import N_BYTES

_PRF_GAME_TWEAK = (12, 27)


def F(K, x, *, label=b""):
    if len(K) != N_BYTES or len(x) != N_BYTES:
        raise ValueError(f"K and x must be {N_BYTES} bytes")
    return hash_lms(_PRF_GAME_TWEAK, label, K, x)[:N_BYTES]


class PRFRFGame:
    # Algorithm 12 from the paper: challenger picks b, adversary queries and guesses

    def __init__(self, prf=F):
        self._prf = prf
        self._b = None
        self._k = None
        self._rf_table = None
        self._query_count = 0

    def init(self, rng=None):
        r = rng if rng is not None else random.SystemRandom()
        self._b = r.randrange(2)
        self._query_count = 0
        if self._b == 1:
            self._k = os.urandom(N_BYTES)
            self._rf_table = None
        else:
            self._k = None
            self._rf_table = {}

    def query(self, x):
        if self._b is None:
            raise RuntimeError("call init() first")
        if len(x) != N_BYTES:
            raise ValueError(f"x must be {N_BYTES} bytes")
        self._query_count += 1
        if self._b == 1:
            return self._prf(self._k, x)
        if x not in self._rf_table:
            self._rf_table[x] = os.urandom(N_BYTES)
        return self._rf_table[x]

    def final(self, b_prime):
        if self._b is None:
            raise RuntimeError("call init() first")
        if b_prime not in (0, 1):
            raise ValueError("b_prime must be 0 or 1")
        return b_prime == self._b

    @property
    def query_count(self):
        return self._query_count


def Init(game, rng=None):
    game.init(rng=rng)


def Query(game, x):
    return game.query(x)


def Final(game, b_prime):
    return game.final(b_prime)
