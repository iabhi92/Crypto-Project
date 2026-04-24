from __future__ import annotations
import os
import random
from typing import Callable, Optional

from hash import hash_lms
from utils import N_BYTES

# Tweak reserved for the PRF/RF distinguishing game (Algorithm 12 in the paper).
# Domain-separated from all LMS/Winternitz tweaks.
_PRF_GAME_TWEAK = (12, 27)


def F(K: bytes, x: bytes, *, label: bytes = b"") -> bytes:
    # concrete PRF F : {0,1}^n x {0,1}^n -> {0,1}^n built on hash_lms
    # optional label byte string gives extra domain separation (Section 3.2)
    if len(K) != N_BYTES or len(x) != N_BYTES:
        raise ValueError(f"F expects {N_BYTES}-byte key and input")
    return hash_lms(_PRF_GAME_TWEAK, label, K, x)[:N_BYTES]


class PRFRFGame:
    # Challenger for Algorithm 12.
    # Call init(), then query(x) as many times as needed, then final(b').

    __slots__ = ("_b", "_k", "_rf_table", "_query_count", "_prf")

    def __init__(self, prf: Callable[[bytes, bytes], bytes] = F) -> None:
        self._prf = prf
        self._b: Optional[int] = None
        self._k: Optional[bytes] = None
        self._rf_table: Optional[dict[bytes, bytes]] = None
        self._query_count = 0

    def init(self, rng: Optional[random.Random] = None) -> None:
        # Algorithm 12, Init: sample b, then either K (PRF mode) or RF table (random function mode)
        r = rng if rng is not None else random.SystemRandom()
        self._b = r.randrange(2)
        self._query_count = 0
        if self._b == 1:
            self._k = os.urandom(N_BYTES)
            self._rf_table = None
        else:
            self._k = None
            self._rf_table = {}

    def query(self, x: bytes) -> bytes:
        # Algorithm 12, Query(x): return F(K, x) or RF(x) depending on b
        if self._b is None:
            raise RuntimeError("init() must be called before query()")
        if len(x) != N_BYTES:
            raise ValueError(f"query expects {N_BYTES}-byte input")
        self._query_count += 1
        if self._b == 1:
            assert self._k is not None
            return self._prf(self._k, x)
        assert self._rf_table is not None
        if x not in self._rf_table:
            self._rf_table[x] = os.urandom(N_BYTES)
        return self._rf_table[x]

    def final(self, b_prime: int) -> bool:
        # Algorithm 12, Final(b'): return True iff b' == b (adversary wins)
        if self._b is None:
            raise RuntimeError("init() must be called before final()")
        if b_prime not in (0, 1):
            raise ValueError("b_prime must be 0 or 1")
        return b_prime == self._b

    @property
    def query_count(self) -> int:
        return self._query_count


# Paper-style function names matching Algorithm 12 notation
def Init(game: PRFRFGame, rng: Optional[random.Random] = None) -> None:
    game.init(rng=rng)


def Query(game: PRFRFGame, x: bytes) -> bytes:
    return game.query(x)


def Final(game: PRFRFGame, b_prime: int) -> bool:
    return game.final(b_prime)
