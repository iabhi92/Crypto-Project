import pytest
import os 
from merkle_tree import MT_Construct, MT_MakePath, MT_Verify, MT_Extract

def make_leaves(n: int, seed: int = 0) -> list[bytes]:
    """Return n distinct deterministic 32-byte leaf values."""
    return [os.urandom(32) if seed == 0 else (i + seed).to_bytes(32, "big")
            for i in range(n)]
 
def deterministic_leaves(n: int) -> list[bytes]:
    """Deterministic leaves so tests are reproducible."""
    return [(i).to_bytes(32, "big") for i in range(n)]
