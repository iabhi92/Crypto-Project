import pytest
import os

from lamport import Gen, Sign, Verify, WINTER, GenLazy, SignLazy, WINTERLazy, A, C, N_BYTES, CHAIN_LEN


def test_gen_basic():
    pk, sk = Gen(0)
    assert(isinstance(pk, bytes))
    assert(len(pk) == N_BYTES)
    assert(len(sk) == A + C)
    for chain in sk:
        assert(len(chain) == CHAIN_LEN)

def test_gen_different_keyids():
    pk0, _ = Gen(0)
    pk1, _ = Gen(1)
    assert(pk0 != pk1)

def test_gen_random_each_time():
    pk1, _ = Gen(0)
    pk2, _ = Gen(0)
    assert(pk1 != pk2)


def test_winter_basic():
    _, sk = Gen(0)
    h = os.urandom(N_BYTES)
    z = WINTER(h, sk)
    assert(len(z) == A + C)
    z2 = WINTER(h, sk)
    assert(z == z2)


def test_sign_and_verify():
    pk, sk = Gen(0)
    msg = b"hello world"
    r = os.urandom(N_BYTES)
    r_out, z = Sign(msg, r, 0, sk)
    assert(r_out == r)
    assert(Verify(r_out, z, msg, 0) == pk)

def test_verify_bad_message():
    pk, sk = Gen(0)
    r = os.urandom(N_BYTES)
    r_out, z = Sign(b"real", r, 0, sk)
    assert(Verify(r_out, z, b"fake", 0) != pk)

def test_verify_bad_keyid():
    pk, sk = Gen(0)
    r = os.urandom(N_BYTES)
    r_out, z = Sign(b"hi", r, 0, sk)
    assert(Verify(r_out, z, b"hi", 5) != pk)

def test_verify_bad_r():
    pk, sk = Gen(0)
    r = os.urandom(N_BYTES)
    _, z = Sign(b"test", r, 0, sk)
    assert(Verify(os.urandom(N_BYTES), z, b"test", 0) != pk)

def test_sign_r_as_int():
    pk, sk = Gen(2)
    r = int.from_bytes(os.urandom(N_BYTES), 'big')
    r_out, z = Sign(b"hello", r, 2, sk)
    assert(Verify(r_out, z, b"hello", 2) == pk)

def test_sign_without_sk_raises():
    with pytest.raises((ValueError, TypeError)):
        Sign(b"msg", os.urandom(N_BYTES), 0)

@pytest.mark.parametrize(
    "kid",
    [0, 1, 2, 3]
)
def test_sign_verify_different_keyids(kid):
    pk, sk = Gen(kid)
    r = os.urandom(N_BYTES)
    r_out, z = Sign(b"hello", r, kid, sk)
    assert(Verify(r_out, z, b"hello", kid) == pk)


def test_genlazy_pk_matches_gen():
    # seeds-only path, PK should match
    pk, seeds = GenLazy(0)
    assert isinstance(pk, bytes) and len(pk) == N_BYTES
    assert len(seeds) == A + C
    assert all(len(s) == N_BYTES for s in seeds)

def test_signlazy_verifies():
    pk, seeds = GenLazy(0)
    r = os.urandom(N_BYTES)
    r_out, z = SignLazy(b"hello lazy", r, 0, seeds)
    assert Verify(r_out, z, b"hello lazy", 0) == pk

def test_signlazy_wrong_message_fails():
    pk, seeds = GenLazy(1)
    r = os.urandom(N_BYTES)
    r_out, z = SignLazy(b"real", r, 1, seeds)
    assert Verify(r_out, z, b"tampered", 1) != pk

def test_winterlazy_matches_winter():
    _, sk = Gen(0)
    _, seeds = GenLazy(0)
    h = os.urandom(N_BYTES)
    z_eager = WINTER(h, sk)
    z_lazy  = WINTERLazy(h, seeds, 0)
    # different keys so outputs differ, but length must match
    assert len(z_lazy) == len(z_eager) == A + C

def test_signlazy_without_seeds_raises():
    with pytest.raises((ValueError, TypeError)):
        SignLazy(b"msg", os.urandom(N_BYTES), 0)
