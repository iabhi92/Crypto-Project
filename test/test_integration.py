import pytest
import os
import stateful_hash as sh
from stateful_hash import StatefulGen, StatefulSign, StatefulVerify
from utils import randomBits


# reset all the module globals before each test so they dont interfere with each other
@pytest.fixture(autouse=True)
def setup():
    sh.cpk = None
    sh.csk = None
    sh.keyIDs = {}
    StatefulGen(2)


# basic test - sign a message and check it verifies correctly
def test_sign_and_verify():
    r, path, z = StatefulSign(0, b"hello world")
    result = StatefulVerify(b"hello world", r, path, z)
    assert result == True


# if we verify with a different message it should fail
def test_wrong_message_fails():
    r, path, z = StatefulSign(0, b"real message")
    assert StatefulVerify(b"wrong message", r, path, z) == False


# signing two different messages should give different outputs
def test_signatures_are_unique():
    r0, _, z0 = StatefulSign(0, b"message one")
    r1, _, z1 = StatefulSign(1, b"message two")
    assert r0 != r1
    assert z0 != z1


# check that both keys in the tree actually work
def test_all_keys_can_sign():
    for kid in range(2):
        r, path, z = StatefulSign(kid, b"test")
        assert StatefulVerify(b"test", r, path, z) == True


# the path has the keyID at the end, changing it should break verification
def test_swapped_key_path_fails():
    r, path, z = StatefulSign(0, b"hello")
    # manually point the path at key 1 instead
    bad_path = path[:-1] + [1]
    assert StatefulVerify(b"hello", r, bad_path, z) == False


# winternitz is one time so signing with the same key twice should be blocked
def test_cannot_reuse_key():
    StatefulSign(0, b"first")
    second = StatefulSign(0, b"second")
    assert second == ()


# tamper with the z values and verify should fail
def test_tampered_signature_fails():
    r, path, z = StatefulSign(0, b"hello")
    # swap the first element of z with random garbage
    bad_z = [os.urandom(len(z[0]))] + z[1:]
    assert StatefulVerify(b"hello", r, path, bad_z) == False


# if r is wrong the hash wont match so verify should fail
def test_wrong_r_fails():
    _, path, z = StatefulSign(0, b"hello")
    wrong_r = randomBits()
    assert StatefulVerify(b"hello", wrong_r, path, z) == False
