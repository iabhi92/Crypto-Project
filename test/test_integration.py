import os
import pytest

import distributed_signing as ds
import shard_trustee as st
import stateful_hash

# reset all module-level state before each test so nothing leaks between runs
@pytest.fixture(autouse=True)
def reset_globals():
    ds.K = {}
    ds.used_keys = {}
    ds.current = {}
    ds.trustee_path_lens = {}
    st.keylist = {}
    st.cl_s = []
    stateful_hash.cpk = None
    stateful_hash.csk = None
    stateful_hash._KEY_IDS.clear()
    yield
    ds.K = {}
    ds.used_keys = {}
    ds.current = {}
    ds.trustee_path_lens = {}
    st.keylist = {}
    st.cl_s = []


def _setup(d, n, cl):
    # run ShardSetup then call TrusteeSetup for every trustee that was created
    cpk, crvs, trustee_init = st.ShardSetup(d, n, cl)
    for t, info in trustee_init.items():
        st.TrusteeSetup(t, info["seed"], info["allowed_keyids"], info["path_lens"])
    return cpk, crvs


# basic sign and verify works end to end
def test_sign_and_verify():
    d, n = 2, 2
    cl = [[1, 2], [1, 2]]
    cpk, crvs = _setup(d, n, cl)

    r, path, z = st.AggregatorSign(b"hello world", crvs, 0)
    assert st.AggregatorVerify(b"hello world", r, path, z) == True


# if we verify with a different message it should fail
def test_wrong_message_fails():
    d, n = 2, 2
    cl = [[1, 2], [1, 2]]
    cpk, crvs = _setup(d, n, cl)

    r, path, z = st.AggregatorSign(b"real message", crvs, 0)
    assert st.AggregatorVerify(b"wrong message", r, path, z) == False


# every keyID in the tree should be signable once
def test_all_keyids_can_sign():
    d, n = 4, 3
    cl = [[1, 2, 3]] * d
    cpk, crvs = _setup(d, n, cl)

    for kid in range(d):
        result = st.AggregatorSign(b"test message", crvs, kid)
        assert result is not None
        r, path, z = result
        assert st.AggregatorVerify(b"test message", r, path, z) == True


# signatures for different keyIDs should be different
def test_signatures_are_unique():
    d, n = 2, 2
    cl = [[1, 2], [1, 2]]
    cpk, crvs = _setup(d, n, cl)

    r0, _, z0 = st.AggregatorSign(b"msg one", crvs, 0)
    r1, _, z1 = st.AggregatorSign(b"msg two", crvs, 1)
    assert r0 != r1
    assert z0 != z1


# tamper with the z values and verify should fail
def test_tampered_z_fails():
    d, n = 2, 2
    cl = [[1, 2], [1, 2]]
    cpk, crvs = _setup(d, n, cl)

    r, path, z = st.AggregatorSign(b"hello", crvs, 0)
    bad_z = [os.urandom(len(z[0]))] + z[1:]
    assert st.AggregatorVerify(b"hello", r, path, bad_z) == False


# if r is wrong the hash won't match so verify should fail
def test_wrong_r_fails():
    d, n = 2, 2
    cl = [[1, 2], [1, 2]]
    cpk, crvs = _setup(d, n, cl)

    _, path, z = st.AggregatorSign(b"hello", crvs, 0)
    wrong_r = os.urandom(len(r) if False else 16)  # N_BYTES = 16
    assert st.AggregatorVerify(b"hello", wrong_r, path, z) == False


# reusing the same keyID a second time should return None (one-time key)
def test_cannot_reuse_keyid():
    d, n = 2, 2
    cl = [[1, 2], [1, 2]]
    cpk, crvs = _setup(d, n, cl)

    assert st.AggregatorSign(b"first", crvs, 0) is not None
    assert st.AggregatorSign(b"second", crvs, 0) is None


# a bad CHK value in round 2 should cause the aggregator to abort
def test_bad_chk_aborts_signing():
    d, n = 2, 2
    cl = [[1, 2], [1, 2]]
    cpk, crvs = _setup(d, n, cl)

    # corrupt all CHK entries for keyID 0
    crvs[0].CHK = {t: os.urandom(16) for t in crvs[0].CHK}
    assert st.AggregatorSign(b"msg", crvs, 0) is None


# with a single trustee the protocol should still work
def test_single_trustee():
    d, n = 2, 1
    cl = [[1], [1]]
    cpk, crvs = _setup(d, n, cl)

    r, path, z = st.AggregatorSign(b"solo trustee", crvs, 0)
    assert st.AggregatorVerify(b"solo trustee", r, path, z) == True


# out of range keyID should return None
def test_invalid_keyid_returns_none():
    d, n = 2, 2
    cl = [[1, 2], [1, 2]]
    cpk, crvs = _setup(d, n, cl)

    assert st.AggregatorSign(b"msg", crvs, 99) is None
