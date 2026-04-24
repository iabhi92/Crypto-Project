# Tests for the PRF-based distributed signing module.
#
# Covers PRF-based KK_Setup, trustee seed-based share generation,
# round-1 and round-2 signing, aggregation into a verifiable
# Lamport/Winternitz signature, one-time key reuse rejection,
# and PRF/RF game helpers.

import os
import random
import sys
import pytest
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))
import distributed_signing as ds
from lamport import Gen, Verify
from prf_rf_game import F, PRFRFGame, Init, Query, Final
from utils import N_BYTES
import shard_trustee as st

MESSAGE = b"distributed signing test"


@pytest.fixture(autouse=True)
def reset_distributed_signing_globals():
    ds.K = {}
    ds.used_keys = {}
    ds.current = {}
    ds.trustee_path_lens = {}
    st.keylist = {}
    st.cl_s = []
    yield
    ds.K = {}
    ds.used_keys = {}
    ds.current = {}
    ds.trustee_path_lens = {}
    st.keylist = {}
    st.cl_s = []


def _trustee_seeds(k: int) -> dict[int, bytes]:
    return {t: os.urandom(N_BYTES) for t in range(1, k + 1)}


def _setup_contribs_from_seeds(seeds: dict[int, bytes], key_id: int, r: bytes, path, sk) -> dict[int, dict]:
    path_lens = [len(node) for node in path[:-1]]
    sk_shape = (len(sk), len(sk[0]))

    return {
        t: ds.KK_SetupContribution(
            seed,
            key_id,
            r,
            path_lens,
            sk_shape,
        )
        for t, seed in seeds.items()
    }


def _setup_low_level_context(key_id: int = 0, k: int = 2):
    """
    This helper manually initialises ds.K, ds.used_keys, ds.current, and
    ds.trustee_path_lens, equivalent to what TrusteeSetup does at shard level.
    """
    pk, sk = Gen(key_id)
    seeds = _trustee_seeds(k)
    r = os.urandom(N_BYTES)
    path = [os.urandom(N_BYTES), key_id]
    contribs = _setup_contribs_from_seeds(seeds, key_id, r, path, sk)
    crv = ds.KK_Setup(contribs, key_id, sk, r, path)
    for t, seed in seeds.items():
        ds.K[t] = seed
        ds.used_keys[t] = set()
        ds.current[t] = None
        ds.trustee_path_lens[t] = {key_id: crv.path_lens}

    return pk, sk, seeds, r, path, crv


def test_kk_setup_from_contributions_returns_crv_without_populating_trustee_state():
    key_id = 0
    pk, sk = Gen(key_id)
    seeds = _trustee_seeds(2)
    r = os.urandom(N_BYTES)
    path = [os.urandom(N_BYTES), key_id]
    contribs = _setup_contribs_from_seeds(seeds, key_id, r, path, sk)
    crv = ds.KK_Setup(contribs, key_id, sk, r, path)
    assert isinstance(crv.R, bytes)
    assert len(crv.R) == N_BYTES
    assert isinstance(crv.CHK, dict)
    assert sorted(crv.CHK.keys()) == [1, 2]
    assert isinstance(crv.PATH, list)
    assert crv.PATH[-1] == key_id
    assert crv.SK is not None
    assert crv.k == 2
    assert crv.trustees == [1, 2]
    assert crv.path_lens == [N_BYTES]
    assert ds.K == {}
    assert ds.used_keys == {}
    assert ds.current == {}


def test_kk_setup_accepts_r_as_int():
    key_id = 1
    _, sk = Gen(key_id)
    seeds = _trustee_seeds(1)
    r_int = int.from_bytes(os.urandom(N_BYTES), "big")
    path = [os.urandom(N_BYTES), key_id]
    contribs = _setup_contribs_from_seeds(seeds, key_id, r_int, path, sk)
    crv = ds.KK_Setup(contribs, key_id, sk, r_int, path)
    assert isinstance(crv.R, bytes)
    assert len(crv.R) == N_BYTES


def test_prf_helpers_are_deterministic_and_domain_separated():
    seed = os.urandom(N_BYTES)
    key_id = 11

    r1 = ds.PRF_R(seed, key_id, N_BYTES)
    r2 = ds.PRF_R(seed, key_id, N_BYTES)
    chk = ds.PRF_Chk(seed, key_id, N_BYTES)
    auth = ds.PRF_Auth(seed, key_id, os.urandom(N_BYTES))
    path0 = ds.PRF_Path(seed, key_id, 0, N_BYTES)
    chain = ds.PRF_Chain(seed, key_id, 1, 2, N_BYTES)

    assert r1 == r2
    assert r1 != chk
    assert r1 != path0
    assert chk != chain
    assert len(auth) == N_BYTES


def test_kk_gensig1_derives_values_from_seed():
    seed = os.urandom(N_BYTES)
    key_id = 2
    rt, chkt = ds.KK_GenSig1(seed, key_id)
    assert rt == ds.PRF_R(seed, key_id, N_BYTES)
    assert chkt == ds.PRF_Chk(seed, key_id, N_BYTES)
    assert len(rt) == N_BYTES
    assert len(chkt) == N_BYTES


def test_kk_gensig2_derives_path_and_signature_share_from_seed():
    seed = os.urandom(N_BYTES)
    key_id = 3
    path_lens = [N_BYTES, N_BYTES]
    h = os.urandom(N_BYTES)

    path_t, z_t = ds.KK_GenSig2(seed, key_id, h, path_lens)

    assert isinstance(path_t, list)
    assert len(path_t) == len(path_lens)
    assert all(len(node) == N_BYTES for node in path_t)
    assert isinstance(z_t, list)
    assert len(z_t) > 0


def test_kk_auth_true_for_prf_derived_value():
    seed = os.urandom(N_BYTES)
    key_id = 4
    r_prime = os.urandom(N_BYTES)
    chk_prime = ds.PRF_Auth(seed, key_id, r_prime)

    assert ds.KK_Auth(seed, key_id, r_prime, chk_prime) is True


def test_kk_auth_false_for_wrong_value():
    seed = os.urandom(N_BYTES)
    key_id = 4
    r_prime = os.urandom(N_BYTES)
    wrong_chk = os.urandom(N_BYTES)

    assert ds.KK_Auth(seed, key_id, r_prime, wrong_chk) is False


@pytest.mark.parametrize("k", [1, 2, 3])
def test_aggregator_sign_verifies_with_lamport(k: int):
    key_id = 7
    pk, _, _, _, original_path, crv = _setup_low_level_context(key_id=key_id, k=k)

    result = ds.KK_Aggregator_Sign(MESSAGE, crv, key_id)

    assert result is not None
    r_out, path_out, z = result
    assert path_out == original_path
    assert Verify(r_out, z, MESSAGE, key_id) == pk


def test_aggregator_sign_fails_verify_on_wrong_message():
    key_id = 8
    pk, _, _, _, _, crv = _setup_low_level_context(key_id=key_id, k=2)

    result = ds.KK_Aggregator_Sign(b"signed message", crv, key_id)

    assert result is not None
    r_out, _, z = result
    assert Verify(r_out, z, b"tampered message", key_id) != pk


def test_kk_sign1_returns_none_for_unknown_trustee():
    assert ds.KK_Sign1(99, 0, b"msg") is None


def test_kk_sign1_cannot_reuse_same_key_for_trustee():
    key_id = 0
    _setup_low_level_context(key_id=key_id, k=1)

    assert ds.KK_Sign1(1, key_id, b"first") is not None
    assert ds.KK_Sign1(1, key_id, b"second") is None


def test_kk_sign2_returns_none_without_prior_sign1():
    key_id = 0
    _, _, _, _, _, crv = _setup_low_level_context(key_id=key_id, k=1)

    assert ds.KK_Sign2(1, crv.R, crv.CHK[1]) is None


def test_kk_sign2_returns_none_when_path_lens_missing():
    key_id = 0
    _, _, _, _, _, crv = _setup_low_level_context(key_id=key_id, k=1)

    # Round 1 succeeds, but Round 2 should fail because path length info is missing.
    assert ds.KK_Sign1(1, key_id, b"hello") is not None
    ds.trustee_path_lens = {}

    assert ds.KK_Sign2(1, crv.R, crv.CHK[1]) is None


def test_kk_sign2_returns_none_when_auth_fails():
    key_id = 0
    _, _, _, _, _, crv = _setup_low_level_context(key_id=key_id, k=1)

    assert ds.KK_Sign1(1, key_id, b"hello") is not None
    bad_chk = os.urandom(N_BYTES)

    assert ds.KK_Sign2(1, crv.R, bad_chk) is None


def test_aggregator_sign_returns_none_when_round2_auth_fails():
    key_id = 0
    _, _, _, _, _, crv = _setup_low_level_context(key_id=key_id, k=1)

    # Corrupt the CHK correction value for trustee 1.
    crv.CHK[1] = os.urandom(N_BYTES)

    assert ds.KK_Aggregator_Sign(b"msg", crv, key_id) is None


def test_kk_setup_is_deterministic_for_same_inputs():
    key_id = 5
    _, sk = Gen(key_id)
    seeds = _trustee_seeds(2)
    r = os.urandom(N_BYTES)
    path = [os.urandom(N_BYTES), key_id]
    contribs = _setup_contribs_from_seeds(seeds, key_id, r, path, sk)
    crv1 = ds.KK_Setup(contribs, key_id, sk, r, path)
    contribs = _setup_contribs_from_seeds(seeds, key_id, r, path, sk)
    crv2 = ds.KK_Setup(contribs, key_id, sk, r, path)

    assert crv1.R == crv2.R
    assert crv1.CHK == crv2.CHK
    assert crv1.PATH == crv2.PATH
    assert crv1.SK == crv2.SK
    assert crv1.path_lens == crv2.path_lens


def test_xor_many_round_trip():
    a = os.urandom(N_BYTES)
    b = os.urandom(N_BYTES)
    c = os.urandom(N_BYTES)

    combined = ds._xor_many([a, b, c])
    recovered = ds._xor_many([combined, b, c])

    assert recovered == a


def test_xor_many_rejects_different_lengths():
    with pytest.raises(ValueError):
        ds._xor_many([b"abc", b"de"])


def test_f_wrong_length_raises():
    k = os.urandom(N_BYTES)
    with pytest.raises(ValueError):
        F(k, b"short")
    with pytest.raises(ValueError):
        F(b"short", os.urandom(N_BYTES))


def test_f_deterministic():
    k = os.urandom(N_BYTES)
    x = os.urandom(N_BYTES)
    assert F(k, x) == F(k, x)


def test_f_label_domain_separates():
    k = os.urandom(N_BYTES)
    x = os.urandom(N_BYTES)
    assert F(k, x, label=b"A") != F(k, x, label=b"B")


def _game_with_b(b: int) -> PRFRFGame:
    for seed in range(500):
        g = PRFRFGame()
        g.init(random.Random(seed))
        if g._b == b:
            return g
    raise RuntimeError(f"no seed found for b={b}")


def test_rf_repeats_same_output_on_same_input():
    g = _game_with_b(0)
    x = os.urandom(N_BYTES)
    y1 = g.query(x)
    y2 = g.query(x)
    assert y1 == y2


def test_prf_deterministic_under_queries():
    g = _game_with_b(1)
    x = os.urandom(N_BYTES)
    assert g.query(x) == g.query(x)


def test_final_detects_correct_bit():
    g = PRFRFGame()
    g.init(random.Random(42))
    b = g._b
    assert g.final(1 - b) is False
    g2 = PRFRFGame()
    g2.init(random.Random(42))
    assert g2._b == b
    assert g2.final(b) is True


def test_paper_style_module_functions():
    g = PRFRFGame()
    Init(g, random.Random(7))
    x = os.urandom(N_BYTES)
    y = Query(g, x)
    assert len(y) == N_BYTES
    assert isinstance(Final(g, 0) | Final(g, 1), bool)


def test_query_before_init_raises():
    g = PRFRFGame()
    with pytest.raises(RuntimeError):
        g.query(os.urandom(N_BYTES))


def test_final_invalid_guess_raises():
    g = PRFRFGame()
    g.init(random.Random(0))
    with pytest.raises(ValueError):
        g.final(2)


def _initialise_all_trustees(trustee_init, trustee_seeds):
    for t, init in trustee_init.items():
        st.TrusteeSetup(
            t,
            trustee_seeds[t],
            init["allowed_keyids"],
            init["path_lens"],
        )


def _make_contribution_provider(trustee_seeds):
    def contribution_provider(t, key_id, r, path_lens, sk_shape):
        return ds.KK_SetupContribution(
            trustee_seeds[t],
            key_id,
            r,
            path_lens,
            sk_shape,
        )

    return contribution_provider


def test_shard_trustee_full_flow_verifies():
    d = 4
    n = 3
    cl = [
        [1, 2],
        [2, 3],
        [1, 3],
        [1, 2, 3],
    ]
    trustee_seeds = _trustee_seeds(n)
    provider = _make_contribution_provider(trustee_seeds)
    cpk, crvs, trustee_init = st.ShardSetup(d, n, cl, provider)
    _initialise_all_trustees(trustee_init, trustee_seeds)
    key_id = 0
    sig = st.AggregatorSign(MESSAGE, crvs, key_id)
    assert sig is not None
    r, path, z = sig
    assert st.AggregatorVerify(MESSAGE, r, path, z) is True


def test_shard_trustee_rejects_key_reuse():
    d = 4
    n = 2
    cl = [
        [1, 2],
        [1, 2],
        [1, 2],
        [1, 2],
    ]
    trustee_seeds = _trustee_seeds(n)
    provider = _make_contribution_provider(trustee_seeds)
    cpk, crvs, trustee_init = st.ShardSetup(d, n, cl, provider)
    _initialise_all_trustees(trustee_init, trustee_seeds)
    first = st.AggregatorSign(b"first message", crvs, 0)
    second = st.AggregatorSign(b"second message", crvs, 0)
    assert first is not None
    assert second is None


def test_shard_trustee_rejects_tampered_message():
    d = 4
    n = 2
    cl = [
        [1, 2],
        [1, 2],
        [1, 2],
        [1, 2],
    ]
    trustee_seeds = _trustee_seeds(n)
    provider = _make_contribution_provider(trustee_seeds)
    _, crvs, trustee_init = st.ShardSetup(d, n, cl, provider)
    _initialise_all_trustees(trustee_init, trustee_seeds)
    sig = st.AggregatorSign(b"original message", crvs, 0)
    assert sig is not None
    r, path, z = sig
    assert st.AggregatorVerify(b"tampered message", r, path, z) is False


def test_shard_setup_does_not_return_trustee_seeds():
    d = 2
    n = 2
    cl = [
        [1, 2],
        [1, 2],
    ]
    trustee_seeds = _trustee_seeds(n)
    provider = _make_contribution_provider(trustee_seeds)
    _, _, trustee_init = st.ShardSetup(d, n, cl, provider)
    for init in trustee_init.values():
        assert "seed" not in init
        assert "allowed_keyids" in init
        assert "path_lens" in init


def test_shard_setup_uses_contribution_provider_for_coalition_members():
    d = 4
    n = 3
    cl = [
        [1, 2],
        [2, 3],
        [1, 3],
        [1, 2, 3],
    ]

    trustee_seeds = _trustee_seeds(n)
    calls = []

    def provider(t, key_id, r, path_lens, sk_shape):
        calls.append((t, key_id))
        return ds.KK_SetupContribution(
            trustee_seeds[t],
            key_id,
            r,
            path_lens,
            sk_shape,
        )

    st.ShardSetup(d, n, cl, provider)

    assert sorted(calls) == sorted([
        (1, 0), (2, 0),
        (2, 1), (3, 1),
        (1, 2), (3, 2),
        (1, 3), (2, 3), (3, 3),
    ])