import pytest

from stateful_hash import StatefulGen, StatefulSign, StatefulVerify, keyIDs
from merkle_tree import MT_Extract

D_SIZE = 4

@pytest.fixture
def stateful_hash():
    StatefulGen(D_SIZE)


@pytest.mark.parametrize(
    "m_1,m_2",
    [
        (b"hello", b"hello"),
        (b"hello", b"goodbye")
    ]
)
def test_stateful_sign(m_1, m_2, stateful_hash):
    r_1, path_1, z_1 = StatefulSign(1, m_1)
    result = StatefulSign(1, m_2)

    # If the same key is used to sign twice empty triple should be returned
    assert(result == ())

    r_2, path_2, z_2 = StatefulSign(2, m_2)

    assert(MT_Extract(path_1) != MT_Extract(path_2))
    assert(path_1 != path_2)


@pytest.mark.parametrize(
    "m_1,m_2",
    [
        (b"hello", b"goodbye")
    ]
)
def test_stateful_verify(m_1, m_2, stateful_hash):
    r_1, path_1, z_1 = StatefulSign(1, m_1)

    # In practice a key is only used to sign one message, only doing this here
    # to allow the same key to sign 2 messages for testing purposes
    keyIDs[1] = False

    r_2, path_2, z_2 = StatefulSign(1, m_2)

    assert(r_1 != r_2)
    assert(path_1 == path_2)
    assert(z_1 != z_2)

    assert(StatefulVerify(m_1, r_1, path_1, z_1) == True)
    assert(StatefulVerify(m_1, r_2, path_2, z_2) == False)

    assert(StatefulVerify(m_2, r_2, path_2, z_2) == True)
    assert(StatefulVerify(m_2, r_1, path_1, z_1) == False)

