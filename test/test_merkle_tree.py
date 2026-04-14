import pytest

from stateful_hash import StatefulHash
from merkle_tree import MT_Extract

D_SIZE = 100

@pytest.fixture
def stateful_hash():
    cpk, csk = StatefulHash.StatefulGen(D_SIZE)
    
    keyIDs = {}
    for index in range(0, D_SIZE):
        keyIDs[index] = False

    return StatefulHash(cpk, csk, keyIDs)


@pytest.mark.parametrize(
    "m_1,m_2",
    [   
        ("hello", "hello"),
        ("hello", "goodbye")
    ] 
)
# test the same key is not used twice
def test_stateful_sign(m_1, m_2, stateful_hash):
    r_1, path_1, z_1 = stateful_hash.StatefulSign(1, m_1)
    result = stateful_hash.StatefulSign(1, m_2)

    # If the same key is used to sign twice empty triple should be returned
    assert(result == ())

    r_2, path_2, z_2 = stateful_hash.StatefulSign(2, m_2)

    assert(MT_Extract(path_1) != MT_Extract(path_2))
    assert(path_1 != path_2)


@pytest.mark.parametrize(
    "m_1,m_2",
    [   
        ("hello", "hello"),
        ("hello", "goodbye")
    ] 
)
# m is the messaged the the signature is created for, M is the message the signature is checked against
def test_stateful_verify(m_1, m_2, stateful_hash):
    r_1, path_1, z_1 = stateful_hash.StatefulSign(1, m_1)
    
    # In practice a key is only used to sign one message, only doing this here  
    # to allow the same key to sign 2 messages for testing purposes
    stateful_hash.keysIDs[1] = False

    r_2, path_2, z_2 = stateful_hash.StatefulSign(1, m_2)

    assert(r_1 != r_2)
    assert(path_1 == path_2)
    assert(z_1 != z_2)

    assert(stateful_hash.StatefulVerify(m_1, r_1, path_1, z_1) == True)
    assert(stateful_hash.StatefulVerify(m_1, r_2, path_2, z_2) == False)

    assert(stateful_hash.StatefulVerify(m_2, r_2, path_2, z_2) == True)
    assert(stateful_hash.StatefulVerify(m_2, r_1, path_1, z_1) == False)