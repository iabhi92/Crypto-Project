import pytest
import hashlib
import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))
from merkle_tree import MT_Construct, MT_MakePath, MT_Verify, MT_Extract


def make_leaves(n):
    return [hashlib.sha256(i.to_bytes(4, "big")).digest() for i in range(n)]


def test_build_size():
    leaves = make_leaves(4)
    tree = MT_Construct(leaves)
    assert(len(tree) == 2 * 4 + 1)
    assert(tree[1] is not None)


def test_build_bad_n():
    with pytest.raises(AssertionError):
        MT_Construct(make_leaves(3))


def test_build_diff_root():
    leaves_a = make_leaves(4)
    leaves_b = make_leaves(4)
    leaves_b[0] = hashlib.sha256(b"other").digest()
    assert(MT_Construct(leaves_a)[1] != MT_Construct(leaves_b)[1])


def test_path_id():
    leaves = make_leaves(4)
    for kid in range(4):
        path = MT_MakePath(leaves, kid)
        assert(MT_Extract(path) == kid)


def test_path_len():
    leaves = make_leaves(4)
    path = MT_MakePath(leaves, 0)
    assert(len(path) == 3)


def test_path_bad_id():
    leaves = make_leaves(4)
    with pytest.raises(AssertionError):
        MT_MakePath(leaves, 4)


def test_verify_ok():
    leaves = make_leaves(4)
    tree = MT_Construct(leaves)
    path = MT_MakePath(leaves, 2)
    assert(MT_Verify(path, leaves[2]) == tree[1])


def test_verify_bad_leaf():
    leaves = make_leaves(4)
    tree = MT_Construct(leaves)
    path = MT_MakePath(leaves, 2)
    assert(MT_Verify(path, b"\xff" * 32) != tree[1])


def test_verify_bad_path():
    leaves = make_leaves(4)
    tree = MT_Construct(leaves)
    path = MT_MakePath(leaves, 2)
    bad = path.copy()
    bad[0] = b"bad".ljust(32, b"\x00")
    assert(MT_Verify(bad, leaves[2]) != tree[1])


def test_verify_bad_id():
    leaves = make_leaves(4)
    tree = MT_Construct(leaves)
    path = MT_MakePath(leaves, 2)
    bad = path.copy()
    bad[-1] = 3
    assert(MT_Verify(bad, leaves[2]) != tree[1])


def test_one_leaf():
    leaves = make_leaves(1)
    tree = MT_Construct(leaves)
    path = MT_MakePath(leaves, 0)
    root = MT_Verify(path, leaves[0])
    assert(MT_Extract(path) == 0)
    assert(root == tree[1])


@pytest.mark.parametrize(
    "n,kid",
    [
        (2, 0),
        (4, 1),
        (8, 7),
    ]
)
def test_verify_cases(n, kid):
    leaves = make_leaves(n)
    tree = MT_Construct(leaves)
    path = MT_MakePath(leaves, kid)
    assert(MT_Verify(path, leaves[kid]) == tree[1])