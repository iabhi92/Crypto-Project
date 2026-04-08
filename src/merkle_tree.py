from helpers import hash_tweak
MERKLE_TWEAK = 3

"""
    Build a complete binary Merkle tree from D = 2^d one-time public keys.
    Parameters
    pk_leaves : list of D byte-strings

    Returns
    P : list of length 2D+1 where P[1] is the root and P[i+D] = hash(PK[i]).
        Index 0 is unused.
"""
def MT_Construct(pk_leaves):
    num_pk = len(pk_leaves)
    assert num_pk >= 1 and (num_pk & (num_pk - 1)) == 0, "D must be a power of two"
 
    # index 0 unused, following paper's 1-based indexing
    tree = [None] * (2 * num_pk + 1)
 
    # Leaf nodes 
    for i in range(num_pk):
        leaf_node = i + num_pk
        tree[leaf_node] = hash_tweak(MERKLE_TWEAK, pk_leaves[i])
 
    # Internal nodes
    for i in range(num_pk - 1, 0, -1):
        tree[i] = hash_tweak(MERKLE_TWEAK, tree[2 * i], tree[2 * i + 1])
 
    return tree

"""
    Compute the authentication PATH for the leaf at position key_id.
    Parameters
    pk_leaves : full list of D one-time public keys
    key_id : index of the leaf whose path is to be computed (0 <= key_id < D)

    Returns
    path : list of siblings from leaf up to and not including root + key_id [sibling_1, sibling_2, ..., sibling_d, key_id]
            where sibling_1 is the sibling closest to the leaf.
"""
def MT_MakePath(pk_leaves, key_id):
    num_pk = len(pk_leaves)
    assert 0 <= key_id < num_pk, "key_id out of range"
 
    tree = MT_Construct(pk_leaves)
 
    path = []
    i = key_id + num_pk
 
    # Tweaked paper condition to i > 1 to correctly get siblings from root to leaf
    while i > 1:
        if i % 2 == 0:
            # i is the left child, store its right sibling (i+1)
            path.append(tree[i + 1])
        else:
            # i is a right child, stores its left sibling (i-1)
            path.append(tree[i - 1])

        # Tree property: Moves up a level
        i = i // 2
 
    path.append(key_id)
    return path

"""
    Recompute the Merkle root from a leaf value and its PATH.
 
    Parameters
    path : PATH as returned by MT_MakePath
    leaf_value : the one-time public key being verified (PK[key_id])
 
    Returns
    root : the recomputed root hash.
           Verification succeeds iff this equals the stored CPK.ROOT.
"""
def MT_Verify(path, leaf_value):
    key_id = MT_Extract(path)
 
    # PATH has d sibling entries + 1 KeyID entry
    depth = len(path) - 1
    num_leaves = 1 << depth
 
    i = key_id + num_leaves
    h = hash_tweak(MERKLE_TWEAK, leaf_value)
 
    for j in range(depth):
        sibling = path[j]
 
        if i % 2 == 0:
            # i is a left child: hash(current, sibling)
            h = hash_tweak(MERKLE_TWEAK, h, sibling)
        else:
            # i is a right child: hash(sibling, current)
            h = hash_tweak(MERKLE_TWEAK, sibling, h)
 
        i = i // 2
 
    return h

"""
    Returns the key_id stored as the last element of path.
    Parameter
    path : list of siblings from leaf up to and not including root + key_id [sibling_1, sibling_2, ..., sibling_d, key_id]
        where sibling_1 is the sibling closest to the leaf.

    Return
    key_id : index of the leaf corresponding to the path generated
"""
def MT_Extract(path):
    return path[-1]