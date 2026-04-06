from helpers import hash_tweak

MERKLE_TWEAK = 3

# Build a complete binary Merkle tree from D = 2^d one-time public keys.
# Parameters
# pk_leaves : list of D byte-strings

# Returns
# P : list of length 2D+1 where P[1] is the root and P[i+D] = hash(PK[i]).
#     Index 0 is unused.
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

def MT_MakePath(PK: list, KeyID: int):
    return

def MT_Verify(PATH, leaf_value):
    return

def MT_Extract(PATH):
    return