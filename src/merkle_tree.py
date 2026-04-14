from hash import hash_lms
MERKLE_TWEAK = 3

def MT_Construct(pk_leaves):
    num_pk = len(pk_leaves)
    assert num_pk >= 1 and (num_pk & (num_pk - 1)) == 0, "D must be a power of two"

    tree = [None] * (2 * num_pk + 1)

    # Leaf nodes: tweak includes node index for per-position domain separation
    for i in range(num_pk):
        leaf_node = i + num_pk
        tree[leaf_node] = hash_lms((MERKLE_TWEAK, leaf_node), pk_leaves[i])

    # Internal nodes: tweak includes node index for per-position domain separation
    for i in range(num_pk - 1, 0, -1):
        tree[i] = hash_lms((MERKLE_TWEAK, i), tree[2 * i], tree[2 * i + 1])

    return tree

def MT_MakePath(pk_leaves, key_id):
    num_pk = len(pk_leaves)
    assert 0 <= key_id < num_pk, "key_id out of range"

    tree = MT_Construct(pk_leaves)

    path = []
    i = key_id + num_pk

    while i > 1:
        if i % 2 == 0:
            path.append(tree[i + 1])
        else:
            path.append(tree[i - 1])
        i = i // 2

    path.append(key_id)
    return path

def MT_Verify(path, leaf_value):
    key_id = MT_Extract(path)

    depth = len(path) - 1
    num_leaves = 1 << depth

    i = key_id + num_leaves
    h = hash_lms((MERKLE_TWEAK, i), leaf_value)

    for j in range(depth):
        sibling = path[j]
        parent = i // 2

        if i % 2 == 0:
            h = hash_lms((MERKLE_TWEAK, parent), h, sibling)
        else:
            h = hash_lms((MERKLE_TWEAK, parent), sibling, h)

        i = parent

    return h

def MT_Extract(path):
    return path[-1]