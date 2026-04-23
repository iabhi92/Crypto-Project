from utils import CPK, CSK, PATH, randomBits, N_BYTES, A, C, CHAIN_LEN

from lamport import Gen, Verify, WINTER
from merkle_tree import MT_Construct, MT_Verify, MT_MakePath, MT_Extract
from hash import hash_lms

class StatefulHash():
    csk: CSK = None
    cpk: CPK = None

    # This is a dict of the keyIDs where each can be true or false to mark if they are used or not
    # Example {1 : True, 2: False}
    keyIDs: dict[int, bool] = {}

    def __init__(self, cpk: CPK, csk: CSK, keyIDs: dict[int, bool]):
        self.csk = csk
        self.cpk = cpk
        self.keyIDs = keyIDs

    # This is stateless so doesn't need access the the class variables
    def StatefulGen(d: int) -> tuple[CPK, CSK]:
        pk = []
        sk = []

        keyID = 0

        while keyID < d:
            p, s = Gen(keyID)
            pk.append(p)
            sk.append(s)
            keyID += 1

        cpk = CPK()
        csk = []

        cpk.ROOT = MT_Construct(pk[0:d])[1]
        csk = sk[0:d]

        return (cpk, csk)


    # This is stateful and it needs access to csk and the keyIDs
    def StatefulSign(self, keyID: int, m: bytes) -> tuple[int, PATH, list[list]]:
        if keyID in self.keyIDs:
            # keyID has already been used
            if self.keyIDs[keyID]:
                return ()
            else:
                self.keyIDs[keyID] = True

        r = randomBits()
        r_bytes = r.to_bytes(N_BYTES, 'big')

        h = hash_lms((1, keyID), r_bytes, m)

        z = WINTER(h, self.csk[keyID])

        # Page 8 of paper to compute pk from sk
        pk = []
        for index in range(0, len(self.keyIDs)):
            tips = [self.csk[index][i][CHAIN_LEN - 1] for i in range(A + C)]
            pk.append(hash_lms((0, index), *tips)[:N_BYTES])

        path = MT_MakePath(pk, keyID)

        return (r, path, z)

    # This is stateful and it needs access to cpk
    def StatefulVerify(self, m: bytes, r: int, path: PATH, z) -> bool:
        # See page 12 to get keyID from the path
        keyID = MT_Extract(path)

        pk_prime = Verify(r, z, m, keyID)

        if MT_Verify(path, pk_prime) == self.cpk.ROOT:
            return True
        else:
            return False
