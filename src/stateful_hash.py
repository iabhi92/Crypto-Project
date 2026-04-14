from utils import CPK, CSK, PATH, randomBits, w

from lamport import Gen, Verify, WINTER
from merkle_tree import MT_Contruct, MT_Verify, MT_MakePath, MT_Extract
from hash import hash_tweak

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
            pk[keyID], sk[keyID] = Gen(keyID)
            keyID += 1

        cpk = CPK()
        csk = []

        cpk.ROOT = MT_Contruct(pk[0:d])
        csk = sk[0:d]

        return (cpk, csk)
    

    # This is stateful and it needs access to csk and the keyIDs
    def StatefulSign(self, keyID: int, m: bytes) -> tuple[int, PATH, list[list]]:
        if keyID in self.keyIDs:
            # keyID has already been used
            if self.keyIDs[keyID]:
                return None
            else:
                self.keyIDs[keyID] = True

        # This will generate n random bits
        # See the n variable in utils.py 
        r = randomBits()

        # Convert the random number to raw bytes
        h = hash_lms((1, keyID), bytes(r), m)

        z = WINTER(h, self.csk[keyID])

        # Page 8 of paper to compute pk from sk
        pk = []
        for index in range(0, len(self.keyIDs)):
            pk.append(self.csk[index][pow(2, w) - 1])

        path = MT_MakePath(pk, keyID)
        
        return (r, path, z)

    # This is stateful and it needs access to cpk
    def StatefulVerify(self, m: bytes, r: int, path: PATH, z) -> bool:
        # See page 12 to get keyID from the path
        keyID = MT_Extract(path)

        # Convert the random number to raw bytes
        h = hash_lms((1, keyID), bytes(r), m)

        pk_prime = Verify(r, z, m, keyID)

        if MT_Verify(path, pk_prime) == self.cpk.ROOT:
            return True
        else:
            return False