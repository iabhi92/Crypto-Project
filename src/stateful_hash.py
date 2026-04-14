from utils import CPK, CSK, PATH, randomBits, w

from lamport import Gen, Verify, WINTER
from merkle_tree import MT_Contruct, MT_Verify, MT_MakePath, MT_Extract

class StatefulHash():
    csk: CSK = None
    cpk: CPK = None
    
    # This is a dict of the keyIDs where each can be true or false to mark if they are used or not
    # Example {1 : True, 2: False}
    KeyIDs: dict[int, bool] = {}

    def __init__(self, csk: CSK, cpk: CPK, KeyIDs: dict[int, bool]):
        self.csk = csk
        self.cpk = cpk
        self.KeyIDs = KeyIDs

    # This is stateless so doesn't need access the the class variables
    def StatefulGen(D: int) -> tuple[CPK, CSK]:
        PK = []
        SK = []
        
        KeyID = 0

        while KeyID < D: 
            PK[KeyID], SK[KeyID] = Gen(KeyID)
            KeyID += 1

        cpk = CPK()
        csk = []

        cpk.ROOT = MT_Contruct(PK[0:D])
        csk = SK[0:D]

        return (cpk, csk)
    

    # This is stateful and it needs access to csk and the KeyIDs
    def StatefulSign(self, KeyID: int, M, csk: CSK) -> tuple[int, PATH, list[list]]:
        if KeyID in self.KeyIDs:
            # KeyID has already been used
            if self.KeyIDs[KeyID]:
                return None
            else:
                self.KeyIDs[KeyID] = True

        # This will generate n random bits
        # See the n variable in utils.py 
        R = randomBits()

        # TODO: LMS or XMSS hash
        # This also needs metadata, 1 and KeyID
        h = hash(R, M)

        Z = WINTER(h, csk[KeyID])

        # Page 8 of paper to compute pk from sk
        PK = []
        for index in range(0, len(self.KeyIDs)):
            PK.append(csk[index][pow(2, w) - 1])

        path = MT_MakePath(PK, KeyID)
        
        return (R, path, Z)

    # This is stateful and it needs access to cpk
    def StatefulVerify(self, M, R: int, path: PATH, Z) -> bool:
        # TODO: LMS or XMSS hash
        # This also needs metadata, 1 and KeyID
        h = hash(R, M)

        # See page 12 to get KeyID from the path
        PK_Prime = Verify(R, Z, M, MT_Extract(path))

        if MT_Verify(path, PK_Prime) == self.cpk.ROOT:
            return True
        else:
            return False