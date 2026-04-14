from utils import (CPK, CSK, randomBits, w)

from lamport import Gen, Verify, WINTER
from merkle_tree import MT_Contruct, MT_Verify, MT_MakePath

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

        while KeyID <= D - 1: 
            PK[KeyID], SK[KeyID] = Gen(KeyID)
            KeyID += 1

        cpk = CPK()
        csk = []

        cpk.ROOT = MT_Contruct(PK[0:D])
        csk = SK[0:D]

        return (cpk, csk)
    

    # This is stateful and it needs access to csk and the KeyIDs
    def StatefulSign(self, KeyID: int, M, csk: CSK):
        if KeyID in self.KeyIDs:
            if self.KeyIDs[KeyID]:
                raise Exception(f"{KeyID} has already been used")
            else:
                self.KeyIDs[KeyID] = True

        R = randomBits()

        # LMS or XMSS hash
        h = hash(R, M)

        Z = WINTER(h, csk(KeyID))

        # Page 8 of paper to compute pk from sk
        PK = []
        for index in range(0, len(csk)):
            PK.append(csk[index][pow(2, w) - 1])

        PATH = MT_MakePath(PK, KeyID)
        
        return (R, PATH, Z)

    # This is stateful and it needs access to cpk
    def StatefulVerify(self, M, R, PATH, Z) -> bool:
        h = hash(R, M)

        # Not sure where KeyID comes from
        PK_Prime = Verify(R, Z, M, KeyID)

        # Not sure where cpk comes from
        if MT_Verify(PATH, PK_Prime) == self.cpk.ROOT:
            return True
        else:
            return False

