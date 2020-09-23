import sys, os, itertools, json

from playcrypt.tools import *
from playcrypt.ideal.block_cipher import *
from playcrypt.ideal.message_authentication_code import *
from playcrypt.games.game_ufcma import GameUFCMA
from playcrypt.simulator.ufcma_sim import UFCMASim
from playcrypt.games.game_lr import GameLR
from playcrypt.simulator.lr_sim import LRSim
from playcrypt.games.game_int_ctxt import GameINTCTXT
from playcrypt.simulator.ctxt_sim import CTXTSim
from playcrypt.ideal.function_family import *

"""
Problem 2

Let E : {0,1}^k x {0,1}^{2n} -> {0,1}^{2n} be a block cipher with k, n >= 128.
Let K be the key-generation algorithm that returns a random k-bit key.
Let SE = (K,Enc,Dec) be the symmetric encryption scheme with encryption and decryption algorithms as described below. 
Note that the message input to Enc is an n-bit string, and the ciphertext input to Dec is a 4n-bit string.
"""

def Enc(K,M):
    if len(M) != n_bytes : 
        return None
    
    A1 = random_string(n_bytes)
    A2 = xor_strings(M,A1)
    C = []
    C.append(E(K,( A1 + "\x00" * n_bytes )))
    C.append(E(K,( A2 + "\xFF" * n_bytes )))
    return join(C)


def Dec(K,C):
    if len(C) != 4 * n_bytes : 
        return None

    C = split(C,2 * n_bytes)
    X1 = E_I(K,C[0])              #X1 = A1 || P1 in the pseudocode
    X2 = E_I(K,C[1])              #X2 = A2 || P2 in the pseudocode
    X1 = split(X1,n_bytes)      #A1 is X1[0] ; P1 is X1[1]
    X2 = split(X2,n_bytes)      #A2 is X2[0] ; P2 is X2[1]

    if (X1[1] != "\x00" * n_bytes) or (X2[1] != "\xFF" * n_bytes) :
        return None
    
    M = xor_strings(X1[0],X2[0])
    return M


    
"""
[50 points] Show that SE is not INT-CTXT secure by presenting an O(n) time adversary A2 making two queries with Adv^int-ctxt_AE(A_2)=1 - 2^{-n}.
"""
def A2(enc):
    """You must fill in this method. We will define variables k, n, k_bytes,
    n_bytes, Enc and Dec for you.

    :param enc: This is the oracle supplied by the game.
    """
    # create arbitrary message M1 and M2
    M1 = "\x01" * n_bytes
    M2 = "\x00" * n_bytes
    # encrypt M1
    C1 = enc(M1)
    # encrypt M2
    C2 = enc(M2)
    # split C1 with 2*n length 
    C3 = split(C1, 2 * n_bytes)
    # split C2 with 2*n length 
    C4 = split(C2, 2 * n_bytes)
    # get the first half encrypted string from C1
    # and the second half encrypted string from C2
    # add those two strings together as a new message
    # which will not in the set and can through the 
    # decryption algorithm that will return a message which is not ⊥
    C = C3[0] + C4[1]
    return C
    


"""
==============================================================================================
The following lines are used to test your code, and should not be modified.
==============================================================================================
"""

if __name__ == '__main__':    
    k = 128
    n = 128
    k_bytes = k//8
    n_bytes = n//8
 
    EE = BlockCipher(k_bytes, 2*n_bytes)
    E = EE.encrypt
    E_I = EE.decrypt

    g = GameINTCTXT(2, Enc, Dec, k_bytes)
    s = CTXTSim(g, A2)

    print ("When k=128, n=128:")
    print ("The advantage of your adversary A2 is ~" + str(s.compute_advantage()))

    k = 256
    n = 128
    k_bytes = k//8
    n_bytes = n//8

    EE = BlockCipher(k_bytes, 2*n_bytes)
    E = EE.encrypt
    E_I = EE.decrypt

    g = GameINTCTXT(2, Enc, Dec, k_bytes)
    s = CTXTSim(g, A2)

    print ("When k=256, n=128:")
    print ("The advantage of your adversary A2 is ~" + str(s.compute_advantage()))
