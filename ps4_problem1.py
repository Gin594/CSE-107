import sys, os, itertools, json

from playcrypt.games.game_cr import GameCR
from playcrypt.simulator.cr_sim import CRSim
from playcrypt.ideal.block_cipher import BlockCipher
from playcrypt.primitives import *
from playcrypt.tools import *

"""
Let E: {0,1}^n x {0,1}^n -> {0,1}^n be a block cipher (with inverse E_I) and let
T_E denote the time to compute E or E_I. Define the family of functions
H: {0,1}^n x {0,1}^{2n} -> {0,1}^n as follows:
"""

def H(K, M):
    """
    Hash function.

    :param K: Key used by the hash function, must be of size n_bytes
    :param M: Message hashed by the function, must be of length 2 * n_bytes
    """
    if (len(M) % n_bytes != 0) and (len(M) // n_bytes != 2):
        raise ValueError("Input length is outside of parameters.")

    M = split(M, n_bytes)
    L0 = K
    L1 = E(L0,M[0])
    L2 = E(L1,M[1])

    return L2

"""
[100 points] Show that H is not collision resistant by presenting an O(T_E + l)
time adversary A with Adv^cr_H(A)=1.
"""

def A(K):
    """
    You must fill in this method. We will define variables n, n_bytes, 
    E, and E_I for you.

    :param K: This is the key used as the seed to the provided hash function
    :return: Return 2 messages, M1 and M2, that your adversary believes collide
    """
    # initialize n_bytes string of all zero
    zero = "\x00" * n_bytes
    # initialize n_bytes string of all one
    one  = "\x01" * n_bytes
    # create first message
    M1 = [zero, one] 
    # get the hash value from the first message
    C = E(E(K, M1[0]), M1[1])
    # create the second message that will collide with first message
    M2 = [one, E_I(E(K, one), C)]

    return (join(M1), join(M2))
    
"""
==============================================================================================
The following lines are used to test your code, and should not be modified.
==============================================================================================
"""
if __name__ == '__main__':
    # Case 1: n = 128
    n = 128
    n_bytes = n//8
    EE = BlockCipher(n_bytes, n_bytes)
    E = EE.encrypt
    E_I = EE.decrypt

    g = GameCR(H, n_bytes)
    s = CRSim(g, A)

    print ("\nWhen n=128:")
    print ("The advantage of your adversary is ~" + str(s.compute_advantage()))


    # Case 2: n = 64
    n = 64
    n_bytes = n//8
    EE = BlockCipher(n_bytes, n_bytes)
    E = EE.encrypt
    E_I = EE.decrypt

    g = GameCR(H, n_bytes)
    s = CRSim(g, A)

    print ("\nWhen n=64:")
    print ("The advantage of your adversary is ~" + str(s.compute_advantage()))