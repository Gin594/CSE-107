import sys, os, itertools, json

from playcrypt.primitives import *
from playcrypt.tools import *
from playcrypt.ideal.block_cipher import *
#from random import *

"""
Problem 1 [100 points]
Let k,n>=4 be integers and let E:{0,1}^k x {0,1}^n --> {0,1}^n be a blockcipher
(with inverse E_I). Let Kg be the key-generation algorithm that returns a random 
128-bit string as the key. Let Enc be the following encryption algorithm whose
message space is the set of all strings M where |M|={mn:1<=m<=n},
meaning these are the allowed messages.

If E is a family of functions, then T_E denotes the time to compute it of its inverse.
All times are worst case.
"""

def Enc(K, M):
    """
    :param K: The key used to encrypt/decrypt the message
    :param M: The plaintext to be encrypted
    :return: return the encryption of plaintext M
    """
    
    M = split(M,n_bytes)
    R = random_string(n_bytes)
    C = [R]
    for i in range(len(M)):
        x = int_to_string((2**(i+1) - 1) << (n_bytes*8 - (i+1)))
        C.append(xor_strings(E(K,xor_strings(M[i], x)),C[i]))
    return join(C)

"""
1. [30 points] Specify a decryption algorithm Dec such that SE = (Kg,Enc,Dec)
is a symmetric encryption scheme satisfying the correct decryption condition of Slide 3.
"""

def Dec(K, C):
    """
    You must fill in this method. This is the decryption algorithm that the
    problem is asking for. We will define variables k, n, k_bytes, n_bytes,
    E, and E_I for you.

    :param K: The key used to encrypt/decrypt the message
    :param C: The ciphertext to be decrypted
    :return: return the decryption on the ciphertext c
    """
    # split C to n_bytes block ciphers
    c = split(C,n_bytes)
    # initialize plaintext with empty string
    M = ""
    # loop through the whole blocks, start at 1
    for i in range(1, len(c)):
        X = int_to_string((2**i - 1) << (n_bytes*8 - i))
        # get the xor message of the c[i] block cipher
        Y = xor_strings(c[i], c[i-1])
        # use E_I with Y to get the encrypted message and xor with X to get M[i]
        M += xor_strings(E_I(K, Y), X)
    return join(M)



"""
2. [70 points] Show that this scheme is not IND-CPA secure by presenting
a O(T_E+n)-time adversary A making one query to its LR oracle and
achieving Adv^ind-cpa_SE(A) = 1.
"""

def A(lr):
    """
    You must fill in this method. This is the adversary that the problem is
    asking for. We will define variables k, n, k_bytes, n_bytes,
    E, and E_I for you.

    :param lr: This is the oracle supplied by the game.
    :return: return 1 to indicate your adversary believes it is the right world
    and return 0 to indicate that your adversary believes it is in the left
    world.
    """    

    # generate string for right world
    M0 = int_to_string((2 - 1) << (n_bytes*8 - 1)) + int_to_string((2**2 - 1) << (n_bytes*8 - 2))
    # generate string for left world
    M1 = '\x01' * n_bytes * 2
    # call lr function
    c1 = lr(M1, M0)
    # split joined message, each blocks with length n_bytes 
    c2 = split(c1, n_bytes)
    # check which world the adversary believes
    if c2[0] == c2[2]:
        return 1
    else:
        return 0
    

from playcrypt.games.game_lr import GameLR
from playcrypt.simulator.lr_sim import LRSim

def testDecryption():
    worked = True
    for j in range(100):
        K = random_string(k_bytes)
        num_blocks = random.randrange(n_bytes*8)
        M = random_string(num_blocks*n_bytes)
        C = Enc(K, M)
        if M != Dec(K, C):
            print ("Your decryption function is incorrect.")
            worked = False
            break
    if worked:
        print ("Your decryption function appears correct.")

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
    EE = BlockCipher(k_bytes, n_bytes)
    E = EE.encrypt
    E_I = EE.decrypt
    

    g = GameLR(1, Enc, k_bytes)
    s = LRSim(g, A)

    print ("When k=128, n=128:")
    testDecryption()
    print ("The advantage of your adversary is ~" + str(s.compute_advantage()))

    k = 64
    n = 16
    k_bytes = k//8
    n_bytes = n//8
    EE = BlockCipher(k_bytes, n_bytes)
    E = EE.encrypt
    E_I = EE.decrypt
    g = GameLR(1, Enc, k_bytes)
    s = LRSim(g, A)

    print ("When k=64, n=16:")
    testDecryption()
    print ("The advantage of your adversary is ~" + str(s.compute_advantage()))
