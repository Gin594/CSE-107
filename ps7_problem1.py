import math
import json
import sys, os, itertools

from playcrypt.primitives import *
from playcrypt.tools import *
from playcrypt.new_tools import *

from playcrypt.games.game_pke_lr import GamePKELR
from playcrypt.simulator.pke_lr_sim import PKELRSim

def ADD(a,b):
    return a+b
def MULT(a,b):
    return a*b
def INT_DIV(a,N):
    return (a//N, a%N)
def MOD(a,N):
    return a%N
def EXT_GCD(a,N):
    return egcd(a,N)
def MOD_INV(a,N):
    res = modinv(a,N)
    if res == None:
        raise ValueError("Inverse does not exist.")
    return res
def MOD_EXP(a,n,N):
    return exp(a,n,N)

"""
Note: As usual, our convention is that the running time of an adversary does not
include the time taken by game procedures to compute responses to adversary's queries.
"""
"""
1. [100 points] Let r >= 8 be an even integer. Let H be a hash function such that 
H(N, R) \in Z_N^* for all integers N >= 2 and all R \in {0, 1}^r. Let K_rsa be an RSA
generator with security parameter k > r, and assume i + 1 \in Z_N^* for all i =
1, ..., 2^{r/2} and all (N, p, q, e, d) that may be outputted by K_rsa.
Consider a key-generation algorithm K and an encryption algorithm K as defined below.
(H, k, r are known to all parties including the adversary. We will define them for you.)
"""

def K():
    (N, p, q, e, d) = K_rsa(k)
    pk = (N, e)
    sk = (N, d)
    return (pk, sk)

def E(pk, M):
    """
    :param pk: The public key pk = (N, e) used to encrypt the message
    :param M: The plaintext to be encrypted, must be in Z_N^*
    :return: return the encryption of plaintext M
    """    
    (N, e) = pk                     # Parse pk as (N, e)
    if not in_Z_N_star(M, N):       # If M is not in Z_N^* 
        raise ValueError("Message not in appropriate domain.")     
    R = random_string_as_integer(r) # Sample a uniformly random r-bit string R
    """
    We sample R as an integer such that 0 <= R < 2^r (meaning R can always be represented
    as an r-bit string). This makes it easier to work with values of r that are not multiples
    of 8 bits.
    """
    U = H(N, R)                     # U <- H(N, R) 
    V = MOD_EXP(U, e, N)            # V <- U^e mod N
    W = MOD(U * M,  N)              # W <- (U * M) mod N
    return (V, W)

"""
(a) [10 points] Specify in pseudocode an O(k^3)-time decryption algorithm D such that
AE = (K, E, D) is an asymmetric encryption scheme satisfying the correct
decryption requirement, for messages that are in Z_N^* when the public key is (N, e).
"""

def D(sk, C):
    """
    This is the decryption algorithm that the problem is asking for.
    :param sk: The secret key used to decrypt the message
    :param C: The ciphertext to be decrypted
    :return: return the decryption on the ciphertext C
    """
    # sk = N, d
    N = sk[0]
    d = sk[1]
    # get the ciphertext c1 = V, c2 = W
    c1 = C[0]
    c2 = C[1]
    # get U
    U = MOD_EXP(c1, d, N)
    # inverse of U*W % N
    c = MOD(MOD_INV(U, N)*c2, N)
    return c

    

"""
(b) [40 points] Specify in pseudocode an O(k^3)-time adversary A1 making one query to
its LR oracle and achieving Adv_{AE}^{ind-cpa}(A1) = 1. Messages in the LR query
must be in Z_N^* when the public key is (N, e).
"""

def A1(lr, pk):
    """
    You must fill in this method. This is the adversary that the problem is
    asking for. We will define variables H, k, r for you.
    :param lr: This is the oracle supplied by the game.
    :param pk: This is the public key returned by the game's procedure Initialize.
    :return: return 1 to indicate your adversary believes it is the right world
    and return 0 to indicate that your adversary believes it is in the left world.
    """

    # pk = N, e
    N = pk[0]
    e = pk[1]

    M1 = 1
    M2 = random.randint(2, N)
    # check if in the Z_N_star
    while EXT_GCD(M2, N)[0] != 1:
        M2 += 1
    
    # call function lr
    c = lr(M1, M2)
    c1 = c[0]
    c2 = c[1]

    if MOD_EXP(c2, e, N) == c1:
        return 0
    else:
        return 1

    

"""
(c) [50 points] Specify in pseudocode an O(2^{r/2} * r * k)-time adversary Ak making
at most 2^{r/2} queries to its LR oracle and achieving Adv_{AE}^{ind-cpa}(Ak) >= 1/4.
Messages in LR queries must be in Z_N^* when the public key is (N, e).
Note that the value of r can be much smaller than k. (For example: r = 8 and k = 1024).
In this case, adversary Ak will be a lot more efficient than adversary A1.
"""

def Ak(lr, pk):
    """
    You must fill in this method. This is the adversary that the problem is
    asking for. We will define variables H, k, r for you.
    :param lr: This is the oracle supplied by the game.
    :param pk: This is the public key returned by the game's procedure Initialize.
    :return: return 1 to indicate your adversary believes it is the right world
    and return 0 to indicate that your adversary believes it is in the left world.
    """
    # get N from pk
    N = pk[0]

    M1 = 1
    M2 = random.randint(2, N)
    # initialize empty set
    V = []
    W = []
    # making at most 2^{r//2} queries
    for i in range(2**(r//2)):
        while EXT_GCD(M2, N)[0] != 1:
            M2 += 1
        # call lr function
        c = lr(M1, M2)
        c1 = c[0]
        c2 = c[1]
        # check V is already in the set
        if c1 in V:
            if W[V.index(c1)] == c2:
                return 0
        V.append(c1)
        W.append(c2)
        M2 += 1
    return 1

# WARNING: H can be any function satisfying the requirements in the problem statement.
# Your adversaries should work for any valid function H, not just for "sampleHashFunction".
# We will define and use multiple different functions H for testing your solutions.
def sampleHashFunction(N, R):
    return MOD_EXP(2, R, N)

"""
==============================================================================================
The following lines are used to test your code, and should not be modified.
==============================================================================================
"""
if __name__ == '__main__':

    # WARNING: H can be any function satisfying the requirements in the problem statement.
    # Your adversaries should work for any valid function H, not just for "sampleHashFunction".
    # We will define and use multiple different functions H for testing your solutions.
    H = sampleHashFunction

    def pk_gen():
            (pk,sk) = K()
            return pk

    print("When k=64, r=48:")
    k = 64
    r = 48

    worked = True
    for j in range(100):
        (pk,sk) = K()
        (N,e) = pk
        M = random_Z_N_star(N)
        C = E(pk, M)
        if M != D(sk, C):
            print ("Your decryption function is incorrect.")
            worked = False
            break
    if worked:
        print ("Your decryption function appears correct.")

    gm = GamePKELR(1, 1, E, pk_gen)
    s = PKELRSim(gm, A1)
    print ("The advantage of your adversary A1 is approx. " + str(s.compute_advantage()))
    

    print("When k=64, r=12:")
    k = 64
    r = 12

    gm = GamePKELR(0, 2**(r/2), E, pk_gen)
    s = PKELRSim(gm, Ak)
    print ("The advantage of your adversary Ak is approx. " + str(s.compute_advantage()))
    
