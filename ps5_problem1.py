import sys, os, itertools, json

from playcrypt.tools import *
from playcrypt.ideal.block_cipher import *
from playcrypt.games.game_ufcma import GameUFCMA
from playcrypt.simulator.ufcma_sim import UFCMASim

"""
Problem 1
Let E: {0, 1}^k x {0, 1)^n -> {0, 1)^n be a block cipher.
Let D = { M \in {0, 1}* : 0 < |M| < n*2^n and |M| mod n = 0}.
Let T: {0, 1}^k x D -> {0, 1}^n be defined as follows:
"""

def T(K, M):
    if len(M) <= 0 or len(M)*8 > n*(2**n) or len(M) % n_bytes != 0:
        return None

    # M[1]...M[m] <- M; M[m+1] <- <m>
    M = split(M, n_bytes)
    m = len(M)
    M = [None] + M + [int_to_string(m, n_bytes)]

    # C[0] <- 0^n
    C = ["\x00" * n_bytes]

    # For i = 1,...,m+1 do C[i] <- E(K, C[i-1] xor M[i])
    for i in range(1, m + 2):
        C += [E(K, xor_strings(C[i - 1], M[i]))]

    # T <- C[m+1]; Return T
    return C[m + 1]

"""
[50 points] Show that T is an insecure MAC by presenting a O(n) time adversary A making
at most 2 queries to its tag oracle and achieving Adv^uf-cma_T(A) = 1.
"""

def A(tag):
    """
    You must fill in this method. This is the adversary that the problem is
    asking for. Returns a (message, tag) pair.
    :param tag: This is an oracle supplied by GameUFCMA, you can call this
    oracle to get a "tag" for the data you pass into it.
    """
    # initialize n_bytes with all zero
    M1 = "\x00" * n_bytes
    # get the tag with message M1
    T1 = tag(M1)
    # create second message 
    M2 = M1 + int_to_string(1, n_bytes) + T1 
    # get the tag with message M2
    # E(K, xor(E(k, xor(0^n, M1)), int_to_string(1, n)) = T1
    # E(K, xor(E(k, xor(T1, T1))), int_to_string(3, n)) = tag(M2)
    T2 = tag(M2)
    # create the return message
    # E(k, xor(E(K, xor(0^n, M1)), int_to_string(3, n)) = T2
    # E(k, xor(E(k, xor(T2, T2))), int_to_string(3, n)) = tag(M3) which should equal to T2
    M3 = M1 + int_to_string(3, n_bytes) + T2
    return (M3, T2)


def V(K, M, t):
    if T(K, M) == t:
        return 1
    else:
        return 0
"""
==============================================================================================
The following lines are used to test your code, and should not be modified.
==============================================================================================
"""
if __name__ == '__main__':
    k = 256
    n = 128
    k_bytes = k//8
    n_bytes = n//8
    E = BlockCipher(k_bytes, n_bytes).encrypt
    g = GameUFCMA(2, T, V, k_bytes)
    s = UFCMASim(g, A)

    print ("The advantage of your adversary is ~" + str(s.compute_advantage()))