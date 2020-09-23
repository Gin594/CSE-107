import json
import sys, os, itertools

sys.path.append(os.path.abspath(os.path.join('..')))
from playcrypt.tools import *
from playcrypt.new_tools import *
from playcrypt.primitives import *

from playcrypt.games.game_sufcma_sign import GameSUFCMASign
from playcrypt.simulator.sufcma_sign_sim import SUFCMASignSim

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

Problem 1 [50 points]
Let DS = (K, S, V) be a digital signature scheme and consider the game SUF-CMA as
defined in playcrypt file "games/game_ufcma_sign.py". The suf-cma advantage of an
adversary A is defined by Adv^{suf-cma}_{DS}(A) = Pr[SUF-CMA^{A}_{DS} => true].

Let H be a function such that H(N, M) \in Z_N^* for all integers N >= 2 and
all M \in {0,1}^*. Let K_rsa be a RSA generator with security parameter k >= 8.
Let DS = (K, S, V) be the signature scheme whose component algorithms are as follows:
"""

def K():
    (N, p, q, e, d) = K_rsa(k)
    pk = (N, e)
    sk = (N, d)
    return (pk, sk)

def S(sk, M):
    """
    :param sk: The secret key sk = (N, d) used to sign messages
    :param M: The message to be signed, can be an arbitrary string
    :return: return the signature of message M
    """
    (N, d) = sk
    U = 1
    while U == 1:
        U = random_Z_N_star(N) # U != 1
    V = MOD_INV(U, N)
    W = MOD_EXP(V, d, N) # W = U^{-d} mod N
    X = MOD_EXP(H(N, M), d, N)
    Y = (U * X) % N # Y = (U * H(N,M)^d) mod N
    return (W, Y)

def V(pk, M, sig):
    """
    :param pk: The public key pk = (N, e) used to verify messages
    :param M: The message to be verified, can be an arbitrary string
    :param s: The signature to be verified
    :return: return 1 if the signature is valid and 0 otherwise
    """
    (N, e) = pk
    (W, Y) = sig
    if not in_Z_N_star(W, N) or not in_Z_N_star(Y, N):
        return 0
    if W == 1:
        return 0
    V = MOD_EXP(W, e, N)
    h = MOD_EXP((V * Y) % N, e, N)
    if h == H(N, M):
        return 1
    else:
        return 0

"""
Specify in pseudocode an O(k^3)-time adversary A making one Sign query to
achieve Adv^{suf-cma}_{DS}(A) = 1.
"""

def A(pk, Sign):
    N = pk[0]
    e = pk[1]
    M = random.randint(0, 100)

    S = Sign(M)
    s1 = S[0]
    s2 = S[1]
    V = MOD_EXP(s1, e, N)
    U = MOD_INV(V, N)

    W = MOD(s1*s1, N)
    Y = MOD(s2*U, N)
    sig = (W, Y)

    return M, sig
# WARNING: H can be any function satisfying the requirements in the problem statement.
# Your adversaries should work for any valid function H, not just for "sampleHashFunction".
# We will define and use multiple different functions H for testing your solutions.
hmap = {}
def sampleHashFunction(N, M):
    if (N, M) not in hmap:
        hmap[(N, M)] = random_Z_N_star(N)
    return hmap[(N, M)]

if __name__ == '__main__':
    # WARNING: H can be any function satisfying the requirements in the problem statement.
    # Your adversaries should work for any valid function H, not just for "sampleHashFunction".
    # We will define and use multiple different functions H for testing your solutions.
    H = sampleHashFunction

    k = 128
    g = GameSUFCMASign(S, V, None, K)
    s = SUFCMASignSim(g, A)

    print("The advantage of your adversary is approx. " + str(s.compute_advantage()))
