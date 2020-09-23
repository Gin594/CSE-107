import json
import sys, os, itertools

sys.path.append(os.path.abspath(os.path.join('..')))
from playcrypt.tools import *
from playcrypt.new_tools import *
from playcrypt.primitives import *

from playcrypt.games.game_bind import GameBIND
from playcrypt.simulator.bind_sim import BINDSim

from playcrypt.games.game_hide import GameHIDE
from playcrypt.simulator.hide_sim import HIDESim


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
Problem 2 [100 points]
Let p be a prime of bit length k >= 8 such that (p - 1)/2 is also prime. Let g,
h be two different generators of the group G = Z_p^*. Let CS= (P, C, V) be the
commitment scheme whose consituent algorithms are as follows, where the message
M is in Z_{p-1}:
"""

def P():
    pi = (g, h)
    return pi

def C(pi, M):
    """
    :param pi: Public parameters
    :param M: The message to be commited, element of Z_{p-1}
    :return: return the commital and decommital key
    """
    (g, h) = pi
    K = random_Z_N(p-1)
    A = MOD_EXP(g, K, p)
    B = MOD_EXP(h, M, p)
    C_1 = MOD(A*B, p)
    C_2 = MOD(M+K, p-1)
    return ((C_1, C_2), K)

def V(pi, C, M, K):
    """
    :param pi: Public parameters
    :param C: The commital
    :param M: The message to be verified
    :param K: The decommital key
    :return: return 1 if the opening is valid and 0 otherwise
    """
    (g, h) = pi
    (C_1, C_2) = C
    if not 0 <= K < p-1 or not 0 <= M < p-1:
        return 0
    A = MOD_EXP(g, K, p)
    B = MOD_EXP(h, M, p)
    C_1_prime = MOD(A*B, p)
    C_2_prime = MOD(M+K, p-1)
    if (C_1 == C_1_prime) and (C_2 == C_2_prime):
        return 1
    else:
        return 0

"""
1. [50 points] Specify an O(k^3)-time adversary A1 making one query to its LR oracle and
achieving Adv^{hide}_CS(A1) = 1.
"""

def A1(lr, pi):
    """
    You must fill in this method. This is the adversary that the problem is
    asking for. It should return 0 or 1.

    :param lr: The oracle supplied by game HIDE
    :param pi: The public parameter pi
    """
    g, h = pi
    M = 0

    C = lr(M, h)

    if MOD_EXP(g, C[1], p) == C[0]:
        return 0
    else:
        return 1


"""
2. [50 points] Specify an O(k)-time adversary A2 such that Adv^{bind}_CS(A2) = 1.
(Hint: What is the value of g^{(p-1)/2} mod p, and why?)
"""

def A2(pi):
    """
    You must fill in this method. This is the adversary that the problem is
    asking for. It should return tuple (C, M_0, M_1, K_0, K_1).

    :param pi: The public parameter pi
    """
    pass


if __name__ == '__main__':

    # Sample random parameters
    k = 12
    print('Sampling random parameters of bit length k = %d' % k)
    p = random.randint(2**(k - 1), 2**k)
    while not is_prime(p) or not is_prime((p-1)//2):
        p = random.randint(2**(k - 1), 2**k)
    g = random_Z_N_star(p)
    while (MOD_EXP(g, (p-1)//2, p) == 1) or (MOD_EXP(g, 2, p) == 1):
        g = random_Z_N_star(p)
    h = random_Z_N_star(p)
    while (h == g) or (MOD_EXP(h, (p-1)//2, p) == 1) or (MOD_EXP(h, 2, p) == 1):
        h = random_Z_N_star(p)
    print('p = %d, g = %d, h = %d' % (p, g, h))

    game_hide = GameHIDE(P, C)
    sim_hide = HIDESim(game_hide, A1)

    game_bind = GameBIND(P, V)
    sim_bind = BINDSim(game_bind, A2)

    print("The advantage of your adversary A1 is approx. " + str(sim_hide.compute_advantage()))
    print("The advantage of your adversary A2 is approx. " + str(sim_bind.compute_advantage()))
