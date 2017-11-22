#!/usr/bin/env python
from __future__ import print_function
"""A few simple math utilities to support
bulletproof calculations; also ECC NUMS generators
using the jmbitcoin bitcoin/secp256k1 library.
"""
import hashlib
from jmbitcoin import (getG, encode, decode, N, multiply, add_pubkeys,
                       podle_PublicKey)

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

def inner_product(a, b, vtype="bin"):
    assert len(a) == len(b)
    assert isinstance(a, list)
    assert isinstance(b, list)
    c = 0
    for i in range(len(a)):
        if vtype == "bin":
            c += decode(a[i], 256) * decode(b[i], 256)
        else:
            c += a[i] * b[i]
        c = c % N
    if vtype == "bin":
        c = encode(c, 256, 32)
    return c

def halves(vec):
    assert len(vec) % 2 == 0
    return (vec[:len(vec)/2], vec[len(vec)/2:])

#wrapper code for ECC operations
def ecmult(scalar, point, usehex, rawpub=True, return_serialized=True):
    if isinstance(scalar, (int, long)):
        scalar = encode(scalar, 256, minlen=32)
    if decode(scalar, 256) == 0:
        return None
    return multiply(scalar, point, usehex, rawpub=rawpub,
                    return_serialized=return_serialized)

def ecadd_pubkeys(pubkeys, usehex):
    pubkeys = filter(None, pubkeys)
    if len(pubkeys) == 1:
        return pubkeys[0]
    return add_pubkeys(pubkeys, usehex)

def getNUMS(index=0):
    """Taking secp256k1's G as a seed,
    either in compressed or uncompressed form,
    append "index" as a byte, and append a second byte "counter"
    try to create a new NUMS base point from the sha256 of that
    bytestring. Loop counter and alternate compressed/uncompressed
    until finding a valid curve point. The first such point is
    considered as "the" NUMS base point alternative for this index value.

    The search process is of course deterministic/repeatable, so
    it's fine to just store a list of all the correct values for
    each index, but for transparency left in code for initialization
    by any user.
    
    The NUMS generator generated is returned as a secp256k1.PublicKey.
    """

    assert index in range(256)
    nums_point = None
    for G in [getG(True), getG(False)]:
        seed = G + chr(index)
        for counter in range(256):
            seed_c = seed + chr(counter)
            hashed_seed = hashlib.sha256(seed_c).digest()
            #Every x-coord on the curve has two y-values, encoded
            #in compressed form with 02/03 parity byte. We just
            #choose the former.
            claimed_point = "\x02" + hashed_seed
            try:
                nums_point = podle_PublicKey(claimed_point)
                return nums_point
            except:
                continue
    assert False, "It seems inconceivable, doesn't it?"

class Vector(object):
    """A vector with elements in Zn; here n is set as 'size'
    in constructor. Optionally constructable from a value v, as integer,
    converted into a bitvector; this is triggered by setting the bitlength
    variable, which controls the length of the bitvector.
    """
    def __str__(self):
        return ",".join([str(x) for x in self.v])

    def __init__(self, v, bitlength=None, size=N):
        self.size = size
        if bitlength:
            assert isinstance(v, (int, long))
            assert v >= 0
            self.bitstring = bin(v)[2:]
            self.v = [int(x) for x in self.bitstring]
            if bitlength:
                assert bitlength >= len(self.v)
                self.v = [0]*(bitlength - len(self.v)) + self.v
                self.bitstring = "0" * (bitlength - len(self.v)) + self.bitstring
            self.v = self.v[::-1]
        else:
            #Some sanity checking here would be appropriate.
            self.v = v
        self.length = len(self.v)

    def subtract(self, v):
        if isinstance(v, Vector):
            v = v.v
        newv = [(self.v[x] - v[x]) % self.size for x in range(self.length)]
        return Vector(newv, size=self.size)

    def add(self, v):
        if isinstance(v, Vector):
            v = v.v
        newv = [(self.v[x] + v[x]) % self.size for x in range(self.length)]
        return Vector(newv, size=self.size)

    def hadamard(self, v):
        #hadamard is the vector whose elements are the pairwise product of
        #the two input vectors
        if isinstance(v, Vector):
            v = v.v
        newv = [(self.v[x] * v[x]) % self.size for x in range(self.length)]
        return Vector(newv, size=self.size)

    def scalar_mult(self, k):
        newv = [(k * self.v[x]) % self.size for x in range(self.length)]
        return Vector(newv, size=self.size)

    def inner_product(self, v):
        if isinstance(v, Vector):
            v = v.v
        return sum([(v[x] * self.v[x]) % self.size for x in range(self.length)]) % self.size

class PowerVector(Vector):
    """A vector constructed from powers of a scalar, e.g.
    v = y*^n = (y^0, y^1, ... , y^(n-1))
    """
    def __init__(self, val, length, size=N):
        self.size = size
        self.v = [pow(val, k, self.size) for k in range(length)]
        self.length = len(self.v)