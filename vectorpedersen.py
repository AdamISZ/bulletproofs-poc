#!/usr/bin/env python
from __future__ import print_function
import os
import hashlib
import json
import binascii

from jmbitcoin import (getG, encode, decode, N, podle_PublicKey, podle_PrivateKey)

from utils import ecmult, ecadd_pubkeys, getNUMS

class PC(object):
    """A simple pedersen commitment to a single scalar value
    """
    def __init__(self, v, g=None, h=None, blinding=None):
        self.v = v
        self.g = getG(True) if not g else g
        self.h = getNUMS(255).serialize() if not h else h
        self.set_blinding(blinding)
        self.get_commitment()

    def set_blinding(self, blinding=None):
        self.blinding = blinding if blinding else os.urandom(32)

    def get_commitment(self):
        self.C = ecmult(self.blinding, self.h, False)
        self.C = ecadd_pubkeys([self.C, ecmult(self.v, self.g, False)], False)
        return self.C
    def serialize(self):
        return "\n".join([binascii.hexlify(x) for x in [self.v, self.g, self.blinding, self.h]])

class VPC(object):
    """An object to encapsulate a vector pedersen
    commitment to 2 vectors (this is the structure used
    primarily in bulletproofs), i.e. a commitment with structure:
    P = c * U + a_1 * G_1 + a_2 * G_2 + ... + a_n * G_n +
    b_1 * H_1 + b_2 * H_2 + ... + b_n * H_n
    where:
    c is the "blinding amount" normally, or, can be the inner product
    a, b are vectors of integer values \in Z_N
    U, G1 .. GN, H1 .. HN are NUMS basepoints.
    U by default is the basepoint getNUMS(0).
    P is the single-EC point commitment created.
    """
    def __init__(self, a, b, g=None, h=None, u=None, vtype="bin"):
        assert self.is_vector(a)
        assert self.is_vector(b)
        if g:
            assert all([len(_) == len(a) for _ in [g, h]])
        self.vlen = len(a)
        assert vtype in ["bin", "int"]
        if vtype == "int":
            #Convert to binary for EC operations
            a = [encode(x%N, 256, 32) for x in a]
            b = [encode(x%N, 256, 32) for x in b]
        self.a = a
        self.b = b
        #the blinding is not initialized; it
        #will be created on-the-fly when the commitment
        #is requested, if it is not yet initialized at that point.
        #This allows subclasses to customize (specifically,
        #for the inner product case).
        self.c = None
        self.set_base_points(g, h, u)

    def is_vector(self, v):
        """Can change this later if necessary, for now,
        only accept a list but don't check types inside the list.
        """
        if not isinstance(v, list):
            return False
        return True

    def set_blinding(self, c=None):
        """The blinding value is kept as binary
        not integer since this is format is used by
        the scalar ecmult function.
        Optionally can set it explicitly, useful for
        forming homomorphic commitments.
        """
        if not c:
            if not self.c:
                self.c = os.urandom(32)
        else:
            if isinstance(c, (int, long)):
                c = encode(c, 256, minlen=32)
            self.c = c

    def set_base_points(self, g=None, h=None, u=None):
        """U is the base point used for commitment to the blinding value
        g is the vector of base points used for vector a
        h is the vector of base points used for vector b
        Acts as a pure setter for g* and h* vectors, for cases
        where we just use VPC as a commitment extractor directly.
        """
        self.U = u if u else getNUMS(0).serialize()
        if g:
            self.g = g
        else:
            self.g = []
            for i in range(self.vlen):
                self.g.append(getNUMS(i+1).serialize())
        if h:
            self.h = h
        else:
            self.h = []
            for j in range(self.vlen, 2*self.vlen):
                self.h.append(getNUMS(j+1).serialize())

    def get_commitment(self):
        """Returns:
        c * U + v_1 * G_1 + v_2 * G_2 + ... + v_n * G_n +
        w_1 * H_1 + w_2 * H_2 + ... + w_n * H_n
        """
        self.set_blinding()
        self.P = ecmult(self.c, self.U, False)
        for i, x in enumerate(self.a):
            self.P = ecadd_pubkeys([self.P, ecmult(x, self.g[i], False)], False)
        for i, x in enumerate(self.b):
            self.P = ecadd_pubkeys([self.P, ecmult(x, self.h[i], False)], False)
        return self.P


def verify_opening(commitment, r, v, w, vtype="bin"):
    """Given a previously supplied commitment commitment,
    verify that it opens correctly to rH + <v><G>
    """
    tempVPC = VPC(v, w, vtype=vtype)
    tempVPC.set_blinding(r=r)
    c = tempVPC.get_commitment()
    return c == commitment

def run_test_VPC():
    rawv = raw_input("Enter a vector cseparated: ")
    v = [int(x) for x in rawv.split(',')]
    vpc = VPC(v, vtype="int")
    print("Successfully created the pedersen commitment to: ", rawv)
    C = vpc.get_commitment()
    print("Here is the commitment: ", binascii.hexlify(C))
    rawv2 = raw_input("Test homomorphism: enter second vector: ")
    v2 = [int(x) for x in rawv2.split(',')]
    vpc2 = VPC(v2, vtype="int")
    C2 = vpc2.get_commitment()
    print("Here is the commitment for the second vector: ", binascii.hexlify(C2))
    assert len(v2) == len(v), "try again"
    sumv = [x + y for x, y in zip(v, v2)]
    print('here is sumv: ', sumv)
    newr = encode((decode(vpc.r, 256) + decode(vpc2.r, 256))%N, 256, 32)
    print("here is newr len: ", len(newr))
    sumvpc = VPC(sumv, vtype="int")
    #reset the blinding value
    sumvpc.set_blinding(r=newr)
    Csum = sumvpc.get_commitment()
    print("Here is the commitment to the sum: ", binascii.hexlify(Csum))
    print("Here is the sum of C and C2: ", binascii.hexlify(ecadd_pubkeys([C, C2], False)))
    if Csum == ecadd_pubkeys([C, C2], False):
        print("Successly verified homomorphism")
    else:
        print("Homomorphism failed to verify.")
        exit(0)
    #test out opening commitments
    if not verify_opening(C, vpc.r, v, vtype="int"):
        print("V1 did not verify")
    if not verify_opening(C2, vpc2.r, v2, vtype="int"):
        print("V2 did not verify")
    if not verify_opening(Csum, sumvpc.r, sumv, vtype="int"):
        print("Vsum did not verify")

if __name__ == "__main__":
    run_test_VPC()