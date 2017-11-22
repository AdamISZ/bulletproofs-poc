#!/usr/bin/env python
from __future__ import print_function
"""Partial implementation (for learning/POC) of:
https://eprint.iacr.org/2017/1066 ("Bulletproofs").
Only single rangeproofs, not aggregated.
Only handles bitlengths that are powers of 2 up to 64.
"""
import os
import sys
import hashlib
import binascii

from jmbitcoin import (getG, encode, decode, N)

from utils import (modinv, inner_product, halves, getNUMS, Vector, PowerVector,
                   ecmult, ecadd_pubkeys)
from vectorpedersen import PC, VPC
from innerproduct import IPC

class RangeProof(object):
    def fiat_shamir(self, data, nret=2):
        """Generates nret integer challenge values from the current interaction
        (data) and the previous challenge values (self.fsstate), thus fulfilling
        the requirement of basing the challenge on the transcript of the prover-verifier
        communication up to this point.
        """
        xb = hashlib.sha256("".join([self.fsstate] + [str(_) for _ in data])).digest()
        challenges = []
        for i in range(nret):
            challenges.append(decode(xb, 256))
            xb = hashlib.sha256(xb).digest()
        self.fsstate = xb
        return challenges

    def get_blinding_vector(self):
        """Returns a vector of random elements in the group Zn,
        length of vector is the bitlength of our value to be rangeproofed.
        """
        randints = [self.get_blinding_value() for _ in range(self.bitlength)]
        return Vector(randints)

    def get_blinding_value(self):
        return decode(os.urandom(32), 256)

    def __init__(self, bitlength):
        self.fsstate = ""
        assert bitlength in [2, 4, 8, 16, 32, 64], "Bitlength must be power of 2 <= 64"
        self.bitlength = bitlength

    def generate_proof(self, value):
        """Given the value value, follow the algorithm laid out
        on p.16, 17 (section 4.2) of paper for prover side.
        """
        self.fsstate = ""
        self.value = value
        self.gamma = os.urandom(32)
        pc = PC(encode(self.value, 256, minlen=32), blinding=self.gamma)
        self.V = pc.get_commitment()
        self.aL = Vector(value, self.bitlength)
        self.aR = self.aL.subtract([1] * self.bitlength)
        assert self.aL.hadamard(self.aR).v == Vector([0]*self.bitlength).v
        assert self.aL.inner_product(PowerVector(2, self.bitlength)) == value
        self.alpha = self.get_blinding_value()
        self.A = IPC(self.aL.v, self.aR.v, vtype="int", u=getNUMS(255).serialize())
        self.A.set_blinding(c=self.alpha)
        self.A.get_commitment()
        self.rho = self.get_blinding_value()
        self.sL = self.get_blinding_vector()
        self.sR = self.get_blinding_vector()
        self.S = IPC(self.sL.v, self.sR.v, vtype="int", u=getNUMS(255).serialize())
        self.S.set_blinding(c=self.rho)
        self.S.get_commitment()
        self.y, self.z = self.fiat_shamir([self.V, self.A.P, self.S.P])
        self.z2 = (self.z * self.z) % N
        self.zv = Vector([self.z] * self.bitlength)
        #construct l(X) and r(X) coefficients; l[0] = constant term, l[1] linear term,
        #same for r(X)
        self.l = []
        self.l.append(self.aL.subtract(self.zv))
        self.l.append(self.sL)
        self.yn = PowerVector(self.y, self.bitlength)
        self.r = []
        #0th coeff is y^n o (aR + z.1^n) + z^2 . 2^n
        self.r.append(self.yn.hadamard(self.aR.add(self.zv)).add(
            PowerVector(2, self.bitlength).scalar_mult(self.z2)))
        self.r.append(self.yn.hadamard(self.sR))
        #constant term of t(X) = <l(X), r(X)> is the inner product of the
        #constant terms of l(X) and r(X)
        self.t0 = self.l[0].inner_product(self.r[0])
        self.t1 = (self.l[0].inner_product(self.r[1]) + (
            self.l[1].inner_product(self.r[0]))) % N
        self.t2 = self.l[1].inner_product(self.r[1])
        self.tau1 = self.get_blinding_value()
        self.tau2 = self.get_blinding_value()
        self.T1 = PC(self.t1, blinding=self.tau1)
        self.T2 = PC(self.t2, blinding=self.tau2)
        self.x_1 = self.fiat_shamir([self.T1.get_commitment(),
                                     self.T2.get_commitment()], nret=1)[0]
        self.mu = (self.alpha + self.rho * self.x_1) % N
        self.tau_x = (self.tau1 * self.x_1 + self.tau2 * self.x_1 * self.x_1 + \
                      self.z2 * decode(self.gamma, 256)) % N
        #lx and rx are vector-valued first degree polynomials evaluated at
        #the challenge value self.x_1
        self.lx = self.l[0].add(self.l[1].scalar_mult(self.x_1))
        self.rx = self.r[0].add(self.r[1].scalar_mult(self.x_1))
        self.t = (self.t0 + self.t1 * self.x_1 + self.t2 * self.x_1 * self.x_1) % N
        assert self.t == self.lx.inner_product(self.rx)
        #Prover will now send tau_x, mu and t to verifier, and inner product argument
        #can be verified from this data.
        self.hprime = []
        self.yinv = modinv(self.y, N)
        for i in range(1, self.bitlength + 1):
            self.hprime.append(ecmult(pow(self.yinv, i-1, N), self.A.h[i-1], False))
        self.uchallenge = self.fiat_shamir([self.tau_x, self.mu, self.t], nret=1)[0]
        self.U = ecmult(self.uchallenge, getG(True), False)
        #On the prover side, need to construct an inner product argument:
        self.iproof = IPC(self.lx.v, self.rx.v, vtype="int", h=self.hprime, u=self.U)
        self.proof = self.iproof.generate_proof()
        #At this point we have a valid data set, but here is included a
        #sanity check that the inner product proof we've generated, actually verifies:
        self.iproof2 = IPC([1]*self.bitlength, [2]*self.bitlength, vtype="int",
                           h=self.hprime, u=self.U)
        ak,bk,lk,rk = self.proof
        assert self.iproof2.verify_proof(ak, bk, self.iproof.get_commitment(), lk, rk)

    def get_proof_serialized(self):
        """Returns the serialization of the rangeproof that's been created.
        Note that all points are compressed EC points so fixed length 33 bytes
        and all scalars are fixed length 32 bytes, including the (a,b)
        components of the inner product proof. The exception is L, R which are
        arrays of EC points, length log_2(bitlength).
        So total size of proof is: 33*4 + 32*3 + (32*2 + 33*2*log_2(bitlength)).
        This agrees with the last sentence of 4.2 in the paper.
        """
        a, b, Ls, Rs = self.proof
        tau_x_ser, mu_ser, t_ser = [encode(x, 256, 32) for x in [self.tau_x, self.mu, self.t]]
        return "".join([self.A.P, self.S.P, self.T1.get_commitment(),
                        self.T2.get_commitment(), tau_x_ser, mu_ser, t_ser, a, b] + Ls + Rs)

    def deserialize_proof(self, proofstr):
        """Extract the points and scalars as per comments
        to get_proof_serialized; this is obviously dumb and
        no appropriate sanity checking; TODO
        """
        Ap = proofstr[:33]
        Sp = proofstr[33:66]
        T1p = proofstr[66:99]
        T2p = proofstr[99:132]
        #these are to be passed in as integers:
        tau_x = decode(proofstr[132:164], 256)
        mu = decode(proofstr[164:196], 256)
        t = decode(proofstr[196:228], 256)
        a = proofstr[228:260]
        b = proofstr[260:292]
        import math
        arraylen = int(math.log(self.bitlength, 2))
        ctr = 292
        Ls = []
        Rs = []
        for i in range(arraylen):
            Ls.append(proofstr[ctr:ctr+33])
            ctr += 33
        for i in range(arraylen):
            Rs.append(proofstr[ctr:ctr+33])
            ctr+=33
        return (Ap, Sp, T1p, T2p, tau_x, mu, t, (a, b, Ls, Rs))
            

    def verify(self, Ap, Sp, T1p, T2p, tau_x, mu, t, proof, V):
        """Takes as input an already-deserialized rangeproof, along
        with the pedersen commitment V to the value (not here known),
        and checks if the proof verifies.
        """
        #wipe FS state:
        self.fsstate = ""
        #compute the challenges to find y, z, x
        self.y, self.z = self.fiat_shamir([V, Ap, Sp])
        self.z2 = (self.z * self.z) % N
        self.zv = Vector([self.z] * self.bitlength)        
        self.x_1 = self.fiat_shamir([T1p, T2p], nret=1)[0]
        self.hprime = []
        self.yinv = modinv(self.y, N)
        for i in range(1, self.bitlength + 1):
            self.hprime.append(ecmult(pow(self.yinv, i-1, N),getNUMS(
                self.bitlength+i).serialize(), False))
        #construction of verification equation (61)
        onen = PowerVector(1, self.bitlength)
        twon = PowerVector(2, self.bitlength)
        yn = PowerVector(self.y, self.bitlength)
        self.k = (yn.inner_product(onen) * -self.z2) % N
        self.k = (self.k - (onen.inner_product(twon) * (pow(self.z, 3, N)))) % N
        self.gexp = (self.k + self.z * onen.inner_product(yn)) % N
        self.lhs = PC(t, blinding=tau_x).get_commitment()
        self.rhs = ecmult(self.gexp, getG(True), False)
        self.vz2 = ecmult((self.z * self.z) % N, V, False)
        self.rhs = ecadd_pubkeys([self.rhs, self.vz2], False)
        self.rhs = ecadd_pubkeys([self.rhs, ecmult(self.x_1, T1p, False)], False)
        self.rhs = ecadd_pubkeys([self.rhs, ecmult(
            (self.x_1 *self.x_1) % N, T2p, False)], False)
        if not self.lhs == self.rhs:
            print("(61) verification check failed")
            print(binascii.hexlify(self.lhs))
            print(binascii.hexlify(self.rhs))
            return False
        #reconstruct P (62)
        self.P = Ap
        self.P = ecadd_pubkeys([ecmult(self.x_1, Sp, False), self.P], False)
        #now add g*^(-z)
        for i in range(self.bitlength):
            self.P = ecadd_pubkeys([ecmult(-self.z % N, getNUMS(i+1).serialize(),
                                           False), self.P], False)
        #zynz22n is the exponent of hprime
        self.zynz22n = yn.scalar_mult(self.z).add(PowerVector(2,
                                            self.bitlength).scalar_mult(self.z2))
        for i in range(self.bitlength):
            self.P = ecadd_pubkeys([ecmult(self.zynz22n.v[i], self.hprime[i],
                                           False), self.P], False)
        self.uchallenge = self.fiat_shamir([tau_x, mu, t], nret=1)[0]
        self.U = ecmult(self.uchallenge, getG(True), False)
        self.P = ecadd_pubkeys([ecmult(t, self.U, False), self.P], False)
        #P should now be : A + xS + -zG* + (zy^n+z^2.2^n)H'* + tU
        #One can show algebraically (the working is omitted from the paper)
        #that this will be the same as an inner product commitment to
        #(lx, rx) vectors (whose inner product is t), thus the variable 'proof'
        #can be passed into the IPC verify call, which should pass.
        #input to inner product proof is P.h^-(mu)
        self.Pprime = ecadd_pubkeys([self.P, ecmult(-mu % N, getNUMS(255).serialize(),
                                                    False)], False)
        #Now we can verify the inner product proof
        a, b, L, R = proof
        #dummy vals for constructor of verifier IPC
        self.iproof = IPC(["\x01"]*self.bitlength, ["\x02"]*self.bitlength,
                          h=self.hprime, u=self.U)
        #self.iproof.P = self.Pprime
        if not self.iproof.verify_proof(a, b, self.Pprime, L, R):
            return False
        return True

def run_test_rangeproof(value, rangebits):
    print("Starting rangeproof test for value: ", value,
          " in range from 0 to 2^", rangebits)
    fail = False
    if not (0 < value and value < 2**rangebits):
        print("Value is NOT in range; we want verification to FAIL.")
        fail = True
    rp = RangeProof(rangebits)
    rp.generate_proof(value)
    proof = rp.get_proof_serialized()
    #now simulating: the serialized proof passed to the validator/receiver;
    #note that it is tacitly assumed that in the expected application (CT
    #or similar), the V value is a pedersen commitment which already exists
    #in the transaction; it's what we're validating *against*, so it's not
    #part of the proof itself. Hence we just pass rp.V into the verify call.
    print("Got rangeproof: ", binascii.hexlify(proof))
    print("Its length is: ", len(proof))
    #Note this is a new RangeProof object:
    rp2 = RangeProof(rangebits)
    A, S, T1, T2, tau_x, mu, t, iproof = rp2.deserialize_proof(proof)
    print("Now attempting to verify a proof in range: 0 -", 2**rangebits)
    if not rp2.verify(A, S, T1, T2, tau_x, mu, t, iproof, rp.V):
        if not fail:
            print('Rangeproof should have verified but is invalid; bug.')
        else:
            print("Rangeproof failed, as it should because value is not in range.")
    else:
        if not fail:
            print('Rangeproof verified correctly, as expected.')
        else:
            print("Rangeproof succeeded but it should not have, value is not in range; bug.")

if __name__ == "__main__":
    value, rangebits = [int(x) for x in sys.argv[1:3]]
    run_test_rangeproof(value, rangebits)
