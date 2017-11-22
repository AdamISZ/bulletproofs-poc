#!/usr/bin/env python
from __future__ import print_function
"""Inner product proof calculation, using
a vector pedersen commitment in which the
"blinding" factor is the dot product.
Notation: in all comments, x* is used to
indicate x is a vector.
"""
import hashlib
import binascii

from jmbitcoin import (multiply, add_pubkeys, encode, decode, N)
from utils import (modinv, inner_product, halves, getNUMS)
from vectorpedersen import VPC

class IPC(VPC):
    """An object to encapsulate an inner product commitment,
    which has form:
    P = a* G* + b* H* + <a,b>U
    where * indicates a vector, and <,> an inner product.
    The two vectors under proof are a* and b*. G*, H* and U are
    all NUMS basepoints.
    Default value for U is mentioned in the parent class.
    """
    def fiat_shamir(self, L, R, P):
        """Generates a challenge value x from the "transcript" up to this point,
        using the previous hash, and uses the L and R values from the current
        iteration, and commitment P. Returned is the value of the challenge and its
        modular inverse, as well as the squares of those values, both as
        integers and binary strings, for convenience.
        """
        xb = hashlib.sha256("".join([self.fsstate] + [str(_) for _ in [L, R, P]])).digest()
        self.fsstate = xb
        x = decode(xb, 256) % N
        x_sq = (x * x) % N
        xinv = modinv(x, N)
        x_sq_inv = (xinv * xinv) % N
        x_sqb, xinvb, x_sq_invb = [encode(_, 256, 32) for _ in [x_sq,
                                                                xinv, x_sq_inv]]
        return (x, xb, x_sq, x_sqb, xinv, xinvb, x_sq_inv, x_sq_invb)    

    def __init__(self, a, b, vtype="bin", g=None, h=None, u=None):
        super(IPC, self).__init__(a, b, vtype=vtype, g=g, h=h, u=u)
        self.fsstate = ""
        self.get_inner_product()
        self.L = []
        self.R = []

    def get_inner_product(self):
        self.c = inner_product(self.a, self.b)
        return self.c

    def generate_proof(self, P=None):
        """Setup feed-in values to recursive proof creation.
        """
        #Make sure that the root 'P' value is set:
        if P:
            self.P = P
        else:
            self.get_commitment()
        return self.get_proof_recursive(self.a, self.b, self.P,
                                        self.g, self.h, self.vlen)

    def get_proof_recursive(self, a, b, P, g, h, n):
        """The prover starts with the full a*, b*, then recursively
        constructs the case n=1 where the proof is output in the form a', b',
        these are scalars, and c' = a' * b'. This will be checked by the verifier
        against the modified P', which the verifier can calculate independently,
        and it should satisfy P' = a'*G_1 + b'*H_1 + c'*U.
        So the prover must provide (L[], R[], a', b') as output to the verifier.
        The verifier checks against the pre-known P and c.
        """
        if n == 1:
            #return the tuple: a', b', L[], R[]
            #note total size is 2 * scalar_size + log(n) * 2 * point_size
            return (a[0], b[0], self.L, self.R)
        #Split the existing vectors into halves
        aL, aR = halves(a)
        bL, bR = halves(b)
        gL, gR = halves(g)
        hL, hR = halves(h)
        self.L.append(IPC(aL, bR, g=gR, h=hL, u=self.U).get_commitment())
        self.R.append(IPC(aR, bL, g=gL, h=hR, u=self.U).get_commitment())
        x, xb, x_sq, x_sqb, xinv, xinvb, x_sq_inv, x_sq_invb = self.fiat_shamir(
            self.L[-1], self.R[-1], P)
        #Construct change of coordinates for base points, and for vector terms
        gprime = []
        hprime = []
        aprime = []
        bprime = []
        for i in range(n/2):
            gprime.append(add_pubkeys([multiply(xinvb, g[i], False),
                                       multiply(xb, g[i+n/2], False)], False))
            hprime.append(add_pubkeys([multiply(xb, h[i], False),
                                       multiply(xinvb, h[i+n/2], False)], False))
            aprime.append(encode((x * decode(a[i],
                        256) + xinv * decode(a[i + n/2], 256)) % N, 256, 32))
            bprime.append(encode((xinv * decode(b[i],
                        256) + x * decode(b[i + n/2], 256)) % N, 256, 32))
        
        Pprime = add_pubkeys([P, multiply(x_sqb, self.L[-1], False),
                              multiply(x_sq_invb, self.R[-1], False)], False)
        return self.get_proof_recursive(aprime, bprime, Pprime, gprime, hprime, n/2)

    def verify_proof(self, a, b, P, L, R):
        """Given a proof (a, b, L, R) and the original pedersen commitment P,
        validates the proof that the commitment is to vectors a*, b* whose
        inner product is committed to (ie. validates it is of form:
        P = a*G* + b*G* + <a,b>U
        Note that this call will ignore the vectors a* and b* set in
        the constructor, so they can be dummy values as long as the length
        is correct.
        Returns True or False for verification.
        """
        self.verif_iter = 0
        self.fsstate = ""
        return self.verify_proof_recursive(P, L, R, a, b,
                                           self.g, self.h, self.vlen)

    def verify_proof_recursive(self, P, L, R, a, b, g, h, n):
        """The verifier starts with the lists of L and R values, then recursively
        constructs the case n=1 where the the verifier calculates the modified P',
        and checks it satisfies P' = a*G_1 + b*H_1 + c*U, where c = a*b
        So the prover must provide (L[], R[], a, b) as output to the verifier.
        Note here 'a' and 'b' are scalars, the final step of recursive reduction
        from the prover's original a* and b* vectors; they are passed through the
        recursion but here, unlike for the proof function, only used in the final
        step.
        """
        if n == 1:
            Pprime = IPC([a], [b], g=g, h=h, u=self.U).get_commitment()
            #print("Finished recursive verify; now comparing original P: ",
            #      binascii.hexlify(P))
            #print("..with calculated P': ", binascii.hexlify(Pprime))
            return P == Pprime
        x, xb, x_sq, x_sqb, xinv, xinvb, x_sq_inv, x_sq_invb = self.fiat_shamir(
                    L[self.verif_iter], R[self.verif_iter], P)        
        #Construct change of coordinates for base points, and for vector terms
        gprime = []
        hprime = []
        for i in range(n/2):
            gprime.append(add_pubkeys([multiply(xinvb, g[i], False),
                                       multiply(xb, g[i+n/2], False)], False))
            hprime.append(add_pubkeys([multiply(xb, h[i], False),
                                       multiply(xinvb, h[i+n/2], False)], False))
        
        Pprime = add_pubkeys([P, multiply(x_sqb, L[self.verif_iter], False),
                            multiply(x_sq_invb, R[self.verif_iter], False)], False)
        self.verif_iter += 1
        return self.verify_proof_recursive(Pprime, L, R, a, b, gprime, hprime, n/2)


def run_test_IPC():
    a = [encode(x, 256, 32) for x in range(1, 9)]
    b = [encode(x, 256, 32) for x in range(9, 17)]
    ipc1 = IPC(a, b)
    comm1 = ipc1.get_commitment()
    print('generated commitment: ', binascii.hexlify(comm1))
    proof = ipc1.generate_proof()
    a, b, L, R = proof
    print('generated proof: ')
    print('a: ', binascii.hexlify(a))
    print('b: ', binascii.hexlify(b))
    print('L: ', [binascii.hexlify(_) for _ in L])
    print('R: ', [binascii.hexlify(_) for _ in R])
    print('Total byte length is: ',
          len(a) + len(b) + len(L) * len(L[0]) + len(R) * len(R[0]))
    print('Length of L, R array: ', len(L))
    print("**NOW ATTEMPTING TO VERIFY: **")
    #Note that the 'a' and 'b' vectors in the following constructor are dummy
    #values, they only set the length:
    verifier_ipc = IPC(["\x01"]*8, ["\x02"]*8)
    result = verifier_ipc.verify_proof(a, b, comm1, L, R)
    print("Verification result: ", result)

if __name__ == "__main__":
    run_test_IPC()
