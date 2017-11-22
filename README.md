# bulletproofs-poc
Learning how to bulletproofs

This is a very rough-and-ready (e.g. lacking in sanity checking) implementation of the
algorithm in the [Bulletproofs paper](https://eprint.iacr.org/2017/1066) of Bunz et al.

The purpose was only to help me (and anyone else similarly curious) understand how
the compact rangeproof explained in the paper, works.

It specifically for now is limited to a single rangeproof, not aggregated. It is also
limited to ranges of 0-2^n where n is between 1 and 6 inclusive (so max range 64 bits).

Obviously being in Python it is laughably slow, but more precisely: there is no attempt
to optimize for performance (which real implementations will have to do).

#### Examples

```
(jmvenv) me@here:~/code/bulletproofs-poc$ python rangeproof.py 3 32
Starting rangeproof test for value:  3  in range from 0 to 2^ 32
...
Got rangeproof:  0273b0509d019916114f515beaaf8426a988db5ae34e283521dec3b1d90f01b3ba02ed2b5f68d889c43f92d6123a758b3646a6dfafba1856e39ef44006612f819f5f03cc5b5109b9c0136fe5c3cb552a19ddd9569dd7c5d2b0334b3fd1e4a0a37eb75902251bee9f06ad6b288696c0f1b4f37dce371ecdd7ce247a1d89fbb799b8263b21808ee89847f67ea5da1bc1fbdd31e4275dc76249f8dc26b7c0957b1802fea8ee71684ed7142e93e01d0db28a12b6b0b76f35e2277dfd06fa976ec0dcaed5f4134bcd0c2e8b0b7931f380e60a62397cb0227883dff343b685935625e075736174a935f4418cd01285a31972fb7579023d31fd5644c6cf9007ca267c687248b12f2bfcf86b59a0bd94e803849ea08ec4431f06a58581028573701fc37caa5d253003e4c6691d58903ba2a5fb86f1081592799ee1680aa18efee94f3d559ef37b1ef60229524d65e8fef896da27792886de5c3c903755463ef3258dbf301da3512c7035030be0a14697aa9b5eb92e52befaa81b9c2b79714006ab8e26c56e389e83803ae6029e114c2be10221c0dd686744a686aa5cb254e77a6652d83db7370fc23627b690020caeafe74480077fa784094a9318bb4b124663f2714d3a996aabf6193849052a022c737d30e869be26488c6f0c0e753ae23d13adb2231fe0ef2736a5b8bc9d3ad2031138324e012a97ef6ce3ef847be83043034a7ea578fb325f25523497452b85dc02b0b3b3f3aaef6b14063ae870f468bc3e0e8c6f9c05f906fc82ad44068c27e42602a766a15c0099b295076fb07cc5d5b9890df685854e028f1c2ce4ad46ddfe705003384e3a297d2e15866402a9a13e23f286c185c6d00dc2a8ea46165b7eeb617f34
Its length is:  622
Now attempting to verify a proof in range: 0 - 4294967296
Rangeproof verified correctly, as expected.
(jmvenv) me@here:~/code/bulletproofs-poc$
```

#### Installation

(If installing these packages is annoying, quite understandably, using
instead another bitcoin code backend will require primitives for EC
scalar multiply (`ecmult`) and point addition (`ec_add_pubkeys`), into the
`utils.py` module. Feel free to ask for help if you want to do that.

(This is mainly for Debian, Ubuntu, others possible but may be trickier):

```
git clone https://github.com/Joinmarket-Org/joinmarket-clientserver
cd joinmarket-clientserver
./install.sh
```

Note this install script installs a bunch of stuff into a virtualenv most of which you
don't need; to avoid that you can if you like go into the `joinmarket-clientserver/jmbitcoin`
directory and do a `python setup.py install` instead, which only pulls in the `secp256k1-py`
binding and that package. Still do it in a virtualenv, though, for sanity.

#### TODO

* Get failure cases working properly.
* Aggregated proofs implementation.
* Larger bit ranges like 128.
* (won't bother) how to improve/optimize algo.
* (won't bother probably) how to deal with non-powers-of-2 bit ranges.