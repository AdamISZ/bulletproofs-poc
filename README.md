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

Small case (range 0-16):

```
(jmvenv) me@here:~/code/bulletproofs-poc$ python rangeproof.py 3 4
Starting rangeproof test for value:  3  in range from 0 to 2^ 4
...
Got rangeproof:  025f4d04f489c79eebad5bf92e7b8d978cf7d904be39613c5406a4b4a6017a956e03e3a83050848e3f1cbf5067ece90f3e3f83837df19da981a912b2c660bd982d290225031a120072ebda4715fc9388098f219e8039245bb005a0b49772a6fdc9ba0203dbf6efef668a081be7f38f1b4aba6779082dbd1e5970d49047ce479576a02c3b91e15c5c17157210e59d41c182cee83d2c9ec9c823973322a27df7bd76018263f8a8f1da8fd8b6e7f8ca3b0f9e48e235f415901c4bb787db0da6b805810977ec70b0fdb52344821a85d104b2d5de42d81b4676ec6bac12abeb4482f3de7ce6fe0d0e1e0c1863c78436634e385b6d750b97d2aad8c1d0a5e2af2069f392740cdd30ad378cfa34afb7886d9bd6e3fc8b73167a123a4ef776422c946d908358e89903b394314f81bd64db880dff155f2ebbd30a6f10fe355ba14b9b6b6cbc62dc82ae02cbb9d4a11c37616b9497c7d1d69f916d90b77fa392310ffa23cdfc29c5fbac420307e6a7e2a6c1a752c9de47eef904a6717b3c7c1a54efe84e69ed1cb8493b3305033a428f67286b1e791b3786658cfd99522e28195b7fde3b183959bfa74d4630ff
Its length is:  424
Now attempting to verify a proof in range: 0 - 16
Rangeproof verified correctly, as expected.
(jmvenv) me@here:~/code/bulletproofs-poc$
```

Out-of-range fails:

```
(jmvenv) me@here:~/code/bulletproofs-poc$ python rangeproof.py 1088 8
Starting rangeproof test for value:  1088  in range from 0 to 2^ 8
...
Value is NOT in range; we want verification to FAIL.
Using truncated bits, value:  64  to create fake proof.
...
Got rangeproof:  02f3a41870cf6d996c7828987049419f5bd365a8c2ea98c90d7b57cfde1bdb42ff03910068f542c27eea0ab71f09d74920c33e4595f1ee396ef333c86e5a6195129a03915e03c2ba396a0c308fa927f17a68bc0d733592c19e9ecaa8fac8982b072dd2038fa05d750afbde2a2b099ea1adfdbaa1d360b144d571c4d3458a142c7637614af06f7353a280086dd8e172883505c903ce551952cf57772bb21bfa04883892ce392ec43ba60b44806209a9842a872eeb9ff3ab51e1fb0e9bd943e54905fdfd7330dc7e371c931ba0edd1e3973a6277e58dc2622ebd8785592aa82f578a4b56f12210bc1e43b9b8002a0fcc414990200653060c979b583a9167a3ea8569886b821614498d552a5aff6a8157f818a7f330d88734e23a547071998381b19864c39c03d5c62cc4366494ec7cf7eb72d05838959d62966d42943ad076e0557a4848beb003c711bcbf68a5c84534fa6be83ae7b951b26d9dc9c0691a069097210968ea90ab03cb4db738403222dae120436879fde23de83e211c9ea1c71ba2a1527fc3e5dcb60212f1525a25c30dc862bbb2d18c2217e4e4a94a45040f3fc2c4a540d059856b87031d6bcf81fcb7dec6ee6e4e71f3ef17ab4d8cf808610803a5a8613fbeab3d17a4021437a37cfaffd93935214b2b00b0484503359ca561332d57ab04c38d7bbc9637
Its length is:  490
Now attempting to verify a proof in range: 0 - 256
(61) verification check failed
02677186c340636c8b94d875ec1dac773aa6812a8867060ba9fbd75853c7b64c9d
024ce5cea460a9f33988c2c44b12c4e6b79fffe5c6b54636fea8b8e79fcd190389
Rangeproof failed, as it should because value is not in range.
(jmvenv) me@here:~/code/bulletproofs-poc$
```

Largest in 32 bit range succeeds:

```
(jmvenv) me@here:~/code/bulletproofs-poc$ python rangeproof.py 4294967295 32
Starting rangeproof test for value:  4294967295  in range from 0 to 2^ 32
...
Got rangeproof:  0306d55f36af51c8ff14533fec2ece519aaea6cca092ad840f7c33a6c0ed6c3def022e3d0031c9e22b69cd6ca95c680497ff3eea218ad82676a483740190b0b0895c031867bf975185773d0e0da9938684550b384e75db7a0c5f8fe975f8fc405eb1af0309383eab4e5a7f690342dfecf9102750f16da52f677b52e88f1915bcd9db7d16b7320b047a137c224460750df8a7759b359c6d13eb957b30af5d7569115e4879c35c0690a73de4774700056954bc0d4d4713b77bf19bc173696993022254f67d07adc49d0ce63e7ba076d943e5144797b5f09f012af81419a6ad87217c5701c747ddbf2baca2e887d1cd89af66cb0cc79772919567ade284b953d7fd74fede273bd80974a3645f655af8aad0001668e7a4f6a100f297de52320736a20ea495cb0369ab72d1cd09b569e92ce7598a6ab64a94a7d4f34393c8f89ab31dc9f111556103b799ba34d5351950a5fbf725896554e40a4e5a21961fd19949eedec99f8aabd2022cdaa31c502e6320fedc3f531249a52875ce0a7e685357afc949d21f56a8ee5703effe462fb09c0e7e04aa8403a681e30b3eeffce848d441f463f45e7b54367124022109de410b6977df9d1ada3cce5d97d510b8047adb0e56cfcfbce35f2d4d6d20032fce6ec7eb92ecc87694a331aa620300eda38a7767c8c42abbf44ee30d2e291202601f1970e25007a887a4fb5f5a106d51e2d7b01954760e0b1bc1153a45abac5b021dcd995ecc6a61a3fc0a34f13dd14203b74859dd54418b3265e8cf4aaf111f42023f142bdef1c9c94c24fc9d2aad20d55feb2faf1e9154167591d65b3de625f8f9026c8c5331df7fcbab2fd286de9b2f5ce16526f9488667d80a2b932fee9db986c9
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
git checkout a612ddba72e8f79fff6fbc681c348172fdaa6544
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
