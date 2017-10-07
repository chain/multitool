# Lungo (DRAFT)

The public key cryptography framework.

**WARNING: this is a very early draft, do not count on it. All opinions are welcome, especially yours.**

* [Motivation](#motivation)
* [Overview](#overview)
* [Core Specification](#core-specification)
    * [Terminology](#terminology)
    * [Labelset](#labelset)
    * [Protocol](#protocol)
    * [Scalar Hash](#scalar-hash)
    * [Challenge Hash](#challenge-hash)
    * [Point Hash](#point-hash)
    * [Compress](#compress)
* [Ristretto Specification](#ristretto-specification)
* [Generic Curve Parameters](#generic-curve-parameters)
* [Acknowledgements](#acknowledgements)

## Motivation

Previously considered exotic cryptographic schemes today become rapidly productized
due to high demand for end-to-end encrypted communication tools, blockchain networks
and all related technology. Verifiable random functions, ring signatures, rangeproofs,
hierarchical key derivation schemes share a few common bits that must be done correctly
to ensure safety and avoid common pitfalls. Things like nonce generation, key derivation,
fiat-shamir challenge generation etc.

**Lungo** is a framework that allows building such zero-knowledge schemes in a safe and
straightforward manner. Lungo is generalized to any prime order group where DLP is hard, but
also has an instance “with batteries included” which uses a high-performance Ristretto group based on Curve25519.

The name **Lungo** comes from the “opposite of ristretto”, meaning, the opposite of _restricting_ it to any specific scheme or group.
Not to be confused with Ristretto group (used together with Lungo), which _restricts_ Decaf scheme to edwards curves with cofactor 8.

## Overview

### Synthetic nonces

Generalized safe nonce-generation procedure that addresses safety and bikeshedding issues:

1. **Deterministic derivation** from secret scalars protects against RNG failures.
2. Additional **RNG entropy** protects against misuse (cross-protocol nonce reuse due to secret reuse) and glitches in the deterministic derivation.
3. Hashing defines a **customization scheme** that comes with an extensive security rationale and provides a standard yet flexible API for the custom protocols.

### Generalized challenge generation

1. Fiat-Shamir transform is generalized to support **variable number of secrets, statements and commitments** for a wide range of schemes, from simple DSA to designated-verifier VRFs and even borromean ring signatures.
2. **Challenge and nonce generation are aligned** to minimize the risk of misuse: when an additional input is added to the challenge, but not to the associated nonce.
3. Challenge hashing uses the same **customization scheme** as synthetic nonces.

### Prime order group

Group elements used to implement commitments and public keys always belong to a prime order group. Protocols instantiated with elliptic curve groups having cofactor greater than 1 (such as Curve25519 and Curve448), **Ristretto** and **Decaf** schemes are used respectively to enforce that rule.

### Indirect commitments

Some schemes derive public keys (or, generally speaking, commitments to secrets, statements of which are being proven) from other commitments. For example, range proofs with base-4 digits derive 4 “public keys” for each digit commitment deterministically. Encoding and hashing these public keys would be 4x more wasteful compared to just encoding a digit commitment and hashing it together with an index from 0 to 3. In order to facilitate these schemes, the challenge is designed to support **indirect commitments** that are defined by each specific scheme.

### Compressed and uncompressed signatures

There are two ways to encode a Schnorr signature: by exposing a nonce-commitment (usually denoted as group element `R`) or by exposing a challenge (denoted by a scalar `e`) that is computed as a hash of the nonce-commitment (not mentioning the message and other associated data):

    Uncompressed signature                 Compressed signature
    1. Receive (R,s)                       1. Receive (e,s)
    2. Compute e = H(R, msg)               2. Compute R = s*G - e*Pubkey
    3. Verify R == s*G - H(R)*Pubkey       3. Verify e == H(encode(R, msg))

**Uncompressed form** is usually as compact as compressed one for the simple single-statement signatures,
and allows batched verification of multiple signatures at once, plus avoids group element encoding overhead.

**Compressed form**, however, is suitable for multi-statement or multi-ring signature because it avoids sending multiple `R` group elements.
For instance, 32-digit base-4 range proofs save 31×32 bytes by compressing all `R` group elements from each ring in one shared challenge hash.

Each protocol should statically decide which form it uses.

### Compatibility

The specification aims to reuse most of existing codebases implementing Curve25519 and Curve448.
Due to Ristretto encoding and related simplification of the schemes,
we intentionally do not maintain compatibility with the existing EdDSA standard ([RFC8032](https://tools.ietf.org/html/rfc8032)).


## Core Specification

### Terminology

Term      | Description
----------|-------------
`l`       | Order of the prime order group used by the protocol.
`|x|`     | Maximum number of bytes necessary to represent the scalar `x`.
`x`       | Scalar, an integer between `0` and `l-1`.
`G`       | Base group element.
`P`       | Public key defined as `x·G`.
`msg`     | An arbitrary-length binary string being signed.
`r`       | Random scalar called "nonce" that blinds the secret, statements of which are being proven.
`R`       | Commitment to a nonce with a relevant base group element (e.g. `R = r·G`).
`e`       | Challenge scalar, a Fiat-Shamir transform for the sigma-protocol.
`s`       | Proof scalar, proving the statement about some secret `x`. Each secret has its own “s-value” (simpler schemes use only one secret).
`entropy` | An arbitrary-length string representing randomness from a RNG. At least 128 bits of entropy are recommended.
`{x#n}`   | A list of `n` elements: `{x[0],...,x[n-1]}`.
`{x#n,m}` | A list of `n` lists of `m` elements.
`{x}`     | A list of unspecified size (could be anything).
`len(x)`  | Number of items in the list `x` (if it's a byte string, number of bytes).
`byte(x)` | Encoding of a integer `x` in range 0..255 as a single byte.
`uint64le(x)` | Encoding of a non-negative integer `x` using little-endian notation as an 8-byte string.

### Labelset

Customization is supported via extensible *labelset*.

The labelset is used to provide independent random oracles in more complex protocols.
It can contain identifiers for the protocol, a user-specified customization label,
and identifiers for the hash instance. 

Labelset is encoded as follows:

    n || len(label1) || label1 || ... || len(label_n) || label_n

Where `n` is a 1-byte encoding of the number of labels, and `len_i` is a 1-byte encoding of the length of the label that follows, in bytes.
Number of labels and the length of each label in bytes is limited to 255.

An empty labelset is encoded as a 1-byte string containing zero: `0x00`.

A labelset can be extended with the additional labels that customize higher-level protocols:

    add_labels(labelset, x...) {
        foreach x {
            verify(len(x) <= 255)
            verify(labelset[0] < 255)
            labelset[0] += 1
            labelset := labelset || byte(len(x)) || x
        }
        return labelset
    }

### Protocol

The framework requires protocol to specify a minimal set of parameters:

    protocol {
        name:  "Schnorr" | "VRF" | ...
        group: "Ristretto" | "Decaf448" | "P256k1" | "P256r1" | ...
        xof:   "SHAKE128" | ...
        extralabels: {...}
    }

* `protocol.name` - a variable-length string, identifying a protocol name.
* `protocol.group` - a variable-length string identifying an elliptic curve and related parameters.
* `protocol.xof` - a variable-length string identifying an extensible-output hash function.
* `protocol.extralabels` - an additional labelset (could be empty) that customizes the given protocol for the higher-level protocols

Each `group` label defines the following parameters:

* `protocol.group.order`, aka prime number `l`, the number of elements in the group.
* `protocol.group.base`, aka `G`, a base group element.
* `protocol.group.equal(a,b)->true`, equality check for a pair of group elements.
* `protocol.group.encode(element)->string`, encoding a group element to a string.
* `protocol.group.decode(string)->element`, decoding a group element from a string. 
* `protocol.group.mapToElement(string)`, a decoding procedure that maps a random string of length `|protocol.group.order|` to a group element.

XOF takes an input string to be hashed and a number of bytes to be returned:

    protocol.xof(input, n) -> {byte[0], ..., byte[n-1]}

Each protocol has a [labelset](#labelset) consisting of a single label:

    protocol.labelset = { <name>_<group>_<xof>, extralabels... }  // e.g. {"Schnorr_Ristretto_SHAKE128"}

Underscores are used to be compatible with syntax for identifiers in most programming languages.


### Scalar Hash

`ScalarHash` outputs a list of synthetic scalars generated using `k` secrets `{x[i]}` and `m` commitment group elements `{C[j]}`.

The first secret in a list is recommended to be the high-entropy output of RNG to defend against cross-protocol misuse.

Commitment strings could be the public keys, various commitments.

* `labelset` is a list of labels that allow customization and domain-separation in the higher-level protocol.
* `n` is the number of scalars to be produced, encoded as a little-endian 64-bit unsigned integer.
* `pad` are distinct minimal all-zero strings (could be empty) that pad the input to the block size of the given XOF.
* `x` is a list of `k` secret arbitrary-length strings (e.g. private key, secret indices).
* `C` is a list of `m` commitment group elements (e.g. public keys).

Algorithm:

    ScalarHash<protocol>(label, {x#k}, {C#m}, msg) -> {r#n} {
        labelset’ := AddLabels(protocol.labelset, "ScalarHash", label)
        {r[0],...,r[n-1]} := protocol.xof(
                                        labelset’   || 
                                        uint64le(n) || <pad> ||
                                        x[0]        || <pad> ||
                                        ...
                                        x[k-1]      || <pad> ||
                                        labelset’   ||
                                        uint64le(m) ||
                                        protocol.group.encode(C[0])   ||
                                        ...
                                        protocol.group.encode(C[m-1]) ||
                                        msg,
                                        n * (|protocol.group.order|+16)
                                       )
        foreach r[i] {
            r[i] := r[i] mod protocol.group.order
        }
        return {r[0],...,r[n-1]}
    }

Rationale:

1. First input to the hash function is the labelset and the desired output length, which provides the domain separation between the protocols. This ensures that a nonce does not get reused between protocols by accident.
2. Padding the customized prefix to the nearest block allows pre-computation and reuse of the XOF instance for a given labelset.
3. Each secret is padded to the nearest block to turn XOF into a PRF keyed with the secret. When the first secret is an output from RNG, it randomizes the XOF against cross-protocol misuse. If the second secret is a static signing key, it provides a defense against faulty RNG by making the resulting nonce unpredictable.
4. Secrets are not length-prefixed as it’s expected they are independent and padding is enough to isolate permutations of each secret. TBD: review this closely to check if it's actually safe.
5. Commitments are all group elements to which the scalar must commit. For instance, public keys, Pedersen or ElGamal commitments and alike. Since the size of these is static for a given group, length prefixes are not used.
5. Output consists of extra 128 bits per scalar to make deviation from the uniform distribution of the resulting scalar after modular reduction negligible.
6. XOF is used instead of a fixed-output hash function for two reasons: to make one hash function work with groups of different order, and to avoid repeated hashing of the inputs which should not be pre-hashed due to collision-resilience requirement.


### Challenge Hash

Challenge hash produces a single scalar `e` out of random commitments to nonces (`{R[i]}`) bound to the commitments (group elements) and the message (arbitrary-length string).

    ChallengeHash<protocol>(label, {R#n}, {C#m}, msg) {
        labelset’ := AddLabels(protocol.labelset, "ChallengeHash", label)
        e := protocol.xof(
                        labelset’   || <pad> ||
                        uint64le(n) ||
                        protocol.group.encode(R[0])   ||
                        ...
                        protocol.group.encode(R[n-1]) ||
                        <pad>       ||
                        labelset’   ||
                        uint64le(m) ||
                        protocol.group.encode(C[0])   ||
                        ...
                        protocol.group.encode(C[m-1]) ||
                        msg,
                        |protocol.group.order|+16
             )
        e := e mod protocol.group.order
        return e
    }

Rationale:

1. TBD: labelset provides domain separation.
2. TBD: nonce commitments are padded to a whole block to turn XOF into a PRF which is hard to find collisions with.
3. TBD: repeated labelset adds collision resilience
4. TBD: extra 16 bytes of XOF output to make bias less than 2^-128 after reducing the scalar mod l.

### Point Hash

Point hash function hashes a list of commitments and an arbitrary-length message into a group element.

    PointHash<protocol>(label, {C[i]}, msg) {
        labelset’ := AddLabels(protocol.labelset, "PointHash", label)
        m = len(C)
        h := protocol.xof(
            labelset’ || pad || 
            uint64le(m) ||
            protocol.group.encode(C[0]) ||
            ...
            protocol.group.encode(C[m-1]) ||
            msg, 
            |protocol.group.order|
        )
        return protocol.group.mapToElement(h)
    }

### Compress

Compression hash function uses XOF customized with the protocol’s label set and produces a 32-byte output.

    Compress<protocol>(label, msg) {
        labelset’ := AddLabels(protocol.labelset, "Compress", label)
        h := protocol.xof(labelset’ || <pad> || msg, 32)
        return h
    }


### Commit

A generalized commitment algorithm that applies `m` scalars to `n` functions and returns `m` group elements.

* `n` — number of statements represented by commitment functions.
* `m` — number of scalars, knowledge of which is being proven.
* `F({x#m})` is a function that takes `m` scalar arguments and returns a single group element.

Definition:

    Commit(label, {F({x#m})#n}, {x}, {C}, msg) {
        {r#m} := ScalarHash(label, {x}, {C}, msg)
        for j := 0..(n-1) {
            R[j] := F[j]({r#m})
        }
        e := ChallengeHash(label, {R#n}, {C}, msg)
        return e, {r#m}, {R#n}
    }

### Prove

_Prove_ blinds `m` secret scalars `{x}` with secret nonces `{r}` using a challenge hash `e`.

    Prove<protocol>(e, {r#m}, {x#m}) {
        for k := 0..(m-1) {
            s[k] = r[k] + e·x[k] mod protocol.group.order
        }
        return {s#m}
    }


### Recommit

_Recommit_ reconstructs the commitments to `n` random nonces produced by _Commit_ using `m` signature elements `{s}`, challenge hash `e` and commitments to secrets `{P}`.

* `n` — number of statements represented with commitment functions.
* `m` — number of scalars, knowledge of which is being proven.
* `F({x#m})` is a function that takes `m` scalar arguments and returns a single group element.
* `{P#n}` — `n` group elements representing a commitment to the secrets. Not always the result of evaluation of `F` functions (e.g. range proofs modify that commitment).

Definition:

    Recommit(label, {F({x#m})#n}, e, {s#m}, {P#n}, {C}, msg) {
        for j := 0..n {
            R[j] := F[j]({s#m}) - e·P[j]
        }
        e := ChallengeHash(label, {R#n}, {P#n..., C...}, msg)
        return e, {R#n}
    }




## Ristretto Specification

### Encode

TBD. normal encoding

TBD: Dual isogeny (aka Doppio), batchable 2*P encoding

### Decode

TBD.

### Equality

TBD. efficient equality check w/o full encoding


### MapToElement

TBD: ristretto-flavored Elligator




## Generic Curve Parameters

This is a recommended configuration for arbitrary curves with cofactor 1 suitable for curves P256k1 and P256r1.

### Equality

TBD. simple encode and compare bit-wise

### MapToElement

TBD: hash and pray in a loop using XOF with a const-time variant that squeezes 128 elements.




## Acknowledgements

* Mike Hamburg, for Decaf, which returns us all on the path of sanity.
* Trevor Perrin, for extremely helpful classification work and thorough explanation of various crypto caveats, all of which are reflected in this document.
* Isis Agora Lovecruft and Henry De Valence, for the excellent implemention and meticulous documention of the high-speed Curve25519 crypto, including Ristretto and Elligator algorithms.

