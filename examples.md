# Lungo Examples

**WARNING: this is a draft document and the examples come without security proofs. Beware of typos and vulnerabilities.**

* [Orthogonal generators](#orthogonal-generators)
* [Schnorr](#schnorr)
* [VRF](#vrf)
* [Designated Verifier VRF](#designated-verifier-vrf)
* [Ring Signature](#ring-signature)
* [Traceable Ring Signature](#traceable-ring-signature)
* [Abstract Range Proof](#abstract-range-proof)
* [Set Range Proof](#set-range-proof)
* [ChainKD](#chainkd)


## Orthogonal generators

Additional generators in the group domain-separated by a name can be generated as follows:

    Generator<protocol>(name) {
        return PointHash<protocol>({"Generator", name}, {protocol.group.base}, "")
    }

Example:

    H := Generator<...>("H")
    J := Generator<...>("J")


## Schnorr

Plain Schnorr uncompressed signature protocol (similar to EdDSA).
    
* `x` — secret scalar representing a private key.
* `P` — public key, such that `P == x·G`.

Definitions:

    schnorr = protocol {
        name:  "Schnorr"
        group: "Ristretto"
        xof:   "SHAKE128"
    }
    
    schnorr_genkey(entropy, customization_label) {
        G := schnorr.group.base
        {x} := ScalarHash<schnorr>(1, {customization_label}, {entropy}, {}, "")
        P := x·G
        P’:= schnorr.group.encode(P’)
        return (P’, x)
    }
    
    schnorr_sign(P, x, entropy, msg, customization_label) {
        G := schnorr.group.base
        {r} := ScalarHash<schnorr>(1, {customization_label}, {entropy,x}, {P}, msg)
        R := r·G
        e := ChallengeHash<schnorr>({customization_label}, {R}, {P}, msg)
        s := r + e·x mod schnorr.group.order
        R’:= schnorr.group.encode(R)
        return R’ || s
    }
    
    schnorr_verify(R’||s, P’, msg, customization_label) {
        G := schnorr.group.base
        R1:= schnorr.group.decode(R’)
        P := schnorr.group.decode(P’)
        e := ChallengeHash<schnorr>({customization_label}, {R1}, {P}, msg)
        R2:= s·G - e·P
        return schnorr.group.equal(R1, R2)
    }


## VRF

Simple VRF maps an arbitrary-length string `msg` to a verifiably random outut keyed with public key `P`.

    vrf = protocol {
        name:  "VRF"
        group: "Ristretto"
        xof:   "SHAKE128"
    }
    
    vrf_genkey(entropy, customization_label) {
        schnorr_genkey(entropy, customization_label)
    }
    
    vrf_commit(P’, x, customization_label, msg) {
        P := vrf.group.decode(P’)
        B := PointHash<vrf>({customization_label}, {P}, msg)
        V := x·B
        h := Compress<vrf>(32, {customization_label}, {V}, "")
        return h
    }
    
    vrf_sign(P’, x, entropy, customization_label, msg) {
        G := vrf.group.base
        P := vrf.group.decode(P’)
        B := PointHash<vrf>({customization_label}, {P}, msg)
        V := x·B
        {r} := ScalarHash<vrf>(1, {customization_label}, {entropy,x}, {P, V}, msg)
        RG:= r·G
        RB:= r·B
        e := ChallengeHash<vrf>({customization_label}, {RG, RB}, {P, V}, msg)
        s := r + e·x mod vrf.group.order
        V’:= vrf.group.encode(V)
        return (V’||e||s)
    }
    
    vrf_verify((V’||e||s), P’, msg, customization_label) {
        G := vrf.group.base
        P := vrf.group.decode(P’)
        B := PointHash<vrf>({customization_label}, {P}, msg)
        V := vrf.group.decode(V’)
        RG:= s·G - e·P
        RB:= s·B - e·V
        e’:= ChallengeHash<vrf>({customization_label}, {RG, RB}, {P, V}, msg)
        if e’ == e {
            h := Compress<vrf>(32, {customization_label}, {V}, "")
            return h
        } else {
            return nil
        }
    }

## Designated Verifier VRF

This is a variant of VRF above, but with a 2-item ring signature that allows forgery by the designated verifier
identified by the key pair `D,d` (`D == d·G`).

    dvrf = protocol {
        name:  "DVRF"
        group: "Ristretto"
        xof:   "SHAKE128"
    }
    
    // used by verifiers and signers
    dvrf_genkey(entropy, customization_label) {
        schnorr_genkey(entropy, customization_label)
    }
    
    dvrf_commit(P’, x, customization_label, msg) {
        P := dvrf.group.decode(P’)
        B := PointHash<dvrf>({customization_label}, {P}, msg)
        V := x·B
        h := Compress<dvrf>(32, {customization_label}, {V}, "")
        return h
    }
    
    dvrf_sign(D’, P’, x, entropy, customization_label, msg) {
        G := dvrf.group.base
        D := dvrf.group.decode(D’)
        P := dvrf.group.decode(P’)
        B := PointHash<dvrf>({customization_label}, {P}, msg)
        V := x·B
        {r,z} := ScalarHash<dvrf>(2, {customization_label}, {entropy,x}, {D, P, V}, msg)
        RG:= r·G
        RB:= r·B
        e1:= ChallengeHash<dvrf>({"Proof", customization_label}, {RG, RB}, {D, P, V}, msg)
        RF:= z·G + e1·D
        e0:= ChallengeHash<dvrf>({"Forgery", customization_label}, {RF}, {D, P, V}, msg)
        s := r + e0·x mod dvrf.group.order
        V’:= dvrf.group.encode(V)
        return (V’||e0||s||z)
    }
    
    dvrf_forge(D’, P’, V’, d, entropy, customization_label, msg) {
        G := dvrf.group.base
        D := dvrf.group.decode(D’)
        P := dvrf.group.decode(P’)
        B := PointHash<dvrf>({customization_label}, {P}, msg)
        V := dvrf.group.decode(V’)
        {r,s} := ScalarHash<dvrf>(2, {customization_label}, {entropy,d}, {D, P, V}, msg)
        RF:= r·G
        e0:= ChallengeHash<dvrf>({"Forgery", customization_label}, {RF}, {D, P, V}, msg)
        RG:= s·G - e0·P
        RB:= s·B - e0·V
        e1:= ChallengeHash<dvrf>({"Proof", customization_label}, {RG, RB}, {D, P, V}, msg)
        z := r + e1·x mod dvrf.group.order
        return (V’||e0||s||z)
    }
    
    dvrf_verify((V’||e0||s||z), D’, P’, msg, customization_label) {
        G := dvrf.group.base
        D := dvrf.group.decode(D’)
        P := dvrf.group.decode(P’)
        B := PointHash<dvrf>({customization_label}, {P}, msg)
        V := dvrf.group.decode(V’)
        RG:= s·G - e0·P
        RB:= s·B - e0·V
        e1:= ChallengeHash<dvrf>({"Proof", customization_label}, {RG, RB}, {D, P, V}, msg)
        RF:= z·G + e1·D
        e’:= ChallengeHash<dvrf>({"Forgery", customization_label}, {RF}, {D, P, V}, msg)
        if e’ == e0 {
            h := Compress<dvrf>(32, {customization_label}, {V}, "")
            return h
        } else {
            return nil
        }
    }


## Ring Signature

The following shows a ring version of Schnorr signature, but using compressed signature form (`e,s[0],...,s[n-1]`) to align with unconditionally binding commitments in the [Set Range Proof](#set-range-proof).

    rs = protocol {
        name:  "RingSignature"
        group: "Ristretto"
        xof:   "SHAKE128"
    }
    
    rs_sign({P’[i]}, j, x[j], entropy, msg, customization_label) {
        G := rs.group.base
        n := len({P’[i]})
        foreach P’[i] {
            P[i] := rs.group.decode(P’[i])
        }
        Pset := {P[0],...,P[n-1]}
        
        {r[i]} := ScalarHash<rs>(n, {customization_label}, {entropy, varint(j), x[j]}, Pset, msg)
        // all but r[0] will be used as forged s-elements
        
        // Precommit
        R := r[0]·G
        e[j+1 mod n] := ChallengeHash<rs>({customization_label}, {R}, Pset, uint64le(j) || msg)
        
        // Forge all other elements
        for step := 1..n-1 {
            i := (j + step) mod n
            s[i] := r[step]  // using r[i≠0] as a forged s-element
            R := s[i]·G - e[i]·P[i]
            e[i+1 mod n] := ChallengeHash<rs>({customization_label}, {R}, Pset, uint64le(i) || msg)
        }
        
        // Sign
        s[j] := r[0] + e[j]·x[j] mod l
        return (e[0], {s[0],...,s[n-1]})
    }
    
    rs_verify(e, {s[i]}, {P’[i]}, msg, customization_label) {
        G := rs.group.base
        foreach P’[i] {
            P[i] := rs.group.decode(P’[i])
        }
        Pset := {P[0],...,P[n-1]}
        e’ := e
        for i := 0..(n-1) {
            R := s[i]·G - e’·P[i]
            e’ := ChallengeHash<rs>({customization_label}, {R}, Pset, uint64le(i) || msg)
        }
        return e == e’
    }


## Traceable Ring Signature

This is a part of the CryptoNote/Monero protocol that is effectively a ring version of VRF where the message under commitment is the public key itself.

* `G` — base point in Curve25519.
* `x` — secret scalar representing a private key.
* `P` — public key, such that `P == x·G`.
* `I` — key image, such that `I == x·PointHash(P)`.

Definitions:

    trs = protocol {
        name:  "TraceableRingSignature"
        group: "Ristretto"
        xof:   "SHAKE128"
    }
    
    trs_commit(P’, x) {
        P := trs.group.decode(P’)
        B := PointHash<trs>({}, {P}, "")
        I := x·B
        I’:= trs.group.encode(I)
        return I’
    }
    
    trs_sign({P’[i]}, j, x[j], entropy, msg, customization_label) {
        G := trs.group.base
        n := len({P’[i]})
        foreach P’[i] {
            P[i] := trs.group.decode(P’[i])
        }
        Pset := {P[0],...,P[n-1]}
        
        {r[i]} := ScalarHash<trs>(n, {customization_label}, {entropy, varint(j), x[j]}, Pset, msg)
        // all but r[0] will be used as forged s-elements
        
        // Precommit
        B[j]:= PointHash<trs>({}, {P[j]}, "")
        I := x[j]·B[j]
        RG:= r[0]·G
        RI:= r[0]·B
        e[j+1 mod n] := ChallengeHash<trs>({customization_label}, {RG, RI}, {I, Pset...}, uint64le(j) || msg)
        
        // Forge all other elements
        for step := 1..n-1 {
            i := (j + step) mod n
            s[i] := r[step]  // using r[i≠0] as a forged s-element
            B[i] := PointHash<trs>({}, {P[i]}, "")
            RG:= s[i]·G    - e[i]·P[i]
            RI:= s[i]·B[i] - e[i]·I
            e[i+1 mod n] := ChallengeHash<trs>({customization_label}, {RG, RI}, {I, Pset...}, uint64le(i) || msg)
        }
        
        // Sign
        s[j] := r[0] + e[j]·x[j] mod l
        return (e[0], {s[0],...,s[n-1]})
    }
    
    trs_verify(e, {s[i]}, I’, {P’[i]}, msg) {
        G := trs.group.base
        I := trs.group.decode(I’)
        foreach P’[i] {
            P[i] := trs.group.decode(P’[i])
        }
        Pset := {P[0],...,P[n-1]}
        e’ := e
        for i := 0..(n-1) {
            B[i]:= PointHash<trs>({}, {P[i]}, "")
            RG  := s[i]·G    - e’·P[i]
            RI  := s[i]·B[i] - e’·I
            e’  := ChallengeHash<trs>({customization_label}, {RG, RI}, {I, Pset...}, uint64le(i) || msg)
        }
        return e == e’
    }


## Abstract Range Proof

This is an abstract template for various rangeproofs. Using it standalone
is not possible because it defers the choice of commitments to be signed (`{C}`)
to the higher-level protocols (e.g. a [set range proof](#set-range-proof)) that must ensure
that none of the commitments are malleable with respect to the proof.

**Warning: this algorithm is not running in constant time.**

* `NR` — number of rings
* `NI` — number of items per ring
* `NS` — number of statements per item
* `NX` — number of secrets per item
* `t = 0..NR-1` - index of a ring
* `i = 0..NI-1` - index of an item
* `j = 0..NS-1` - index of a statement
* `k = 0..NX-1` - index of a secret within an item
* `î[t] = 0..NI-1` - secret index of a non-formed item in ring `t`
* `x[t,k]` - secret scalar for ring `t` with index `k`
* `{s[t,i,k]}` — 3-dimensional array of s-elements of size `NR·NI·NX`.
* `{P[t,i,j]}` — 3-dimensional array of commitments of size `NR·NI·NS`.
* `{C}` — array of original commitments to be signed that themselves commit to `{P[t,i,j]}` (specified by the concrete protocol).
* `{F[j]({x[k]})}` — a list of commitment functions of size `NS` over `NX` variables.

Definitions:

    rangeproof = protocol {
        name:  ___,
        NR:    ___,
        NI:    ___,
        NS:    ___,
        NX:    ___,
        group: "Ristretto"
        xof:   "SHAKE128"
    }
        
    rangeproof_sign<protocol>({x[t,k]}, {î[t]}, {P[t,i,j]}, {C}, {F[j]({x[k]})}, entropy, msg, label) {
        // Generate NR·NI·NX random scalars
        {r[t,i,k]} := ScalarHash<protocol>(NR·NI·NX, {label}, {entropy, x[0,0],...,x[NR-1,NX-1], î[0],...,î[NR-1]}, {C}, msg)
        
        // Precommit
        for t := 0..(NR-1) {
            i := î[t]
            for j := 0..(NS-1) {
                R[t,i,j] := F[j](r[t,i,0], ..., r[t,i,NX-1])
            }
            e[t, i+1 mod NI] := ChallengeHash<protocol>(
                                    {label},
                                    // points are doubled to take advantage of Doppio, a batchable variant of Ristretto encoding
                                    {2·R[t,i,0],...,2·R[t,i,NS-1]},
                                    {C}, uint64le(t) || uint64le(i) || msg
                                )
        }
        
        // First halves of the rings
        for t := 0..(NR-1) {
            for i := î[t]+1..(NI-1) { // Note: can be an empty loop if î[t] == NI-1
                for k := 0..(NX-1) {
                    s[t,i,k] = r[t,i,k] // forged
                }
                for j := 0..(NS-1) {
                    R[t,i,j] := F[j](s[t,i,0], ..., s[t,i,NX-1]) - e[t,i]·P[t,i,j]
                }
                e[t, i+1 mod NI] := ChallengeHash<protocol>(
                                        {label},
                                        {2·R[t,i,0],...,2·R[t,i,NS-1]},
                                        {C}, uint64le(t) || uint64le(i) || msg
                                    )
            }
        }
        
        // Shared challenge at statement 0
        ê := Compress<protocol>(32, {label}, {}, e[0,0] || ... || e[NR-1,0])
        
        // Complete second halves of the rings
        for t := 0..(NR-1) {
            e[t,0] := ê
            for i := 0..î[t]-1 { // Note: can be an empty loop if î[t] == 0
                for k := 0..(NX-1) {
                    s[t,i,k] = r[t,i,k] // forged
                }
                for j := 0..(NS-1) {
                    R[t,i,j] := F[j](s[t,i,0], ..., s[t,i,NX-1]) - e[t,i]·P[t,i,j]
                }
                e[t, i+1 mod NI] := ChallengeHash<protocol>(
                                        {label},
                                        {2·R[t,i,0],...,2·R[t,i,NS-1]},
                                        {C}, uint64le(t) || uint64le(i) || msg
                                    )
            }
        }
        
        // Sign
        for t := 0..(NR-1) {
            i := î[t]
            for k := 0..(NX-1) {
                s[t,i,k] = r[t,i,k] + x[t,k]·e[t,i] mod rangeproof.group.order
            }
        }
        
        return (ê, {s[t,i,k]})
    }
    
    rangeproof_verify<protocol>(ê, {s[t,i,k]}, {P[t,i,j]}, {C}, {F[j]({x[k]})}, label, msg) {
        for t := 0..(NR-1) {
            e[t,0] := ê
            for i := 0..(NI-1) {
                for j := 0..(NS-1) {
                    R[t,i,j] := F[j](s[t,i,0], ..., s[t,i,NX-1]) - e[t,0]·P[t,i,j]
                }
                e[t, i+1 mod NI] := ChallengeHash<protocol>(
                                        {label},
                                        // points are doubled to take advantage of Doppio, a batchable variant of Ristretto encoding
                                        {2·R[t,i,0],...,2·R[t,i,NS-1]},
                                        {C},
                                        uint64le(t) || uint64le(i) || msg
                                    )
            }
        }
        e’ := Compress<protocol>(32, {label}, {}, e[0,0] || ... || e[NR-1,0])
        return ê == e’
    }


## Set Range Proof

Set range proof proves that a given ElGamal commitment belongs to a range of other ElGamal commitments.

* `G,J` — orthogonal generators, first one is a standard base point.
* `M` — group element for which commitment is created
* `c’` — a blinding scalar.
* `(H’,B’) = (M+c’·G, c’·J)` — non-trusted commitment to be proven to belong to the required range
* `N` — number of items in the range
* `i=0..N-1` — index of the item in the range
* `î` — secret index of the commitment in the range, which is re-blinded as `H’,B’`.
* `(H[i],B[i])` — the required range of `N` trusted commitments.

Definitions:

    srp = rangeproof {
        name: "SetRangeProof",
        NR:   1, // rings
        NI:   N, // items
        NS:   2, // statements
        NX:   1  // secrets
    }
    
    srp_sign(M, î, c’, c[î], {H[i],B[i]}, entropy, msg, label) {
        G := srp.group.base
        J := Generator<srp>("J")
        
        // Blind
        H’:= M + c’·G
        B’:= c’·J
        
        // Prepare rangeproof configuration
        x := c’ - c[î]
        for i := 0..(N-1) {
            P[0,i,0] := H’ - H[i]
            P[0,i,1] := B’ - B[i]
        }
        F[0](x) := x·G
        F[1](x) := x·J
        
        // Sign
        return rangeproof_sign<protocol>(
                    {x}, {î}, 
                    {P[t,i,j]}, 
                    {H’,B’,H[0],B[0], ... H[N-1],B[N-1]}, 
                    {F[j](x)}, 
                    entropy, msg, label
                )
    }
    
    srp_verify(ê, {s[t,i,k]}, (H’,B’), {H[i],B[i]}, label, msg) {
        G := srp.group.base
        J := Generator<srp>("J")
        
        // Prepare rangeproof configuration
        for i := 0..(N-1) {
            P[0,i,0] := H’ - H[i]
            P[0,i,1] := B’ - B[i]
        }
        F[0](x) := x·G
        F[1](x) := x·J
        
        // Verify
        return rangeproof_verify<srp>(
                    ê, {s[t,i,k]},
                    {P[t,i,j]},
                    {H’,B’,H[0],B[0], ... H[N-1],B[N-1]},
                    {F[j](x)},
                    label, msg
                )
    }
    


## ChainKD

ChainKD is a hierarchical key derivation (HKD) scheme inspired by BIP32.
It is not a signature scheme per-se, but reuses the existing framework for deriving keys.

ChainKD extends Schnorr public and private keys to xpubs and xprvs: extended public/private keys.
Each key is encoded with additional 32-byte string `dk` used as symmetric “derivation key”.

If the public or private key is stripped of `dk`, it cannot be used to derive or identify child keys.

    chainkd = protocol {
        name:  "ChainKD"
        group: "Ristretto"
        xof:   "SHAKE128"
    }
    
    chainkd_generate(seed) {
        {x,dk} := ScalarHash<chainkd>(2, {"Generate"}, {seed}, {}, "")
        return x||dk
    }
    
    // Compute xpub for a given xprv.
    chainkd_xpub(x||dk) {
        G := chainkd.group.base
        P := x·G
        P’:= chainkd.group.encode(P)
        return P’||dk
    }
    
    chainkd_derive_xpub(P1’||dk1, selector) {
        G := chainkd.group.base
        P1 := chainkd.group.decode(P1’)
        {f,dk2} := ScalarHash<chainkd>(2, {"Derive"}, {dk1}, {P1}, selector)
        P2 := P1 + f·G
        P2’:= chainkd.group.encode(P2)
        return P2’||dk2
    }
    
    chainkd_derive_xprv(x1||dk1, selector) {
        G := chainkd.group.base
        P1 := x1·G
        {f,dk2} := ScalarHash<chainkd>(2, {"Derive"}, {dk1}, {P1}, selector)
        x2 := x1 + f mod chainkd.group.order
        return x2||dk2
    }
    
    chainkd_derive_hardened(x||dk, selector) {
        return chainkd_generate(x||dk||selector)
    }


