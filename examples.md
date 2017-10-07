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

Definition:

    protocol Schnorr(customlabel) {
        name        := "Schnorr"
        group       := "Ristretto"
        xof         := "SHAKE128"
        extralabels := {customlabel}
        G           := group.base
        F(x)        := x·G
        
        genkey(entropy) {
            x := ScalarHash("", {entropy}, {}, "")
            P := F(x)
            return (P, x)
        }
    
        sign(x, entropy, P, msg) {
            e,r,R := Commit("", {F}, {entropy,x}, {P}, msg)
            s     := Prove(e, {r}, {x})
            return (R,s)
        }
    
        verify(R, s, P, msg) {
            e    := ChallengeHash("", {R}, {P}, msg)
            _,R’ := Recommit("", {F}, e, {s}, {P}, {}, msg)
            return group.equal(R, R’)
        }
    }


## VRF

Simple VRF maps an arbitrary-length string `msg` to a verifiably random outut keyed with public key `P`.

    protocol VRF(customlabel) {
        name        := "VRF"
        group       := "Ristretto"
        xof         := "SHAKE128"
        extralabels := {customlabel}
        
        G           := group.base
        B(P,msg)    := PointHash("", {P}, msg)
        F0(x)       := x·G
        F1(P,msg,x) := x·B(P,msg)
        
        commit(x, P, msg) {
            V := F1(P,msg,x)
            h := Compress(32, "", {V}, "")
            return h
        }
    
        sign(x, P, entropy, msg) {
            P       := F0(x)
            V       := F1(P,msg,x)
            e,r,_,_ := Commit("", {F0, F1(P,msg)}, {entropy,x}, {P,V}, msg)
            s       := Prove(e, {r}, {x})
            return (V,e,s)
        }
    
        verify((V,e,s), P, msg) {
            e’,_,_ := Recommit("", {F0, F1(P,msg)}, e, {s}, {P,V}, {}, msg)
            if e’ == e {
                h := Compress(32, "", {V}, "")
                return h
            } else {
                return nil
            }
        }
    }

## Designated Verifier VRF

This is a variant of VRF above, but with a 2-item ring signature that allows forgery by the designated verifier
identified by the key pair `D,d` (`D == d·G`).

    protocol DVRF(customlabel) {
        name        := "DVRF"
        group       := "Ristretto"
        xof         := "SHAKE128"
        extralabels := {customlabel}
        
        G           := group.base
        B(P,msg)    := PointHash("", {P}, msg)
        F0(x)       := x·G
        F1(P,msg,x) := x·B(P,msg)
        
        commit(x, P, msg) {
            V := F1(P,msg,x)
            h := Compress(32, "", {V}, "")
            return h
        }
    
        sign(D, P, x, entropy, msg) {
            P        := F0(x)
            V        := F1(P,msg,x)
            e1,r,_,_ := Commit("prove", {F0, F1(P,msg)}, {entropy,x}, {D,P,V}, msg)
            z        := ScalarHash("verifier signature forgery", {entropy,x}, {D,P,V}, msg)
            e0,_     := Recommit("forge", {F0}, e1, {z}, {D}, {P,V}, msg)
            s        := Prove(e0, {r}, {x})
            return (V,e0,s,z)
        }
    
        forge(D, P, V, d, entropy, msg) {
            e0,r,_ := Commit("forge", {F0}, {entropy,d}, {D,P,V}, msg)
            s      := ScalarHash("signer signature forgery", {entropy,d}, {D,P,V}, msg)
            e1,_,_ := Recommit("prove", {F0, F1(P,msg)}, e0, {s}, {P,V}, {D}, msg)
            z      := Prove(e1, {r}, {d})
            return (V,e0,s,z)
        }
        
        verify((V,e0,s,z), D, P, msg) {
            e1,_,_ := Recommit("prove", {F0, F1(P,msg)}, e0, {s}, {P,V}, {D}, msg)
            e’,_   := Recommit("forge", {F0}, e1, {z}, {D}, {P,V}, msg)
            if e’ == e0 {
                h := Compress(32, "", {V}, "")
                return h
            } else {
                return nil
            }
        }
    }


## Ring Signature

The following shows a ring version of Schnorr signature, but using compressed signature form (`e,s[0],...,s[n-1]`) to align with unconditionally binding commitments in the [Set Range Proof](#set-range-proof).

    protocol RingSignature(customlabel) {
        name        := "RingSignature"
        group       := "Ristretto"
        xof         := "SHAKE128"
        extralabels := {customlabel}
        
        G           := group.base
        F(x)        := x·G
        
        sign({P#n}, j, x[j], entropy, msg) {
        
            {r[0],...,r[n-1]} := ScalarHash("", {entropy, varint(j), x[j]}, {P#n}, msg)
            // all but r[0] will be used as forged s-elements
        
            // Precommit
            R            := Commit(r[0], {F})
            e[j+1 mod n] := ChallengeHash(uint64le(j), {R}, {P#n}, msg)
        
            // Forge all other elements
            for step := 1..n-1 {
                i            := (j + step) mod n
                s[i]         := r[step]  // using r[i≠0] as a forged s-element
                R            := Recommit(e[i], {s[i]}, {P[i]}, {F}) 
                e[i+1 mod n] := ChallengeHash(uint64le(i), {R}, {P#n}, msg)
            }
        
            // Sign
            s[j] := Prove(e[j], {r[0]}, {x[j]})
            return (e[0], {s[0],...,s[n-1]})
        }
    
        verify(e, {s#n}, {P#n}, msg) {
            e’ := e
            for i := 0..(n-1) {
                R := Recommit(e’, {s[i]}, {P[i]}, {F}) 
                e’:= ChallengeHash(uint64le(i), {R}, {P#n}, msg)
            }
            return e == e’
        }
    }


## Traceable Ring Signature

This is a part of the CryptoNote/Monero protocol that is effectively a ring version of VRF where the message under commitment is the public key itself.

* `G` — base point in Curve25519.
* `x` — secret scalar representing a private key.
* `P` — public key, such that `P == x·G`.
* `I` — key image, such that `I == x·PointHash(P)`.

Definition:

    protocol TraceableRingSignature(customlabel) {
        name        := "TraceableRingSignature"
        group       := "Ristretto"
        xof         := "SHAKE128"
        extralabels := {customlabel}
        
        G           := group.base
        B(P)        := PointHash({}, {P}, "")
        F0(x)       := x·G
        F1(P,x)     := x·B(P)
        
        commit(P, x) {
            I := Commit({x}, {F1(P)})
            I’:= group.encode(I)
            return I’
        }
    
        sign({P#n}, j, x[j], entropy, msg) {        
            {r#n} := ScalarHash("", {entropy, varint(j), x[j]}, {P#n}, msg)
            // all but r[0] will be used as forged s-elements
        
            // Precommit
            P[j]         := Commit({x}, {F0})
            I            := Commit({x}, {F1(P[j])})
            
            RG,RI        := Commit({r[0]}, {F0, F1(P[j])})
            e[j+1 mod n] := ChallengeHash(uint64le(j), {RG, RI}, {I, P#n...}, msg)
        
            // Forge all other elements
            for step := 1..n-1 {
                i            := (j + step) mod n
                s[i]         := r[step]  // using r[i≠0] as a forged s-element
                RG,RI        := Recommit(e[i], {s[i]}, {P[i]}, {F0,F1(P[i])}) 
                e[i+1 mod n] := ChallengeHash(uint64le(i), {RG, RI}, {I, P#n...}, msg)
            }
        
            // Sign
            s[j] := Prove(e[j], {r[0]}, {x[j]})
            return (e[0], {s[0],...,s[n-1]})
        }
    
        verify(e, {s[i]}, I’, {P#n}, msg) {
            I := group.decode(I’)
            e’ := e
            for i := 0..(n-1) {
                RG,RI := Recommit(e’, {s[i]}, {P[i]}, {F0,F1(P[i])}) 
                e’  := ChallengeHash(uint64le(i), {RG, RI}, {I, P#n...}, msg)
            }
            return e == e’
        }
    }


## Abstract Borromean Ring Signature

This is an abstract template intended for various rangeproofs. Using it standalone
is not possible because it defers the choice of the commitments being signed (`{C}`)
to the higher-level protocols (e.g. a [set range proof](#set-range-proof)) that must ensure
that none of the commitments are malleable with respect to the proof.

**Warning: this algorithm is not running in constant time.**

* `NR` — number of rings
* `NI` — number of items per ring
* `NS` — number of statements per item
* `NX` — number of secrets per item
* `t = 0..NR-1` — index of a ring
* `i = 0..NI-1` — index of an item
* `j = 0..NS-1` — index of a statement
* `k = 0..NX-1` — index of a secret within an item
* `î[t] = 0..NI-1` - secret index of a non-formed item in ring `t`
* `x[t,k]` - secret scalar for ring `t` with index `k`
* `{s[t,i,k]}` — 3-dimensional array of s-elements of size `NR·NI·NX`.
* `{P[t,i,j]}` — 3-dimensional array of commitments of size `NR·NI·NS`.
* `{C}` — array of original commitments to be signed that themselves commit to `{P[t,i,j]}` (specified by the concrete protocol).
* `{F[j]({x[k]})}` — a list of commitment functions of size `NS` over `NX` variables.

Definition:

    AbstractBRS = protocol {
        name:  ___,
        NR:    ___,
        NI:    ___,
        NS:    ___,
        NX:    ___,
        group: "Ristretto"
        xof:   "SHAKE128"
        
        sign<protocol>({x[t,k]}, {î[t]}, {P[t,i,j]}, {C}, {F[j]({x[k]})}, entropy, msg, label) {
            // Generate NR·NI·NX random scalars
            {r[t,i,k]} := ScalarHash<protocol>(label, {entropy, x[0,0],...,x[NR-1,NX-1], î[0],...,î[NR-1]}, {C}, msg)
        
            // Precommit
            for t := 0..(NR-1) {
                i := î[t]
                for j := 0..(NS-1) {
                    R[t,i,j] := F[j](r[t,i,0], ..., r[t,i,NX-1])
                }
                e[t, i+1 mod NI] := ChallengeHash<protocol>(
                                        label,
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
                                            label,
                                            {2·R[t,i,0],...,2·R[t,i,NS-1]},
                                            {C}, uint64le(t) || uint64le(i) || msg
                                        )
                }
            }
        
            // Shared challenge for all trailing items in each ring
            if NR == 1 {
                // special case for 1 ring to avoid unnecessary double-hashing
                ê := e[0,0]
            } else {
                ê := ChallengeHash<protocol>(label, {}, e[0,0] || ... || e[NR-1,0])
            }
            
        
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
                                            label,
                                            {2·R[t,i,0],...,2·R[t,i,NS-1]},
                                            {C}, uint64le(t) || uint64le(i) || msg
                                        )
                }
            }
        
            // Sign
            for t := 0..(NR-1) {
                i := î[t]
                for k := 0..(NX-1) {
                    s[t,i,k] = r[t,i,k] + x[t,k]·e[t,i] mod group.order
                }
            }
        
            return (ê, {s[t,i,k]})
        }
    
        verify<protocol>(ê, {s[t,i,k]}, {P[t,i,j]}, {C}, {F[j]({x[k]})}, label, msg) {
            for t := 0..(NR-1) {
                e[t,0] := ê
                for i := 0..(NI-1) {
                    for j := 0..(NS-1) {
                        R[t,i,j] := F[j](s[t,i,0], ..., s[t,i,NX-1]) - e[t,0]·P[t,i,j]
                    }
                    e[t, i+1 mod NI] := ChallengeHash<protocol>(
                                            label,
                                            // points are doubled to take advantage of Doppio, a batchable variant of Ristretto encoding
                                            {2·R[t,i,0],...,2·R[t,i,NS-1]},
                                            {C},
                                            uint64le(t) || uint64le(i) || msg
                                        )
                }
            }
            if NR == 1 {
                // special case for 1 ring to avoid unnecessary double-hashing
                e’ := e[0,0]
            } else {
                e’ := ChallengeHash<protocol>(label, {}, e[0,0] || ... || e[NR-1,0])
            }
            return ê == e’
        }
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

Definition:

    SetRangeProof = protocol {
        name: "SetRangeProof",
        group: "Ristretto"
        xof:   "SHAKE128"
        
        NR:   1, // rings
        NI:   N, // items
        NS:   2, // statements
        NX:   1  // secrets
    
        sign(M, î, c’, c[î], {H[i],B[i]}, entropy, msg, label) {
            G := group.base
            J := Generator("J")
        
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
            return AbstractBRS.sign(
                        {x}, {î}, 
                        {P[t,i,j]}, 
                        {H’,B’,H[0],B[0], ... H[N-1],B[N-1]}, 
                        {F[j](x)}, 
                        entropy, msg, label
                    )
        }
    
        verify(ê, {s[t,i,k]}, (H’,B’), {H[i],B[i]}, label, msg) {
            G := group.base
            J := Generator<srp>("J")
        
            // Prepare rangeproof configuration
            for i := 0..(N-1) {
                P[0,i,0] := H’ - H[i]
                P[0,i,1] := B’ - B[i]
            }
            F[0](x) := x·G
            F[1](x) := x·J
        
            // Verify
            return AbstractBRS.verify(
                        ê, {s[t,i,k]},
                        {P[t,i,j]},
                        {H’,B’,H[0],B[0], ... H[N-1],B[N-1]},
                        {F[j](x)},
                        label, msg
                    )
        }
    }



## ChainKD

ChainKD is a hierarchical key derivation (HKD) scheme inspired by BIP32.
It is not a signature scheme per-se, but reuses the existing framework for deriving keys.

ChainKD extends Schnorr public and private keys to xpubs and xprvs: extended public/private keys.
Each key is encoded with additional 32-byte string `dk` used as symmetric “derivation key”.

If the public or private key is stripped of `dk`, it cannot be used to derive or identify child keys.

    ChainKD = protocol {
        name:  "ChainKD"
        group: "Ristretto"
        xof:   "SHAKE128"
    
        generate(seed) {
            {x,dk} := ScalarHash(2, {"Generate"}, {seed}, {}, "")
            return x||dk
        }
    
        // Compute xpub for a given xprv.
        xpub(x||dk) {
            G := group.base
            P := x·G
            P’:= group.encode(P)
            return P’||dk
        }
    
        derive_xpub(P1’||dk1, selector) {
            G := group.base
            P1 := group.decode(P1’)
            {f,dk2} := ScalarHash(2, {"Derive"}, {dk1}, {P1}, selector)
            P2 := P1 + f·G
            P2’:= group.encode(P2)
            return P2’||dk2
        }
    
        derive_xprv(x1||dk1, selector) {
            G := group.base
            P1 := x1·G
            {f,dk2} := ScalarHash(2, {"Derive"}, {dk1}, {P1}, selector)
            x2 := x1 + f mod group.order
            return x2||dk2
        }
    
        derive_hardened(x||dk, selector) {
            return generate(x||dk||selector)
        }
    }

