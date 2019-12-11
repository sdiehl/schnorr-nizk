<p align="center">
<a href="https://www.adjoint.io">
  <img width="250" src="./.assets/adjoint.png" alt="Adjoint Logo" />
</a>
</p>

[![CircleCI](https://circleci.com/gh/adjoint-io/schnorr-nizk.svg?style=svg)](https://circleci.com/gh/adjoint-io/schnorr-nizk)

The purpose of the Schnorr protocol is to allow one to prove the knowledge of a discrete logarithm without revealing its value.

## Schnorr Identification Scheme

The Schnorr protocol is an example of a Sigma protocol.
A Sigma protocol is a three-step protocol in which communication between prover and verifier goes forwards once, then backwards, then forwards again.
In general terms:

- `P  ->  V`:  commitment
- `V  ->  P`:  challenge
- `P  ->  V`:  response (proof)

The protocol is defined for a cyclic group of order `n`.

The prover aims to convince the verifier that he knows some private value `a`. Therefore, `P = G * [a]`**[1]** will be her public key. In order to prove knowledge of it, the prover interacts with the verifier in three passes:

- The prover commits to a random private value `v`, chosen in the range `[1, n-1]`. This is the first message `commitment = G * [v]`.

- The verifier replies with a `challenge` chosen at random from `[0, 2^t - 1]`.

- After receiving the `challenge`, the prover sends the third and last message (the response) `resp = (v - challenge * a) mod n`.

The verifier accepts, if:
- The prover's public key, `P`, is a valid public key. It means that it must be a valid point on the curve and `P * [h]` is not a point at infinity, where `h` is the cofactor of the curve.

- The prover's commitment value is equal to `G * [r] + P * [challenge]`

## Zero Knowledge Proofs

Zero knowledge proofs are a way by which one party succeeds in convincing another party that she knows a private value x without exposing any information apart from the fact that she knows the value x.

All proof systems have two requirements:

- **Completeness**: An honest verifier will be convinced of this fact by an untrusted prover.

- **Soundness**: No prover, even if it doesn't follow the protocol, can convince the honest verifier that it is true, except with some small probability.

It is assumed that the verifier is always honest.


## Schnorr NIZK proof

The original Schnorr identification scheme is made non-interactive through a Fiat-Shamir transformation, assuming that there exists a secure cryptographic hash function (i.e., the so-called random oracle model).

An oracle is considered to be a black box that outputs unpredictable but deterministic random values in response to a certain input. That means that, given the same input, the oracle will give back the same random output. The input to the random oracle, in the Fiat-Shamir heuristic, is specifically the transcript of the interaction up to that point. The challenge is then redefined as `challenge = H(g || V || A)`, where `H` is a secure cryptographic hash function like SHA-256. The bit length of the hash output should be at least equal to that of the order `n` of the considered subgroup.

An example of the Schnorr protocol for Non-Interactive Zero-Knowledge Proofs looks as follows.

```haskell

testSchnorrNIZK :: IO Bool
testSchnorrNIZK = do
  -- Setup
  let curveName = Curve25519
      basePoint = Curve.g curveName
  keyPair@(pk, sk) <- genKeys curveName basePoint

  -- Prover
  proof <- Schnorr.prove curveName basePoint keyPair

  -- Verifier
  pure $ Schnorr.verify curveName basePoint pk proof

```

## Curves

This Schnorr implementation offers support for both SECp256k1 and Curve25519 curves,
which are Koblitz and Montgomery curves, respectively.

* SECP256k1
* Curve25519

**References**:

1.  Hao, F. "Schnorr Non-interactive Zero-Knowledge Proof." Newcastle University, UK, 2017
2. Schnorr Non-interactive Zero-Knowledge Proof [https://tools.ietf.org/html/rfc8235](https://tools.ietf.org/html/rfc8235)

**Notation**:

1. `P * [b]`: multiplication of a point P with a scalar b over an elliptic curve defined over a finite field modulo a prime number

## Disclaimer

This is experimental code meant for research-grade projects only. Please do not
use this code in production until it has matured significantly.

## License

```
Copyright 2018-2020 Adjoint Inc

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
