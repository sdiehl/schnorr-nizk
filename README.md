<p align="center">
<a href="https://www.adjoint.io">
  <img width="250" src="./.assets/adjoint.png" alt="Adjoint Logo" />
</a>
</p>

[![CircleCI](https://circleci.com/gh/adjoint-io/schnorr-nizk.svg?style=svg)](https://circleci.com/gh/adjoint-io/schnorr-nizk)

The purpose of the Schnorr protocol is to allow one to prove the knowledge of a discrete logarithm without revealing its value.

## Schnorr Identification Scheme

The Schnorr protocol is an example of a Sigma protocol (<img src="/tex/813cd865c037c89fcdc609b25c465a05.svg?invert_in_darkmode&sanitize=true" align=middle width=11.87217899999999pt height=22.465723500000017pt/>-protocol).  A
Sigma protocol is a three-step protocol in which communication between prover
and verifier goes forwards once, then backwards, then forwards again.  In
general terms:

- <img src="/tex/ea9c178cb3769c43630d811b78f1ed05.svg?invert_in_darkmode&sanitize=true" align=middle width=51.64940879999999pt height=22.465723500000017pt/>:  commitment
- <img src="/tex/de16f2f1965b4e18fbb4e0789817fa67.svg?invert_in_darkmode&sanitize=true" align=middle width=51.649405499999986pt height=22.465723500000017pt/>:  challenge
- <img src="/tex/ea9c178cb3769c43630d811b78f1ed05.svg?invert_in_darkmode&sanitize=true" align=middle width=51.64940879999999pt height=22.465723500000017pt/>:  response (proof)

The protocol is defined for a cyclic group of order <img src="/tex/55a049b8f161ae7cfeb0197d75aff967.svg?invert_in_darkmode&sanitize=true" align=middle width=9.86687624999999pt height=14.15524440000002pt/>.

The prover aims to convince the verifier that he knows some private value <img src="/tex/44bc9d542a92714cac84e01cbbb7fd61.svg?invert_in_darkmode&sanitize=true" align=middle width=8.68915409999999pt height=14.15524440000002pt/>.
Therefore, <img src="/tex/e9038b8ddce37b94004bf4faad6e7264.svg?invert_in_darkmode&sanitize=true" align=middle width=77.37262994999999pt height=24.65753399999998pt/> (see [1]) will be her public key. In order to prove
knowledge of it, the prover interacts with the verifier in three passes:

- The prover commits to a random private value <img src="/tex/6c4adbc36120d62b98deef2a20d5d303.svg?invert_in_darkmode&sanitize=true" align=middle width=8.55786029999999pt height=14.15524440000002pt/>, chosen in the range <img src="/tex/7e0d17922ebb7f7727c61c114a4a6e86.svg?invert_in_darkmode&sanitize=true" align=middle width=62.83481819999999pt height=24.65753399999998pt/>. This is the first message commitment <img src="/tex/4995c46ed6c126a9e551683efedeb34a.svg?invert_in_darkmode&sanitize=true" align=middle width=71.51835075pt height=24.65753399999998pt/>.

- The verifier replies with a `challenge` chosen at random from <img src="/tex/8a1f3cd6b928ebf50788855d5a539172.svg?invert_in_darkmode&sanitize=true" align=middle width=66.97483814999998pt height=26.085962100000025pt/>.

- After receiving the `challenge`, the prover sends the third and last message
  (the response) <img src="/tex/ef26fb18eebe8a0219cbc89c6bbf5a31.svg?invert_in_darkmode&sanitize=true" align=middle width=151.2327135pt height=24.65753399999998pt/>.

The verifier accepts, if:

- The prover's public key, <img src="/tex/df5a289587a2f0247a5b97c1e8ac58ca.svg?invert_in_darkmode&sanitize=true" align=middle width=12.83677559999999pt height=22.465723500000017pt/>, is a valid public key. It means that it must be
  a valid point on the curve and <img src="/tex/44503004471f3ac6ef45826b069d0fa8.svg?invert_in_darkmode&sanitize=true" align=middle width=43.31231684999999pt height=24.65753399999998pt/> is not a point at infinity, where
  <img src="/tex/2ad9d098b937e46f9f58968551adac57.svg?invert_in_darkmode&sanitize=true" align=middle width=9.47111549999999pt height=22.831056599999986pt/> is the cofactor of the curve.
- The prover's commitment value is equal to <img src="/tex/082bdfdbb1bf27bb2ca138de799dfa4c.svg?invert_in_darkmode&sanitize=true" align=middle width=102.84822569999999pt height=24.65753399999998pt/>

## Zero Knowledge Proofs

Zero knowledge proofs are a way by which one party succeeds in convincing
another party that she knows a private value <img src="/tex/332cc365a4987aacce0ead01b8bdcc0b.svg?invert_in_darkmode&sanitize=true" align=middle width=9.39498779999999pt height=14.15524440000002pt/> without exposing any information
apart from the fact that she knows the value <img src="/tex/332cc365a4987aacce0ead01b8bdcc0b.svg?invert_in_darkmode&sanitize=true" align=middle width=9.39498779999999pt height=14.15524440000002pt/>.

All proof systems have two requirements:

- **Completeness**: An honest verifier will be convinced of this fact by an
  untrusted prover.

- **Soundness**: No prover, even if it doesn't follow the protocol, can convince
  the honest verifier that it is true, except with some small probability.

It is assumed that the verifier is always honest.

## Schnorr NIZK proof

The original Schnorr identification scheme is made non-interactive through a
Fiat-Shamir transformation, assuming that there exists a secure cryptographic
hash function (i.e., the so-called random oracle model).

An oracle is considered to be a black box that outputs unpredictable but
deterministic random values in response to a certain input. That means that,
given the same input, the oracle will give back the same random output. The
input to the random oracle, in the Fiat-Shamir heuristic, is specifically the
transcript of the interaction up to that point. The challenge is then redefined
as <img src="/tex/5f5e107456684cb7b813d5d45237d144.svg?invert_in_darkmode&sanitize=true" align=middle width=125.5208361pt height=24.65753399999998pt/>, where <img src="/tex/7b9a0316a2fcd7f01cfd556eedf72e96.svg?invert_in_darkmode&sanitize=true" align=middle width=14.99998994999999pt height=22.465723500000017pt/> is a secure cryptographic hash
function like SHA-256. The bit length of the hash output should be at least
equal to that of the order <img src="/tex/55a049b8f161ae7cfeb0197d75aff967.svg?invert_in_darkmode&sanitize=true" align=middle width=9.86687624999999pt height=14.15524440000002pt/> of the considered subgroup.

An example of the Schnorr protocol for Non-Interactive Zero-Knowledge Proofs
looks as follows.

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
  pure (Schnorr.verify curveName basePoint pk proof)
```

## Curves

This Schnorr implementation offers support for both SECP256k1 and Curve25519
curves, which are Koblitz and Montgomery curves, respectively.

* SECP256k1
* Curve25519

**References**:

1.  Hao, F. "Schnorr Non-interactive Zero-Knowledge Proof." Newcastle University, UK, 2017
2. Schnorr Non-interactive Zero-Knowledge Proof [https://tools.ietf.org/html/rfc8235](https://tools.ietf.org/html/rfc8235)

**Notation**:

1. <img src="/tex/b38c1f3a84b4eb88f169638e34cb23b0.svg?invert_in_darkmode&sanitize=true" align=middle width=40.89599744999999pt height=24.65753399999998pt/> : multiplication of a point <img src="/tex/df5a289587a2f0247a5b97c1e8ac58ca.svg?invert_in_darkmode&sanitize=true" align=middle width=12.83677559999999pt height=22.465723500000017pt/> with a scalar <img src="/tex/4bdc8d9bcfb35e1c9bfb51fc69687dfc.svg?invert_in_darkmode&sanitize=true" align=middle width=7.054796099999991pt height=22.831056599999986pt/> over an elliptic
   curve defined over a finite field modulo a prime number

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
