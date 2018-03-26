module Schnorr
  ( Challenge
  , Response
  , PublicCommitment
  , PrivateCommitment
  , generateKeys
  , generateCommitment
  , computeResponse
  , verify
  ) where

import           Crypto.Hash
import           Crypto.Number.Generate     (generateBetween)
import           Crypto.Random.Types (MonadRandom)
import           Crypto.Number.Serialize    (os2ip)
import qualified Crypto.PubKey.ECC.ECDSA    as ECDSA
import           Crypto.PubKey.ECC.Generate
import           Crypto.PubKey.ECC.Prim
import           Crypto.PubKey.ECC.Types
import           Data.ByteString            as BS
import           Data.Monoid
import           Protolude                  hiding (hash)

import qualified Curve

-------------------------------------------------------------------------------
-- Schnorr Indentification Scheme - Elliptic Curve (SECP256k1)
-------------------------------------------------------------------------------

type Challenge = Integer
type Response = Integer
type PublicCommitment = Point
type PrivateCommitment = Integer

-- | Generate public and private keys
generateKeys :: MonadRandom m => m (ECDSA.PublicKey, ECDSA.PrivateKey)
generateKeys = generate Curve.secp256k1

-- | Compute response from previous generated values:
-- private commitment value, prover's private key and verifier's challenge
computeResponse :: PrivateCommitment -> ECDSA.PrivateKey -> Challenge -> Response
computeResponse pc pk challenge = pc - ECDSA.private_d pk * challenge `mod` Curve.n

-- | Verify proof given by the prover.
-- It receives a public key, a commitment, a challenge and a response value.
verify :: ECDSA.PublicKey -> PublicCommitment -> Challenge -> Response -> Bool
verify pubKey pubCommit challenge r = verifyPubKey && verifyPubCommit
  where
    verifyPubKey = isPointValid Curve.secp256k1 (ECDSA.public_q pubKey)
        && not (isPointAtInfinity $ pointMul Curve.secp256k1 Curve.h (ECDSA.public_q pubKey))
    t = pointAddTwoMuls Curve.secp256k1 r Curve.g challenge (ECDSA.public_q pubKey)
    verifyPubCommit = pubCommit == t

-- | Generate random commitment value
-- The prover keeps the random value generated safe
-- while sharing the point in the curve obtained by multiplying G * [k]
generateCommitment :: MonadRandom m => m (PublicCommitment, PrivateCommitment)
generateCommitment = do
  k <- generateBetween 0 (Curve.n-1)
  let k' = pointBaseMul Curve.secp256k1 k
  pure (k', k)
