module Schnorr
  ( generateKeys
  , generateCommit
  , generateChallenge
  , computeResponse
  , verify
  , oracle
  ) where

import           Crypto.Hash
import           Crypto.Number.Generate     (generateBetween)
import           Crypto.Number.Serialize    (os2ip)
import qualified Crypto.PubKey.ECC.ECDSA    as ECDSA
import           Crypto.PubKey.ECC.Generate
import           Crypto.PubKey.ECC.Prim
import           Crypto.PubKey.ECC.Types
import qualified Data.ByteArray             as BA
import           Data.ByteString            as BS
import           Data.Monoid
import           Protolude                  hiding (hash)

import           Curve

-------------------------------------------------------------------------------
-- Schnorr Indentification Scheme - Elliptic Curve (SECP256k1)
-------------------------------------------------------------------------------

type Challenge = Integer
type Response = Integer
type Commitment = Point

-- | Generate public and private keys
generateKeys :: IO (ECDSA.PublicKey, ECDSA.PrivateKey)
generateKeys = generate secp256k1

-- | Generate random commitment value
-- The prover keeps the random value generated safe
-- while sharing the point in the curve obtained by multiplying G * [k]
generateCommitment :: IO (Commitment, Integer)
generateCommitment = do
  k <- generateBetween 0 (n-1)
  let k' = pointBaseMul secp256k1 k
  pure (k', k)

-- | Generate challenge from a given message
generateChallenge :: ByteString -> IO Challenge
generateChallenge msg = generateBetween 0  (2^BS.length msg - 1)

-- | Compute response from previous generated values:
-- private commitment value, prover's private key and verifier's challenge
computeResponse :: Integer -> ECDSA.PrivateKey -> Challenge -> Response
computeResponse pc pk challenge = pc - ECDSA.private_d pk * challenge `mod` n

-- Verify proof given by the prover.
-- It receives a public key, a commitment, a challenge and a response value.
verify :: ECDSA.PublicKey -> Commitment -> Challenge -> Response -> Bool
verify pubKey pubCommit challenge r = verifyPubKey && verifyPubCommit
  where
    verifyPubKey = isPointValid secp256k1 (ECDSA.public_q pubKey)
        && not (isPointAtInfinity $ pointMul secp256k1 h (ECDSA.public_q pubKey))
    t = pointAddTwoMuls secp256k1 r g challenge (ECDSA.public_q pubKey)
    verifyPubCommit = pubCommit == t

-- | A “random oracle” is considered to be a black box that
-- outputs unpredictable but deterministic random values in
-- response to input. That means that, if you give it the same
-- input twice, it will give back the same random output.
-- The input to the random oracle, in the Fiat-Shamir heuristic,
-- is specifically the transcript of the interaction up to that point.
oracle :: ByteString -> Integer
oracle x = os2ip (sha256 x) `mod` n

-- | Secure cryptographic hash function
sha256 :: ByteString -> ByteString
sha256 bs = BA.convert (hash bs :: Digest SHA3_256)
