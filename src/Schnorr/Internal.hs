module Schnorr.Internal where

import           Protolude                  hiding (hash)
import           Crypto.Hash
import           Crypto.Random.Types (MonadRandom)
import qualified Crypto.PubKey.ECC.Prim as ECC
import qualified Crypto.PubKey.ECC.ECDSA    as ECDSA
import qualified Crypto.PubKey.ECC.Types    as ECC
import           Crypto.Number.Serialize    (os2ip)
import qualified Data.ByteArray             as BA
import           Data.ByteString
import           Data.Monoid

import Schnorr.Curve as Curve

-- | Generate random commitment value
-- The prover keeps the random value generated safe
-- while sharing the point in the curve obtained by multiplying G * [k]
genCommitment
  :: (MonadRandom m, Curve.Curve c)
  => c
  -> ECC.Point    -- ^ Base point
  -> m (ECC.Point, Integer)
genCommitment curveName basePoint = do
  k <- ECC.scalarGenerate (Curve.curve curveName)
  let k' = Curve.pointMul curveName k basePoint
  pure (k', k)

-- | Make challenge through a Fiat-Shamir transformation.
-- The challenge is then defined as `H(g || V || A)`,
-- where `H` is a secure cryptographic hash function (SHA-256).
genChallenge
  :: Curve.Curve c
  => c
  -> ECC.Point      -- ^ Base point
  -> ECC.Point      -- ^ Public key
  -> ECC.Point      -- ^ Public commitment
  -> Integer
genChallenge curveName basePoint pubKey pubCommit
  = genChallengeWithMsg curveName basePoint pubKey pubCommit ""

-- | Generate a challenge defined as `H(g || V || A || msg)`
genChallengeWithMsg
  :: Curve c
  => c
  -> ECC.Point
  -> ECC.Point
  -> ECC.Point
  -> ByteString
  -> Integer
genChallengeWithMsg curveName basePoint pubKey pubCommit msg
  = oracle curveName (gxy <> cxy <> pxy <> msg)
  where
    gxy = appendCoordinates basePoint
    cxy = appendCoordinates pubCommit
    pxy = appendCoordinates pubKey

-- | Compute response from previous generated values:
-- private commitment value, prover's private key and verifier's challenge
computeResponse
  :: Curve.Curve c
  => c
  -> Integer -- ^ Private commitment
  -> Integer -- ^ Private key
  -> Integer -- ^ Challenge
  -> Integer
computeResponse curveName privCommit sk challenge =
  (privCommit - sk * challenge) `mod` Curve.n curveName

-- | A “random oracle” is considered to be a black box that
-- outputs unpredictable but deterministic random values in
-- response to input. That means that, if you give it the same
-- input twice, it will give back the same random output.
-- The input to the random oracle, in the Fiat-Shamir heuristic,
-- is specifically the transcript of the interaction up to that point.
oracle :: Curve.Curve c => c -> ByteString -> Integer
oracle curveName x = os2ip (sha256 x) `mod` Curve.n curveName

-- | Secure cryptographic hash function
sha256 :: ByteString -> ByteString
sha256 bs = BA.convert (hash bs :: Digest SHA3_256)

-- | Append coordinates to create a hashable type.
-- It will be used in the protocol to make the challenge
appendCoordinates :: ECC.Point -> ByteString
appendCoordinates ECC.PointO      = ""
appendCoordinates (ECC.Point x y) = show x <> show y

