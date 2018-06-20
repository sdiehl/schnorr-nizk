module Schnorr
  ( generateCommitment
  , computeResponse
  , verify

  , mkChallenge
  , generateChallenge
  ) where

import           Crypto.Hash
import           Crypto.Number.Generate     (generateMax)
import           Crypto.Random.Types (MonadRandom)
import           Crypto.Number.Serialize    (os2ip)
import qualified Crypto.PubKey.ECC.ECDSA    as ECDSA
import qualified Crypto.PubKey.ECC.Generate as ECC
import qualified Crypto.PubKey.ECC.Prim     as ECC
import qualified Crypto.PubKey.ECC.Types    as ECC
import qualified Data.ByteString            as BS
import           Data.Monoid
import           Protolude

import qualified Curve
import NonInteractive (mkChallenge)
import Interactive (generateChallenge)

-----------------------------------------------------
-- Schnorr Indentification Scheme - Elliptic Curve
-----------------------------------------------------

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
  privCommit - sk * challenge `mod` Curve.n curveName

-- | Verify proof given by the prover.
-- It receives a public key, a commitment, a challenge and a response value.
verify
  :: Curve.Curve c
  => c
  -> ECC.Point          -- ^ Base point
  -> ECC.Point          -- ^ Public key
  -> ECC.Point          -- ^ Public commitment
  -> Integer            -- ^ Challenge
  -> Integer            -- ^ Response
  -> Bool
verify curveName basePoint pubKey pubCommit challenge r =
  verifyPubKey && verifyPubCommit
  where
    validPoint = Curve.isPointValid curveName pubKey
    infinity = Curve.isPointAtInfinity curveName $
      Curve.pointMul curveName h pubKey
    verifyPubKey = validPoint && not infinity
    t = Curve.pointAddTwoMuls curveName r basePoint challenge pubKey
    verifyPubCommit = pubCommit == t
    curve = Curve.curve curveName
    h = Curve.h curveName

-- | Generate random commitment value
-- The prover keeps the random value generated safe
-- while sharing the point in the curve obtained by multiplying G * [k]
generateCommitment
  :: (MonadRandom m, Curve.Curve c)
  => c
  -> ECC.Point    -- ^ Base point
  -> m (ECC.Point, Integer)
generateCommitment curveName basePoint = do
  k <- generateMax (Curve.n curveName - 1)
  let k' = Curve.pointMul curveName k basePoint
  pure (k', k)
