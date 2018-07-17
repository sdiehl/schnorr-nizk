{-# LANGUAGE RecordWildCards #-}
module Schnorr
  ( prove
  , verify
  , Curve.SECCurve(..)
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

import qualified Schnorr.Curve as Curve
import Schnorr.Internal

-----------------------------------------------------
-- Schnorr Indentification Scheme - Elliptic Curve
-----------------------------------------------------

data NIZK
  = NIZK
    { t :: ECC.Point
    , c :: Integer
    , s :: Integer
    }

-- | Verify proof given by the prover.
verify
  :: Curve.Curve c
  => c
  -> ECC.Point          -- ^ Base point
  -> ECC.Point          -- ^ Public key
  -> NIZK
  -> Bool
verify curveName basePoint pk NIZK{..} =
  verifyPubKey && verifyPubCommit
  where
    validPoint = Curve.isPointValid curveName pk
    infinity = Curve.isPointAtInfinity curveName $
      Curve.pointMul curveName h pk
    verifyPubKey = validPoint && not infinity
    t' = Curve.pointAddTwoMuls curveName s basePoint c pk
    verifyPubCommit = t == t'
    curve = Curve.curve curveName
    h = Curve.h curveName

prove
  :: (MonadRandom m, Curve.Curve c)
  => c
  -> ECC.Point
  -> (ECC.Point, Integer)
  -> m NIZK
prove curveName basePoint (pk, sk) = do
  (pubCommit, privCommit) <- genCommitment curveName basePoint
  let challenge = genChallenge curveName basePoint pk pubCommit
      resp = computeResponse curveName privCommit sk challenge
  pure NIZK
    { t = pubCommit
    , c = challenge
    , s = resp
    }


