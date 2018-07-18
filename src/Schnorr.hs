{-# LANGUAGE RecordWildCards #-}
module Schnorr
  ( prove
  , verify
  , Curve.SECCurve(..)
  , Curve.Curve25519(..)
  , NIZKProof(..)
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

data NIZKProof
  = NIZKProof
    { t :: ECC.Point
    , c :: Integer
    , s :: Integer
    } deriving (Show, Eq)

-- | Verify proof given by the prover.
verify
  :: Curve.Curve c
  => c
  -> ECC.Point          -- ^ Base point
  -> ECC.Point          -- ^ Public key
  -> NIZKProof
  -> Bool
verify curveName basePoint pk NIZKProof{..} =
  checkPubKey && checkPubCommit && checkChallenge
  where
    checkPubKey = validPoint && not infinity
    checkPubCommit = t == Curve.pointAddTwoMuls curveName s basePoint c pk
    checkChallenge = c == genChallenge curveName basePoint pk t

    validPoint = Curve.isPointValid curveName pk
    infinity = Curve.isPointAtInfinity curveName $
      Curve.pointMul curveName h pk
    h = Curve.h curveName

prove
  :: (MonadRandom m, Curve.Curve c)
  => c
  -> ECC.Point
  -> (ECC.Point, Integer)
  -> m NIZKProof
prove curveName basePoint (pk, sk) = do
  (pubCommit, privCommit) <- genCommitment curveName basePoint
  let challenge = genChallenge curveName basePoint pk pubCommit
      resp = computeResponse curveName privCommit sk challenge
  pure NIZKProof
    { t = pubCommit
    , c = challenge
    , s = resp
    }


