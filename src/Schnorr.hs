{-# LANGUAGE RecordWildCards #-}
module Schnorr
  ( prove
  , verify
  , sign
  , verifySignature
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
import           Protolude

import Schnorr.Curve as Curve
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

-- | Verify a proof of knowledge of a discrete log.
verify
  :: Curve c
  => c
  -> ECC.Point          -- ^ Base point
  -> ECC.Point          -- ^ Public key
  -> NIZKProof          -- ^ Proof of knowledge
  -> Bool
verify curveName basePoint pk NIZKProof{..} =
  checkPubKey && checkPubCommit && checkChallenge
  where
    checkPubKey = validPoint && not infinityPoint
    checkPubCommit = t == Curve.pointAddTwoMuls curveName s basePoint c pk
    checkChallenge = c == genChallenge curveName basePoint pk t

    validPoint = Curve.isPointValid curveName pk
    infinityPoint = Curve.isPointAtInfinity curveName $
      Curve.pointMul curveName (Curve.h curveName) pk

-- Generate a proof of knowledge of a discrete log
prove
  :: (MonadRandom m, Curve c)
  => c
  -> ECC.Point              -- ^ Base point
  -> (ECC.Point, Integer)   -- ^ Public and private key
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

-- Sign a message with a private key
sign
  :: (MonadRandom m, Curve c)
  => c
  -> ECC.Point              -- ^ Base point
  -> (ECC.Point, Integer)   -- ^ Public and private key
  -> ByteString             -- ^ Message to be signed
  -> m Schnorr.NIZKProof
sign curveName basePoint (pk, sk) msg = do
  (pubCommit, privCommit) <- genCommitment curveName basePoint
  let challenge = genChallengeWithMsg curveName basePoint pk pubCommit msg
      resp = computeResponse curveName privCommit sk challenge
  pure Schnorr.NIZKProof
    { t = pubCommit
    , c = challenge
    , s = resp
    }

-- Verify a signature against a message
verifySignature
  :: Curve c
  => c
  -> ECC.Point          -- ^ Base point
  -> ECC.Point          -- ^ Public key
  -> ByteString         -- ^ Message
  -> Schnorr.NIZKProof  -- ^ Signature
  -> Bool
verifySignature curveName basePoint pk msg Schnorr.NIZKProof{..}
  = checkPubKey && checkPubCommit && checkChallenge
  where
    checkPubKey = validPointPk && not infinityPk
    checkPubCommit = t == Curve.pointAddTwoMuls curveName s basePoint c pk
    checkChallenge = c == genChallengeWithMsg curveName basePoint pk t msg

    validPointPk = Curve.isPointValid curveName pk
    infinityPk = Curve.isPointAtInfinity curveName $
      Curve.pointMul curveName (Curve.h curveName) pk
