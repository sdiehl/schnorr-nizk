module NonInteractive
  ( testProof
  , mkChallenge
  ) where

import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import           Crypto.PubKey.ECC.Types
import           Data.ByteString
import           Data.Monoid
import           Protolude

import           Curve
import           Schnorr

appendCoordinates :: Point -> ByteString
appendCoordinates PointO      = ""
appendCoordinates (Point x y) = show x <> show y

mkChallenge :: ECDSA.PublicKey -> Point -> Integer
mkChallenge pubKey pubCommit = oracle (gxy <> cxy <> pxy)
  where
    gxy = appendCoordinates g
    cxy = appendCoordinates pubCommit
    pxy = (appendCoordinates . ECDSA.public_q) pubKey

testProof :: IO Bool
testProof = do
  (pubKey, privKey) <- generateKeys
  (pubCommit, privCommit) <- generateCommit
  let challenge = mkChallenge pubKey pubCommit
  let r = computeResponse privCommit privKey challenge
  pure $ verify pubKey pubCommit challenge r
