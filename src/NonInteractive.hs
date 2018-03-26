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

-- | Append coordinates to create a hashable type.
-- It will be used in the protocol to make the challenge
appendCoordinates :: Point -> ByteString
appendCoordinates PointO      = ""
appendCoordinates (Point x y) = show x <> show y

-- | Make challenge through a Fiat-Shamir transformation.
-- The challenge is then defined as `H(g || V || A)`,
-- where `H` is a secure cryptographic hash function (SHA-256).
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
