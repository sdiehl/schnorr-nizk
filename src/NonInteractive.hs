-- | Non interactive variant of the Schnorr protocol
--
-- >>> (pubKey, privKey) <- generateKeys -- prover
-- >>> (pubCommit, privCommit) <- generateCommitment -- prover
-- >>> let challenge = mkChallenge pubKey pubCommit
-- >>> let r = computeResponse privCommit privKey challenge -- prover
-- >>> verify pubKey pubCommit challenge r -- verifier
-- True
module NonInteractive
  ( testProof
  , mkChallenge
  ) where

import           Protolude                  hiding (hash)
import           Crypto.Hash
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import           Crypto.PubKey.ECC.Types

import           Crypto.Number.Serialize    (os2ip)
import qualified Data.ByteArray             as BA

import           Data.ByteString
import           Data.Monoid

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
