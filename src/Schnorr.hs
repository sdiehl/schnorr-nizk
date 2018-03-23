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

generateKeys :: IO (ECDSA.PublicKey, ECDSA.PrivateKey)
generateKeys = generate secp256k1

generateChallenge :: ByteString -> IO Challenge
generateChallenge msg = generateBetween 0  (2^BS.length msg - 1)

computeResponse :: Integer -> ECDSA.PrivateKey -> Challenge -> Response
computeResponse pc pk challenge = pc - ECDSA.private_d pk * challenge `mod` n

-- Given a public key, a commitment, a challenge and a response value, verify the proof
verify :: ECDSA.PublicKey -> Point -> Challenge -> Response -> Bool
verify pubKey pubCommit challenge r = verifyPubKey && verifyPubCommit
  where
    verifyPubKey = isPointValid secp256k1 (ECDSA.public_q pubKey)
        && not (isPointAtInfinity $ pointMul secp256k1 h (ECDSA.public_q pubKey))
    t = pointAddTwoMuls secp256k1 r g challenge (ECDSA.public_q pubKey)
    verifyPubCommit = pubCommit == t

oracle :: ByteString -> Integer
oracle x = os2ip (sha256 x) `mod` n

sha256 :: ByteString -> ByteString
sha256 bs = BA.convert (hash bs :: Digest SHA3_256)

generateCommit :: IO (Point, Integer)
generateCommit = do
  k <- generateBetween 0 (n-1)
  let k' = pointBaseMul secp256k1 k
  pure (k', k)
