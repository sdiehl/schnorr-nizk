module Interactive
  ( generateKeys
  , generateCommit
  , generateChallenge
  , computeResponse
  , verify
  ) where

import           Protolude

import           Data.ByteString            as BS

import qualified Crypto.Hash                as Hash
import qualified Crypto.PubKey.ECC.ECDSA    as ECDSA

import qualified Crypto.PubKey.ECC.Generate as ECC
import qualified Crypto.PubKey.ECC.Prim     as ECC
import qualified Crypto.PubKey.ECC.Types    as ECC
import           System.Random              (randomRIO)

type PrivateCommit = ECDSA.PrivateKey
type PublicCommit = ECDSA.PublicKey

type Challenge = Integer
type Response = Integer

secp256k1 :: ECC.Curve
secp256k1 = ECC.getCurveByName ECC.SEC_p256k1

generateKeys :: IO (ECDSA.PublicKey, ECDSA.PrivateKey)
generateKeys = ECC.generate secp256k1

generateCommit :: IO (PublicCommit, PrivateCommit)
generateCommit = generateKeys

generateChallenge :: ByteString -> IO Challenge
generateChallenge msg = randomRIO (0, 2^BS.length msg - 1)

computeResponse :: PrivateCommit -> ECDSA.PrivateKey -> Challenge -> Response
computeResponse pc pk challenge =
  ECDSA.private_d pc - ECDSA.private_d pk * challenge `mod` n
  where
    n = ECC.ecc_n $ ECC.common_curve secp256k1

verify :: PublicCommit -> ECDSA.PublicKey -> Challenge -> Response -> Bool
verify pubCommit pubKey challenge r = verifyPubKey && verifyPubCommit
  where
    verifyPubKey = ECC.isPointValid secp256k1 (ECDSA.public_q pubKey)
        && not (ECC.isPointAtInfinity $ ECC.pointMul secp256k1 h (ECDSA.public_q pubKey))
    t = ECC.pointAddTwoMuls secp256k1 r g challenge (ECDSA.public_q pubKey)
    verifyPubCommit = ECDSA.public_q pubCommit == t
    n = ECC.ecc_n cc
    g = ECC.ecc_g cc
    h = ECC.ecc_h cc
    cc = ECC.common_curve secp256k1

-------------------------------------------------------------------------------
-- Schnorr Indentification Scheme - Elliptic Curve (SECP256k1)
-------------------------------------------------------------------------------

interactive :: ByteString -> IO Bool
interactive msg = do
  --    In the setup of the scheme, Alice publishes her public key
  --    pubKey = g x [a], where a is the private key chosen uniformly at random
  --    from [1, n-1].
  (pubKey, privKey) <- generateKeys
  --    The protocol works in three passes:
  --    1.  Alice chooses a number v uniformly at random from [1, n-1] and
  --        computes V = G x [v].  She sends V to Bob.
  (pubCommit, privCommit) <- generateCommit
  --    2.  Bob chooses a challenge c uniformly at random from [0, 2^t-1],
  --        where t is the bit length of the challenge (say, t = 80).  Bob
  --        sends c to Alice.
  challenge <- generateChallenge msg
  --    3.  Alice computes r = v - a * c mod n and sends it to Bob.
  let r = computeResponse privCommit privKey challenge

  -- At the end of the protocol, Bob performs the following checks.  If
  --   any check fails, the verification is unsuccessful.
  pure $ verify pubCommit pubKey challenge r
