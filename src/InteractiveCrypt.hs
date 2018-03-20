module InteractiveCrypt where

import           Protolude

import           Data.ByteString

import qualified Crypto.Hash                as Hash
import qualified Crypto.PubKey.ECC.ECDSA    as ECDSA

import qualified Crypto.PubKey.ECC.Generate as ECC
import qualified Crypto.PubKey.ECC.Prim     as ECC
import qualified Crypto.PubKey.ECC.Types    as ECC
import           System.Random              (randomRIO)

secp256k1 :: ECC.Curve
secp256k1 = ECC.getCurveByName ECC.SEC_p256k1

generate :: IO (ECDSA.PublicKey, ECDSA.PrivateKey)
generate = ECC.generate secp256k1

generateChallenge :: ByteString -> IO Integer
generateChallenge msg = randomRIO (0, 2^Data.ByteString.length msg - 1)
-------------------------------------------------------------------------------
-- Schnorr Indentification Scheme - Elliptic Curve (SECP256k1)
-------------------------------------------------------------------------------

interactive :: ByteString -> IO Bool
interactive msg = do
  --    In the setup of the scheme, Alice publishes her public key
  --    pubKey = g x [a], where a is the private key chosen uniformly at random
  --    from [1, n-1].
  (pubKey, privKey) <- generate
  --    The protocol works in three passes:
  --    1.  Alice chooses a number v uniformly at random from [1, n-1] and
  --        computes V = G x [v].  She sends V to Bob.
  (pubCommit, privCommit) <- generate
  --    2.  Bob chooses a challenge c uniformly at random from [0, 2^t-1],
  --        where t is the bit length of the challenge (say, t = 80).  Bob
  --        sends c to Alice.
  challng <- generateChallenge msg
  --    3.  Alice computes r = v - a * c mod n and sends it to Bob.
  let r = ECDSA.private_d privCommit - ECDSA.private_d privKey * challng `mod` n

  -- At the end of the protocol, Bob performs the following checks.  If
  --   any check fails, the verification is unsuccessful.
  --
  --   1.  To verify pubKey is a valid point on the curve and A x [h] is not the
  --       point at infinity;
  let verifyPubKey = ECC.isPointValid secp256k1 (ECDSA.public_q pubKey)
                   && ECC.isPointAtInfinity (ECDSA.public_q pubKey)
  --    2.  To verify V = G x [r] + A x [c].pubKey
  let t = ECC.pointAddTwoMuls secp256k1 r g challng (ECDSA.public_q pubKey)
  let verifyPubCommit = ECDSA.public_q pubCommit == t

  pure $ verifyPubKey && verifyPubCommit

  where
      n = ECC.ecc_n cc
      g = ECC.ecc_g cc
      cc = ECC.common_curve secp256k1
