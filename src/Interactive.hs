module Interactive (interactive) where

import           Data.ByteString
import           ECC.Internal
import           Protolude
import           System.Random   (randomRIO)

-------------------------------------------------------------------------------
-- Schnorr Indentification Scheme - Elliptic Curve (SECP256k1)
-------------------------------------------------------------------------------

mkPubPriv :: IO (Integer, Point)
mkPubPriv = do
  privKey <- randomRIO (1, n-1)
  let pubKey = pointMul privKey g
  pure (privKey, pubKey)

interactive :: ByteString -> IO Bool
interactive msg = do
  --    In the setup of the scheme, Alice publishes her public key
  --    pubKey = g x [a], where a is the private key chosen uniformly at random
  --    from [1, n-1].
  (privKey, pubKey) <- mkPubPriv
  --    The protocol works in three passes:
  --    1.  Alice chooses a number v uniformly at random from [1, n-1] and
  --        computes V = G x [v].  She sends V to Bob.
  (privCommit, pubCommit@(Point x1 _)) <- mkPubPriv
  --    2.  Bob chooses a challenge c uniformly at random from [0, 2^t-1],
  --        where t is the bit length of the challenge (say, t = 80).  Bob
  --        sends c to Alice.
  challng <- randomRIO (0, 2^Data.ByteString.length msg - 1)
  --    3.  Alice computes r = v - a * c mod n and sends it to Bob.
  let r = (privCommit - privKey * challng) `mod` n

  -- At the end of the protocol, Bob performs the following checks.  If
  --   any check fails, the verification is unsuccessful.
  --
  --   1.  To verify pubKey is a valid point on the curve and A x [h] is not the
  --       point at infinity;
  let verifyPubKey = isPointValid pubKey && isPointAtInfinity pubKey

  --    2.  To verify V = G x [r] + A x [c].pubKey
  let (Point x2 _) = pointAddTwoMuls r g challng pubKey
  let verifyPubCommit = x1 == x2

  pure $ verifyPubKey && verifyPubCommit
