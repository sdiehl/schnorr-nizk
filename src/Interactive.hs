module Interactive
  ( testProof
  ) where

import qualified Data.ByteString as BS
import           Protolude

import           Schnorr

testProof :: IO Bool
testProof = do
  (pubKey, privKey) <- generateKeys
  (pubCommit, privCommit) <- generateCommit
  print "Enter a challenge:"
  challenge <- BS.getLine >>= generateChallenge
  let r = computeResponse privCommit privKey challenge
  pure $ verify pubKey pubCommit challenge r
