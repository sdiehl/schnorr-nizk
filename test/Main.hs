{-# LANGUAGE OverloadedStrings #-}

module Main where

import           Data.ByteString
import           Protolude
import           Test.QuickCheck.Monadic
import           Test.Tasty
import           Test.Tasty.HUnit
import           Test.Tasty.QuickCheck
import           Crypto.Number.Generate     (generateBetween)
import qualified Crypto.PubKey.ECC.Types as ECC

import           NonInteractive
import           Interactive
import           Schnorr
import qualified Curve

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests = testGroup "Tests" [schnorrTests]

completenessNonInt :: Curve.Curve c => c -> ([Char] -> IO ()) -> IO ()
completenessNonInt curveName step = do
    step "Alice generates private and public keys..."
    (pubKey, privKey) <- generateKeys curveName

    step "Alice also generates private and public commitment values..."
    (pubCommit, privCommit) <- generateCommitment curveName

    step "Using a secure cryptographic hash function to issue the challenge instead..."
    let challenge = mkChallenge curveName pubKey pubCommit

    step "Alice computes the response..."
    let resp = computeResponse curveName privCommit privKey challenge

    step "Bob only verifies that Alice knows the value of the private key..."
    assertBool "Non-Interactive Schnorr doesn't work" $
      verify curveName pubKey pubCommit challenge resp

soundnessNonInt :: Curve.Curve c => c -> ([Char] -> IO ()) -> IO ()
soundnessNonInt curveName step = do
    step "Alice generates private and public keys..."
    (pubKey, privKey) <- generateKeys curveName

    step "Alice also generates private and public commitment values..."
    (pubCommit, privCommit) <- generateCommitment curveName

    step "Using a secure cryptographic hash function to issue the challenge instead..."
    let challenge = mkChallenge curveName pubKey pubCommit

    step "Alice computes the response but doesn't know the random commitment private value..."
    randomPrivCommit <- generateBetween 1 (Curve.n curveName - 1)
    let resp = computeResponse curveName randomPrivCommit privKey challenge

    step "Bob only verifies that Alice knows the value of the private key..."
    assertBool "Non-Interactive Schnorr doesn't work" $
      not $ verify curveName pubKey pubCommit challenge resp

schnorrTests = testGroup "Schnorr Indentification Schemes"
  [ testCaseSteps
      "Non-interactive. Completeness property. Secp256k1 Curve"
      (completenessNonInt ECC.SEC_p256k1)

  , testCaseSteps
      "Non-interactive. Soundness property. Secp256k1 Curve"
      (soundnessNonInt ECC.SEC_p256k1)

  -- , testCaseSteps
  --     "Non-interactive. Completeness property. Curve25519 Curve"
  --     (completenessNonInt ECC.Curve25519)
  --
  -- , testCaseSteps
  --     "Non-interactive. Soundness property. Curve25519 Curve"
  --     (soundnessNonInt ECC.Curve25519)

  , testProperty "Interactive. Secp256k1 Curve" (interactiveTest ECC.SEC_p256k1)
  ]


interactiveTest :: Curve.Curve c => c -> [Char] -> Property
interactiveTest curveName msg = monadicIO $ do
  (pubKey, privKey) <- liftIO $ generateKeys curveName
  (pubCommit, privCommit) <- liftIO $ generateCommitment curveName
  challenge <- liftIO $ generateChallenge (show msg)
  let r = computeResponse curveName privCommit privKey challenge
  pure $ verify curveName pubKey pubCommit challenge r
