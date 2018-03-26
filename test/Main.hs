{-# LANGUAGE OverloadedStrings #-}

module Main where

import           Data.ByteString
import           Protolude
import           Test.QuickCheck.Monadic
import           Test.Tasty
import           Test.Tasty.HUnit
import           Test.Tasty.QuickCheck
import           Crypto.Number.Generate     (generateBetween)

import           NonInteractive
import           Interactive
import           Schnorr
import           Curve

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests = testGroup "Tests" [schnorrTests]

schnorrTests = testGroup "Schnorr Indentification Schemes"
  [ testCaseSteps "Non-interactive. Completeness property" $ \step -> do
      step "Alice generates private and public keys..."
      (pubKey, privKey) <- generateKeys

      step "Alice also generates private and public commitment values..."
      (pubCommit, privCommit) <- generateCommitment

      step "Using a secure cryptographic hash function to issue the challenge instead..."
      let challenge = mkChallenge pubKey pubCommit

      step "Alice computes the response..."
      let resp = computeResponse privCommit privKey challenge

      step "Bob only verifies that Alice knows the value of the private key..."
      assertBool "Non-Interactive Schnorr doesn't work" $ verify pubKey pubCommit challenge resp

  , testCaseSteps "Non-interactive. Soundness property" $ \step -> do
      step "Alice generates private and public keys..."
      (pubKey, privKey) <- generateKeys

      step "Alice also generates private and public commitment values..."
      (pubCommit, privCommit) <- generateCommitment

      step "Using a secure cryptographic hash function to issue the challenge instead..."
      let challenge = mkChallenge pubKey pubCommit

      step "Alice computes the response but doesn't know the random commitment private value..."
      randomPrivCommit <- generateBetween 1 (n - 1)
      let resp = computeResponse randomPrivCommit privKey challenge

      step "Bob only verifies that Alice knows the value of the private key..."
      assertBool "Non-Interactive Schnorr doesn't work" $ not $ verify pubKey pubCommit challenge resp


  , testProperty "Interactive" interactiveTest
  ]


interactiveTest :: [Char] -> Property
interactiveTest msg = monadicIO $ do
    (pubKey, privKey) <- liftIO generateKeys
    (pubCommit, privCommit) <- liftIO generateCommitment
    challenge <- liftIO $ generateChallenge (show msg)
    let r = computeResponse privCommit privKey challenge
    pure $ verify pubKey pubCommit challenge r
