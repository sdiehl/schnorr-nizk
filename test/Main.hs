{-# LANGUAGE OverloadedStrings #-}

module Main where

import           Data.ByteString
import           NonInteractive
import           Schnorr
import           Test.Tasty
import           Test.Tasty.HUnit

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests = testGroup "Tests" [unitTests]

unitTests = testGroup "Schnorr Indentification Schemes"
  [ testCaseSteps "Non-interactive" $ \step -> do
      step "Alice generates private and public keys..."
      (pubKey, privKey) <- generateKeys

      step "Alice also generates private and public commitment values..."
      (pubCommit, privCommit) <- generateCommit

      step "Using a secure cryptographic hash function to issue the challenge instead..."
      let challenge = mkChallenge pubKey pubCommit

      step "Alice computes the response..."
      let r = computeResponse privCommit privKey challenge

      step "Bob only verifies that Alice knows the value of the private key..."
      assertBool "Non-Interactive Schnorr doesn't work" $ verify pubKey pubCommit challenge r

  -- , testCaseSteps "Interactive" $ \step -> do
  --     step "Alice generates private and public keys..."
  --     (pubKey, privKey) <- generateKeys
  --
  --     step "Alice also generates private and public commitment values..."
  --     (pubCommit, privCommit) <- generateCommit
  --
  --     TODO: Mock IO to enter a random message
  --     step "Bob generates a challenge..."
  --     challenge <- generateChallenge msg
  --
  --     step "Alice computes the response..."
  --     let r = computeResponse privCommit privKey challenge
  --
  --     step "Bob verifies that Alice knows the value of the private key..."
  --     assertBool "Interactive Schnorr doesn't work" $ verify pubKey pubCommit challenge r
  ]
