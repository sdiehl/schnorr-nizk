{-# LANGUAGE OverloadedStrings #-}

module Main where

import           Data.ByteString
import           Interactive
import           Test.Tasty
import           Test.Tasty.HUnit

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests = testGroup "Tests" [unitTests]

-- TODO: Use QuickCheck to generate random messages
msg :: ByteString
msg = "Random message"

unitTests = testGroup "Unit tests"
  [ testCaseSteps "Schnorr Indentification Schemes" $ \step -> do
      step "Alice generates private and public keys..."
      (pubKey, privKey) <- generateKeys

      step "Alice also generates private and public commitment values..."
      (pubCommit, privCommit) <- generateCommit

      step "Bob generates a challenge..."
      challenge <- generateChallenge msg

      step "Alice computes the response..."
      let r = computeResponse privCommit privKey challenge

      step "Bob verifies that Alice knows the value of the private key..."
      assertBool "Interactive Schnorr doesn't work" $ verify pubCommit pubKey challenge r
  ]
