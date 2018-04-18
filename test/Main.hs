{-# LANGUAGE OverloadedStrings #-}

module Main where

import           Protolude
import           Test.QuickCheck.Monadic
import           Test.Tasty
import           Test.Tasty.HUnit
import           Test.Tasty.QuickCheck
import           Crypto.Number.Generate     (generateBetween)
import qualified Crypto.PubKey.ECC.Prim as ECC
import qualified Crypto.PubKey.ECC.Types as ECC
import qualified Crypto.PubKey.ECC.Generate as ECC
import qualified Crypto.PubKey.ECC.ECDSA    as ECDSA

import           NonInteractive
import           Interactive
import           Schnorr
import qualified Curve

import TestSchnorr
import TestGroupLaws
import TestCurveOps

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests = testGroup "Tests"
  [ testGroupLaws
  , testCurveOps
  , testSchnorr
  ]
