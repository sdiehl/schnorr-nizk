{-# LANGUAGE OverloadedStrings #-}

module Main where

import           Protolude
import           Test.Tasty
import           Test.Tasty.HUnit

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
