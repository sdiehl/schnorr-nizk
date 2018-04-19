module TestCurveOps (testCurveOps) where

import Protolude

import           Test.QuickCheck.Monadic
import           Test.Tasty
import           Test.Tasty.HUnit
import           Test.Tasty.QuickCheck

import           Crypto.Number.Generate     (generateBetween)
import qualified Crypto.PubKey.ECC.Prim as ECC
import qualified Crypto.PubKey.ECC.Types as ECC
import qualified Crypto.PubKey.ECC.Generate as ECC
import qualified Crypto.PubKey.ECC.ECDSA    as ECDSA

import qualified Curve
import qualified Curve25519

testCurveOps :: TestTree
testCurveOps = testGroup "Curve operations"
  [ testCurveOps' Curve.Curve25519
  , testCurveOps' $ Curve.SECCurve ECC.SEC_p256k1
  ]

testCurveOps' :: Curve.Curve c => c -> TestTree
testCurveOps' curveName = testGroup ("Curve: " <> show curveName)
  [ testCase
      "Curve generator g is valid point."
      (gIsPointValid curveName)

  , testProperty
      "A randomly generated point is valid point."
      (rndIsPointValid curveName)

  , testProperty
      "A generated public key is valid point."
      (publicKeyIsPointValid curveName)

  , testProperty
      "The result of adding two points is valid point."
      (pointAddIsPointValid curveName)

  , testProperty
      "The result of doubling a point is valid point."
      (pointDoubleIsPointValid curveName)

  , testProperty
      "The result of multiplying a point by a scalar is valid point."
      (pointMulIsPointValid curveName)
  ]

rndIsPointValid :: Curve.Curve c => c -> Property
rndIsPointValid curveName = monadicIO $ do
  d <- liftIO $ generateBetween 1 (Curve.n curveName - 1)
  let point = Curve.generateQ curveName d
  pure $ Curve.isPointValid curveName point

publicKeyIsPointValid :: Curve.Curve c => c -> Property
publicKeyIsPointValid curveName = monadicIO $ do
  (pubKey, privKey) <- liftIO $ Curve.generateKeys curveName
  pure $ Curve.isPointValid curveName (ECDSA.public_q pubKey)

gIsPointValid :: Curve.Curve c => c -> Assertion
gIsPointValid curveName = assertBool "generator g is not a valid point" $
  Curve.isPointValid curveName (Curve.g curveName)

pointAddIsPointValid :: Curve.Curve c => c -> Property
pointAddIsPointValid curveName = monadicIO $ do
  -- Generate point 1
  d1 <- liftIO $ generateBetween 1 (Curve.n curveName - 1)
  let p1 = Curve.generateQ curveName d1
  -- Generate point 2
  d2 <- liftIO $  generateBetween 1 (Curve.n curveName - 1)
  let p2 = Curve.generateQ curveName d2

  let result = Curve.pointAdd curveName p1 p2
  pure $ Curve.isPointValid curveName result

pointDoubleIsPointValid :: Curve.Curve c => c -> Property
pointDoubleIsPointValid curveName = monadicIO $ do
  -- Generate point
  d <- liftIO $ generateBetween 1 (Curve.n curveName - 1)
  let p = Curve.generateQ curveName d
  let result = Curve.pointAdd curveName p p
  pure $ Curve.isPointValid curveName result

pointMulIsPointValid :: Curve.Curve c => c -> Property
pointMulIsPointValid curveName = monadicIO $ do
  -- Generate scalar
  m <- liftIO $ generateBetween 1 (Curve.n curveName - 1)

  -- Generate point
  d <- liftIO $  generateBetween 1 (Curve.n curveName - 1)
  let p = Curve.generateQ curveName d

  let result = Curve.pointMul curveName m p
  pure $ Curve.isPointValid curveName result
