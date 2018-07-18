module TestSchnorr where

import           Protolude
import           Crypto.Random.Types (MonadRandom)
import qualified Test.QuickCheck.Monadic as QCM
import           Test.Tasty
import           Test.Tasty.HUnit
import           Test.Tasty.QuickCheck
import           Crypto.Number.Generate     (generateMax)
import qualified Crypto.PubKey.ECC.Prim as ECC
import qualified Crypto.PubKey.ECC.Types as ECC
import qualified Crypto.PubKey.ECC.Generate as ECC
import qualified Crypto.PubKey.ECC.ECDSA    as ECDSA

import           Schnorr
import           Schnorr.Internal
import           Schnorr.Curve as Curve

testSchnorr :: TestTree
testSchnorr = testGroup "Schnorr Indentification Schemes"
  [ testSchnorr' $ SECCurve ECC.SEC_p256k1
  , testSchnorr' Curve25519
  ]

genKeys :: (MonadRandom m, Curve c) => c -> ECC.Point -> m (ECC.Point, Integer)
genKeys curveName basePoint = do
  sk <- generateMax (Curve.n curveName)
  let pk = Curve.pointMul curveName sk basePoint
  pure (pk, sk)

testSchnorr' :: Curve c => c -> TestTree
testSchnorr' curveName = testGroup ("Curve: " <> show curveName)
  [ testProperty
      "Test Schnorr NIZK completeness"
      (prop_completenessNIZK curveName)
  , testProperty
      "Test Schnorr NIZK soundness"
      (prop_soundnessNIZK curveName)
  ]

prop_completenessNIZK :: Curve c => c -> Property
prop_completenessNIZK curveName = QCM.monadicIO $ do
  (basePoint, _) <- QCM.run $ genKeys curveName (Curve.g curveName)
  keyPair@(pk, sk) <- QCM.run $ genKeys curveName basePoint
  proof <- QCM.run $ Schnorr.prove curveName basePoint keyPair
  QCM.assert $ Schnorr.verify curveName basePoint pk proof

prop_soundnessNIZK :: Curve c => c -> Property
prop_soundnessNIZK curveName = QCM.monadicIO $ do
  (basePoint, _) <- QCM.run $ genKeys curveName (Curve.g curveName)
  keyPair@(pk, sk) <- QCM.run $ genKeys curveName basePoint
  invalidSk <- QCM.run $ ECC.scalarGenerate (Curve.curve curveName)
  proof <- QCM.run $ Schnorr.prove curveName basePoint (pk, invalidSk)
  QCM.assert $ not $ Schnorr.verify curveName basePoint pk proof
