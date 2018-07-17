module TestGroupLaws
  ( testGroupLaws
  ) where

import           Protolude
import           Test.QuickCheck.Monadic
import           Test.Tasty
import           Test.Tasty.HUnit
import           Test.Tasty.QuickCheck
import qualified Crypto.PubKey.ECC.Generate as ECC
import qualified Crypto.PubKey.ECC.Prim as ECC
import qualified Crypto.PubKey.ECC.Types as ECC

import Schnorr.Curve
import GroupLaws

genPoint :: ECC.Curve -> Gen ECC.Point
genPoint curve = ECC.generateQ curve <$> arbitrary

testAbelianGroupLaws
  :: (ECC.Curve -> ECC.Point -> ECC.Point -> ECC.Point)
  -> (ECC.Curve -> ECC.Point -> ECC.Point)
  -> ECC.Point
  -> ECC.Curve
  -> TestName
  -> TestTree
testAbelianGroupLaws binOp neg identity curve descr
  = testGroup ("Test Abelian group laws of " <> descr)
    [ testProperty "commutativity of addition"
      $ forAll (genPoint curve) $ \p1
      -> forAll (genPoint curve) $ \p2
      -> commutes (binOp curve) p1 p2

    , testProperty "commutativity of addition"
        $ forAll (genPoint curve) $ \p1
        -> forAll (genPoint curve) $ \p2
        -> forAll (genPoint curve) $ \p3
        -> associates (binOp curve) p1 p2 p3

    , testProperty "additive identity"
      $ forAll (genPoint curve) $ isIdentity (binOp curve) identity

    , testProperty "additive inverse"
      $ forAll (genPoint curve) $ isInverse (binOp curve) (neg curve) identity
    ]

testCurveGroupLaws :: Curve c => c -> TestTree
testCurveGroupLaws curveName =
  testAbelianGroupLaws
      ECC.pointAdd
      ECC.pointNegate
      ECC.PointO
      (curve curveName)
      (show curveName)

testGroupLaws :: TestTree
testGroupLaws = testGroup "Tests Group Laws" [
  testCurveGroupLaws Curve25519,
  testCurveGroupLaws (SECCurve ECC.SEC_p256k1)
  ]
