module TestSchnorr where

import           Protolude
import           Crypto.Random.Types (MonadRandom)
import           Test.QuickCheck.Monadic
import           Test.Tasty
import           Test.Tasty.HUnit
import           Test.Tasty.QuickCheck
import           Crypto.Number.Generate     (generateMax)
import qualified Crypto.PubKey.ECC.Prim as ECC
import qualified Crypto.PubKey.ECC.Types as ECC
import qualified Crypto.PubKey.ECC.Generate as ECC
import qualified Crypto.PubKey.ECC.ECDSA    as ECDSA

import           NonInteractive
import           Interactive
import           Schnorr
import           Curve

testSchnorr :: TestTree
testSchnorr = testGroup "Schnorr Indentification Schemes"
  [ testSchnorr' $ SECCurve ECC.SEC_p256k1
  {-, testSchnorr' Curve25519-}
  ]

genKeys :: (MonadRandom m, Curve c) => c -> ECC.Point -> m (ECC.Point, Integer)
genKeys curveName basePoint = do
  sk <- generateMax (Curve.n curveName - 1)
  let pk = ECC.pointMul (Curve.curve curveName) sk basePoint
  pure (pk, sk)

testSchnorr' :: Curve c => c -> TestTree
testSchnorr' curveName = testGroup ("Curve: " <> show curveName)
  [ testCaseSteps
      "Non-interactive variant. Completeness property. Curve generator as base point"
      (completenessNonInt curveName (Curve.g curveName))

  , testCaseSteps
      "Non-interactive variant. Completeness property. Random base point"
      (\step -> do
        (basePoint, _) <- genKeys curveName (Curve.g curveName)
        completenessNonInt curveName basePoint step
      )

  , testCaseSteps
      "Non-interactive variant. Soundness property. Curve generator as base point"
      (soundnessNonInt curveName (Curve.g curveName))

  , testProperty "Interactive variant. Property check" (interactiveTest curveName)
  , testProperty "Non-Interactive variant. Property check" (interactiveTest curveName)
  ]

completenessNonInt :: Curve c => c -> ECC.Point -> ([Char] -> IO ()) -> IO ()
completenessNonInt curveName basePoint step = do
    step "Alice generates private and public keys..."
    (pubKey, privKey) <- genKeys curveName basePoint

    step "Alice also generates private and public commitment values..."
    (pubCommit, privCommit) <- generateCommitment curveName basePoint

    step "Using a secure cryptographic hash function to issue the challenge instead..."
    let challenge = mkChallenge curveName basePoint pubKey pubCommit

    step "Alice computes the response..."
    let resp = computeResponse curveName privCommit privKey challenge

    step "Bob only verifies that Alice knows the value of the private key..."

    let verified = verify curveName basePoint pubKey pubCommit challenge resp
    assertBool "Non-Interactive Schnorr doesn't work" verified

soundnessNonInt :: Curve c => c -> ECC.Point -> ([Char] -> IO ()) -> IO ()
soundnessNonInt curveName basePoint step = do
    step "Alice generates private and public keys..."
    privKey <- generateMax (Curve.n curveName - 1)
    let pubKey = ECC.pointMul (Curve.curve curveName) privKey basePoint

    step "Alice also generates private and public commitment values..."
    (pubCommit, _) <- generateCommitment curveName basePoint

    step "Using a secure cryptographic hash function to issue the challenge instead..."
    let challenge = mkChallenge curveName basePoint pubKey pubCommit

    step "Alice computes the response but doesn't know the random commitment private value..."
    randomPrivCommit <- generateMax (Curve.n curveName - 1)
    let resp = computeResponse curveName randomPrivCommit privKey challenge

    step "Bob only verifies that Alice knows the value of the private key..."
    assertBool "Non-Interactive Schnorr doesn't work" $
      not $ verify curveName basePoint pubKey pubCommit challenge resp

interactiveTest :: Curve c => c -> [Char] -> Property
interactiveTest curveName msg = monadicIO $ do
  (basePoint, _) <- liftIO $ genKeys curveName (Curve.g curveName)
  (pubKey, privKey) <- liftIO $ genKeys curveName basePoint
  (pubCommit, privCommit) <- liftIO $ generateCommitment curveName basePoint
  challenge <- liftIO $ generateChallenge (show msg)
  let r = computeResponse curveName privCommit privKey challenge
  pure $ verify curveName basePoint pubKey pubCommit challenge r


nonInteractiveTest :: Curve c => c -> Property
nonInteractiveTest curveName = monadicIO $ do
  (basePoint, _) <- liftIO $ genKeys curveName (Curve.g curveName)
  (pubKey, privKey) <- liftIO $ genKeys curveName basePoint
  (pubCommit, privCommit) <- liftIO $ generateCommitment curveName basePoint
  let challenge = mkChallenge curveName basePoint pubKey pubCommit
  let r = computeResponse curveName privCommit privKey challenge
  pure $ verify curveName basePoint pubKey pubCommit challenge r
