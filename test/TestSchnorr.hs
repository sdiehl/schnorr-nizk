module TestSchnorr where

import           Protolude
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
  , testSchnorr' Curve25519
  ]

testSchnorr' :: Curve c => c -> TestTree
testSchnorr' curveName = testGroup ("Curve: " <> show curveName)
  [ testCaseSteps
      "Non-interactive variant. Completeness property. Curve generator"
      (completenessNonInt curveName (Curve.g curveName))

  {-, testCaseSteps-}
      {-"Non-interactive variant. Completeness property. Curve generator"-}
      {-(\step -> do-}
        {-k <- generatemax (curve.n curvename - 1)-}
        {-let randombasepoint = ecc.pointmul (curve.curve curvename) 1 (curve.g curvename)-}
        {-print "HELLO"-}
        {-completenessNonInt curveName (Curve.g curveName) step-}
      {-)-}

  , testCaseSteps
      "Non-interactive variant. Soundness property. Curve generator"
      (soundnessNonInt curveName (Curve.g curveName))

  , testProperty "Interactive variant. Curve generator" (interactiveTest curveName (Curve.g curveName))
  , testProperty "Non-Interactive variant. Different generators" (interactiveTest curveName )
  ]

completenessNonInt :: Curve c => c -> ECC.Point -> ([Char] -> IO ()) -> IO ()
completenessNonInt curveName basePoint step = do
    step "Alice generates private and public keys..."
    (pubKey, privKey) <- bimap ECDSA.public_q ECDSA.private_d <$> generateKeys curveName

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
    (pubKey, privKey) <- bimap ECDSA.public_q ECDSA.private_d <$> generateKeys curveName

    step "Alice also generates private and public commitment values..."
    (pubCommit, _) <- generateCommitment curveName basePoint

    step "Using a secure cryptographic hash function to issue the challenge instead..."
    let challenge = mkChallenge curveName basePoint pubKey pubCommit

    step "Alice computes the response but doesn't know the random commitment private value..."
    randomPrivCommit <- generateMax (n curveName - 1)
    let resp = computeResponse curveName randomPrivCommit privKey challenge

    step "Bob only verifies that Alice knows the value of the private key..."
    assertBool "Non-Interactive Schnorr doesn't work" $
      not $ verify curveName basePoint pubKey pubCommit challenge resp

interactiveTest :: Curve c => c -> ECC.Point -> [Char] -> Property
interactiveTest curveName basePoint msg = monadicIO $ do
  (pubKey, privKey) <- liftIO $ bimap ECDSA.public_q ECDSA.private_d <$> generateKeys curveName
  (pubCommit, privCommit) <- liftIO $ generateCommitment curveName basePoint
  challenge <- liftIO $ generateChallenge (show msg)
  let r = computeResponse curveName privCommit privKey challenge
  pure $ verify curveName basePoint pubKey pubCommit challenge r


nonInteractiveTest :: Curve c => c -> ECC.Point -> Property
nonInteractiveTest curveName basePoint = monadicIO $ do
  {-(pubKey, privKey) <- liftIO $ bimap ECDSA.public_q ECDSA.private_d <$> generateKeys curveName-}
  (pubCommit, privCommit) <- liftIO $ generateCommitment curveName basePoint
  let challenge = mkChallenge curveName basePoint pubKey pubCommit
  let r = computeResponse curveName privCommit privKey challenge
  pure $ verify curveName basePoint pubKey pubCommit challenge r
