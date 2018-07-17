module Schnorr.Curve25519
  ( curve25519
  , isPointValid
  , pointMul
  , pointAdd
  , pointNegate
  , pointDouble
  , pointAddTwoMuls
  , pointBaseMul
  , generateQ
  , generateKeys
  ) where

import Protolude

import qualified Crypto.PubKey.ECC.Prim       as ECC
import qualified Crypto.PubKey.ECC.Types      as ECC
import qualified Crypto.PubKey.ECC.Generate   as ECC
import           Crypto.Number.Generate       (generateBetween)
import qualified Crypto.PubKey.ECC.ECDSA      as ECDSA
import           Crypto.Random.Types          (MonadRandom)
import           Crypto.Number.ModArithmetic  (inverse)

-- | Curve25519 definition
--
-- For the ~128-bit security level, the prime 2^255 - 19 is recommended
-- for performance on a wide range of architectures.
--
-- * @v^2 = u^3 + A*u^2 + u@:
-- * p  2^255 - 19
-- * A  486662
-- * order  2^252 + 0x14def9dea2f79cd65812631a5cf5d3ed = 7237005577332262213973186563042994240857116359379907606001950938285454250989
-- * cofactor  8
-- * U(P)  9
-- * V(P)  14781619447589544791020593568409986887264606134616475288964881837755586237401
-- * The base point is u = 9, v = 14781619447589544791020593568409986887264606134616475288964881837755586237401
curve25519 :: ECC.Curve
curve25519 = ECC.CurveFP $ ECC.CurvePrime
  0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED
  ECC.CurveCommon
      { ecc_a = 0x76D06
      , ecc_b = 0x1
      , ecc_g = ECC.Point 0x9 0x20AE19A1B8A086B4E01EDD2C7748D14C923D4D7E6D7C61B229E9C5A27ECED3D9
      , ecc_n = 0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED
      , ecc_h = 0x8
      }

-- | Check if a point is on specific curve
--
-- This perform three checks:
--
-- * x is not out of range
-- * y is not out of range
-- * the equation @y^2 = x^3 + a*x^2 + x (mod p)@ holds
isPointValid :: ECC.Curve -> ECC.Point -> Bool
isPointValid _                                   ECC.PointO      = True
isPointValid (ECC.CurveFP (ECC.CurvePrime p cc)) (ECC.Point x y) =
  isValid x && isValid y
    && (y ^ (2 :: Int)) `eqModP` (x ^ (3 :: Int) + a * (x ^ (2 :: Int)) + b * x)
  where a  = ECC.ecc_a cc
        b  = ECC.ecc_b cc
        eqModP z1 z2 = (z1 `mod` p) == (z2 `mod` p)
        isValid e = e >= 0 && e < p
isPointValid _ _ = False

-- | Elliptic Curve point doubling.
--
-- /WARNING:/ Vulnerable to timing attacks.
pointDouble :: ECC.Curve -> ECC.Point -> ECC.Point
pointDouble _ ECC.PointO = ECC.PointO
pointDouble (ECC.CurveFP (ECC.CurvePrime pr cc)) (ECC.Point xp yp) =
  fromMaybe ECC.PointO $ do
    lambda <- divmod (3 * xp ^ (2::Int) + 2 * a * xp + 1) (2 * yp) pr
    let xr = (lambda ^ (2::Int) - a - 2 * xp) `mod` pr
        yr = (lambda * (xp - xr) - yp) `mod` pr
    return $ ECC.Point xr yr
  where a = ECC.ecc_a cc
pointDouble _ _ = panic "Invalid point"

-- | Elliptic curve point multiplication (double and add algorithm).
--
-- /WARNING:/ Vulnerable to timing attacks.
pointMul :: ECC.Curve -> Integer -> ECC.Point -> ECC.Point
pointMul _ _ ECC.PointO = ECC.PointO
pointMul c n p
    | n <  0 = pointMul c (-n) (pointNegate c p)
    | n == 0 = ECC.PointO
    | n == 1 = p
    | odd n = pointAdd c p (pointMul c (n - 1) p)
    | otherwise = pointMul c (n `div` 2) (pointDouble c p)

-- | Elliptic Curve point negation:
--
-- @pointNegate c p@ returns point @q@ such that @pointAdd c p q == PointO@.
pointNegate :: ECC.Curve -> ECC.Point -> ECC.Point
pointNegate _               ECC.PointO      = ECC.PointO
pointNegate (ECC.CurveFP c) (ECC.Point x y) = ECC.Point x (ECC.ecc_p c - y)
pointNegate _ _                             = panic "Invalid point"

-- | Elliptic Curve point addition.
--
-- /WARNING:/ Vulnerable to timing attacks.
pointAdd :: ECC.Curve -> ECC.Point -> ECC.Point -> ECC.Point
pointAdd _ ECC.PointO ECC.PointO = ECC.PointO
pointAdd _ ECC.PointO q = q
pointAdd _ p ECC.PointO = p
pointAdd c p q
  | p == q = pointDouble c p
  | p == pointNegate c q = ECC.PointO
pointAdd curve@(ECC.CurveFP (ECC.CurvePrime pr cc)) (ECC.Point xp yp) (ECC.Point xq yq)
    = fromMaybe ECC.PointO $ do
        lambda <- divmod (yq - yp) (xq - xp) pr
        let xr = (lambda ^ (2::Int) - a - xp - xq) `mod` pr
            yr = (lambda * (xp - xr) - yp) `mod` pr
        return $ ECC.Point xr yr
  where a = ECC.ecc_a cc
pointAdd _ _ _ = panic "Invalid point"

-- | Elliptic curve double-scalar multiplication (uses Shamir's trick).
--
-- > pointAddTwoMuls c n1 p1 n2 p2 == pointAdd c (pointMul c n1 p1)
-- >                                             (pointMul c n2 p2)
--
-- /WARNING:/ Vulnerable to timing attacks.
pointAddTwoMuls :: ECC.Curve -> Integer -> ECC.Point -> Integer -> ECC.Point -> ECC.Point
pointAddTwoMuls _ _  ECC.PointO _  ECC.PointO = ECC.PointO
pointAddTwoMuls c _  ECC.PointO n2 p2     = pointMul c n2 p2
pointAddTwoMuls c n1 p1     _  ECC.PointO = pointMul c n1 p1
pointAddTwoMuls c n1 p1     n2 p2
    | n1 < 0    = pointAddTwoMuls c (-n1) (pointNegate c p1) n2 p2
    | n2 < 0    = pointAddTwoMuls c n1 p1 (-n2) (pointNegate c p2)
    | otherwise = go (n1, n2)

  where
    p0 = pointAdd c p1 p2

    go (0,  0 ) = ECC.PointO
    go (k1, k2) =
        let q = pointDouble c $ go (k1 `div` 2, k2 `div` 2)
        in case (odd k1, odd k2) of
            (True  , True  ) -> pointAdd c p0 q
            (True  , False ) -> pointAdd c p1 q
            (False , True  ) -> pointAdd c p2 q
            (False , False ) -> q

-- | Elliptic curve point multiplication using the base
--
-- /WARNING:/ Vulnerable to timing attacks.
pointBaseMul :: ECC.Curve -> Integer -> ECC.Point
pointBaseMul c n = pointMul c n (ECC.ecc_g $ ECC.common_curve c)

-- | Generate Q given d.
--
-- /WARNING:/ Vulnerable to timing attacks.
generateQ :: ECC.Curve
          -> Integer
          -> ECC.Point
generateQ curve d = pointMul curve d g
  where g = ECC.ecc_g $ ECC.common_curve curve

-- | Generate a pair of (private, public) key.
--
-- /WARNING:/ Vulnerable to timing attacks.
generateKeys :: MonadRandom m
         => ECC.Curve -- ^ Elliptic Curve
         -> m (ECDSA.PublicKey, ECDSA.PrivateKey)
generateKeys curve = do
    d <- generateBetween 1 (n - 1)
    let q = generateQ curve d
    return (ECDSA.PublicKey curve q, ECDSA.PrivateKey curve d)
  where
        n = ECC.ecc_n $ ECC.common_curve curve

-- | div and mod
divmod :: Integer -> Integer -> Integer -> Maybe Integer
divmod y x m = do
    i <- inverse (x `mod` m) m
    return $ y * i `mod` m
