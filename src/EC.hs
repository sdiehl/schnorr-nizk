module EC where

import           Control.Monad
import           Data.Maybe
import           Data.Monoid
import           Protolude

-- Elliptic curve point
data Point = Point Integer Integer | PointO
  deriving (Show, Eq)

-- ECDSA Signature
data Signature = Signature { r :: Integer, s :: Integer }
  deriving Show

-- Elliptic curve private key
type PrivateKey = Integer

-- Elliptic public key
type PublicKey = Point

-------------------------------------------------------------------------------
-- secp256k1 curve specification
-------------------------------------------------------------------------------

-- curve coefficient
b :: Integer
b = 7

-- prime
pr :: Integer
pr = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f

-- a generator of the elliptic curve
g :: Point
g = Point 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
          0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8

-- the order of the curve
n :: Integer
n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

-- | Elliptic Curve point negation:
pointNegate :: Point -> Point
pointNegate PointO      = PointO
pointNegate (Point x y) = Point x (-y)

-- | Elliptic Curve point doubling.
pointDouble :: Point -> Point
pointDouble PointO = PointO
pointDouble (Point xp yp) = fromMaybe PointO $ do
    m <- divmod (3 * xp * xp) (2 * yp) pr
    let xr = (m * m - 2 * xp) `mod` pr
        yr = (m * (xp - xr) - yp) `mod` pr
    pure $ Point xr yr

-- | Extended euclidean algorithm
eGCD :: Integer -> Integer -> (Integer,Integer,Integer)
eGCD 0 b = (b, 0, 1)
eGCD a b = let (g, s, t) = eGCD (b `mod` a) a
           in (g, t - (b `div` a) * s, s)

-- | Elliptic Curve point addition
pointAdd :: Point -> Point -> Point
pointAdd PointO PointO = PointO
pointAdd PointO q = q
pointAdd p PointO = p
pointAdd p q
  | p == q = pointDouble p
  | p == pointNegate q = PointO
pointAdd p@(Point xp yp) q@(Point xq yq)
    = fromMaybe PointO $ do
      m <- slope p q
      let xR = (m * m - xp - xq) `mod` pr
          yR = -(yp + m * (xR - xp)) `mod` pr
      pure $ Point xR yR

-- | Elliptic Curve point multiplication
pointMul :: Integer -> Point -> Point
pointMul _ PointO = PointO
pointMul n p
    | n <  0 = pointMul (-n) (pointNegate p)
    | n == 0 = PointO
    | n == 1 = p
    | odd n = pointAdd p (pointMul (n - 1) p)
    | otherwise = pointMul (n `div` 2) (pointDouble p)

-- | Elliptic curve add two scaled points
pointAddTwoMuls :: Integer -> Point -> Integer -> Point -> Point
pointAddTwoMuls _  PointO _  PointO = PointO
pointAddTwoMuls _  PointO n2 p2     = pointMul n2 p2
pointAddTwoMuls n1 p1     _  PointO = pointMul n1 p1
pointAddTwoMuls n1 p1     n2 p2
    | n1 < 0    = pointAddTwoMuls (-n1) (pointNegate p1) n2 p2
    | n2 < 0    = pointAddTwoMuls n1 p1 (-n2) (pointNegate p2)
    | otherwise = go (n1, n2)
  where
    p0 = pointAdd p1 p2

    go (0,  0 ) = PointO
    go (k1, k2) =
        let q = pointDouble $ go (k1 `div` 2, k2 `div` 2)
        in case (odd k1, odd k2) of
            (True  , True  ) -> pointAdd p0 q
            (True  , False ) -> pointAdd p1 q
            (False , True  ) -> pointAdd p2 q
            (False , False ) -> q


-- | Calculate the inverse modulo p
mulInverse :: Integer -> Integer -> Integer
mulInverse a b
  | a * s `mod` b == 1 = s
  | otherwise = panic $ "No multiplicative inverse: " <> show s <> " + " <> show a
  where (_, s, _) = eGCD a b

-- | div and mod
divmod :: Integer -> Integer -> Integer -> Maybe Integer
divmod _ 0 _ = Nothing
divmod y x m = Just $ y * i `mod` m
  where
    i = mulInverse (x `mod` m) m

-- | Slope of a line given two points in a field modulo pr
slope :: Point -> Point -> Maybe Integer
slope (Point x1 y1) (Point x2 y2) = divmod (y1 - y2) (x1 - x2) pr
slope _ _                         = Nothing
