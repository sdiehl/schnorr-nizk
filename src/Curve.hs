module Curve
  ( Curve(..)
  , Curve25519(..)
  ) where

import qualified Crypto.PubKey.ECC.Prim as ECC
import qualified Crypto.PubKey.ECC.Types as ECC
import qualified Crypto.ECC as ECC hiding (Point)
import           Protolude

class Curve a where
  curve :: a -> ECC.Curve
  cc :: a -> ECC.CurveCommon
  n :: a -> Integer
  g :: a -> ECC.Point
  h :: a -> Integer

instance Curve ECC.CurveName where
  curve = ECC.getCurveByName
  cc = ECC.common_curve . curve
  n = ECC.ecc_n . cc
  g = ECC.ecc_g . cc
  h = ECC.ecc_h . cc

data Curve25519 = Curve25519 deriving Show
-- For the ~128-bit security level, the prime 2^255 - 19 is recommended
-- for performance on a wide range of architectures.
-- v^2 = u^3 + A*u^2 + u, called "curve25519":
-- p  2^255 - 19
-- A  486662
-- order  2^252 + 0x14def9dea2f79cd65812631a5cf5d3ed
-- cofactor  8
-- U(P)  9
-- V(P)  147816194475895447910205935684099868872646061346164752889648818
--    37755586237401
-- The base point is u = 9, v = 1478161944758954479102059356840998688726
-- 4606134616475288964881837755586237401
curve25519 :: ECC.Curve
curve25519 = ECC.CurveFP $ ECC.CurvePrime
  0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED
  ECC.CurveCommon
      { ecc_a = 0x76D06
      , ecc_b = 0x1
      , ecc_g = ECC.Point 0x9 0x20AE19A1B8A086B4E01EDD2C7748D14C923D4D7E6D7C61B229E9C5A27ECED3D9
      , ecc_n = 0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED
      , ecc_h = 8
      }

instance Curve Curve25519 where
  curve = const curve25519
  cc = ECC.common_curve . curve
  n = ECC.ecc_n . cc
  g = ECC.ecc_g . cc
  h = ECC.ecc_h . cc
