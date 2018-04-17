module Curve
  ( Curve(..)
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

instance Curve ECC.Curve_X25519 where
  curve = undefined
  cc = undefined
  n = undefined
  g = undefined
  h = undefined
