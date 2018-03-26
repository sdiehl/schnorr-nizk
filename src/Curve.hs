module Curve
  ( secp256k1
  , n
  , g
  , h
  ) where

import           Crypto.PubKey.ECC.Prim
import           Crypto.PubKey.ECC.Types
import           Protolude

secp256k1 :: Curve
secp256k1 = getCurveByName SEC_p256k1

cc :: CurveCommon
cc = common_curve secp256k1

-- | Order of the curve
n :: Integer
n = ecc_n cc

-- | Generator base point
g :: Point
g = ecc_g cc

-- | Curve cofactor
h :: Integer
h = ecc_h cc
