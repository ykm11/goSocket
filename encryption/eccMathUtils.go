package encryption

import (
    "math/big"
)

var (
    ZERO = big.NewInt(0)
    ONE = big.NewInt(1)
    TWO = big.NewInt(2)
    THREE = big.NewInt(3)
    //POWER255 = big.NewInt(255)
    A_x25519 = big.NewInt(486662)

    U_x25519 = big.NewInt(9)
    U_x448 = big.NewInt(5)
    //V = Str2Int("14781619447589544791020593568409986887264606134616475288964881837755586237401", 10)
    p_x25519 = Str2Int("57896044618658097711785492504343953926634992332820282019728792003956564819949", 10)
    p_x448 = Str2Int("fffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)
)

func Add(a, b, modulus *big.Int) *big.Int {
    r := new(big.Int).Add(a, b)
    if modulus != nil {
        r.Mod(r, modulus)
    }
    return r
}
func Mul(a, b, modulus *big.Int) *big.Int {
    r := new(big.Int).Mul(a, b)
    if modulus != nil {
        r.Mod(r, modulus)
    }
    return r
}
func Sub(a, b, modulus *big.Int) *big.Int {
    r := new(big.Int).Sub(a, b)
    if modulus != nil {
        r.Mod(r, modulus)
    }
    return r
}
func Exp(a, b, modulus *big.Int) *big.Int {
    r := new(big.Int).Exp(a, b, modulus)
    return r
}
