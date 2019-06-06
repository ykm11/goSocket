package encryption

import (
    "math/big"
    "crypto/rand"
)

var (
    ZERO = big.NewInt(0)
    ONE = big.NewInt(1)
    TWO = big.NewInt(2)
    THREE = big.NewInt(3)
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

func Randint(offset, n *big.Int) *big.Int {
    if offset != nil { // [offset, n)
        randNum, _ := rand.Int(rand.Reader, Sub(n, offset, nil))
        return Add(randNum, offset, nil)
    } else { // [0, n)
        randNum, _ := rand.Int(rand.Reader, n)
        return randNum
    }
}

