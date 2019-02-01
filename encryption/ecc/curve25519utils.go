package ecc

import (
    "math/big"
)

/*
    Defined Functions on GF(p) here as following :
        Add, Sub, Mul, Pow, DivMod, 
*/

var (
    ONE = big.NewInt(1)
    TWO = big.NewInt(2)
    THREE = big.NewInt(3)
    POWER = big.NewInt(255)
    A = big.NewInt(486662)

    U = big.NewInt(9)
    V, _ = new(big.Int).SetString("14781619447589544791020593568409986887264606134616475288964881837755586237401", 10)
    p, _ = new(big.Int).SetString("57896044618658097711785492504343953926634992332820282019728792003956564819949", 10)

)

type Position struct {
    X *big.Int
    Y *big.Int
}

func add(x, y *big.Int) *big.Int {
    r := new(big.Int).Add(x, y)
    r.Mod(r, p)
    return r
}
func mul(x, y *big.Int) *big.Int {
    r := new(big.Int).Mul(x, y)
    r.Mod(r, p)
    return r
}
func pow(x, y *big.Int) *big.Int {
    r := new(big.Int).Exp(x, y, p)
    return r
}
func sub(x, y *big.Int) *big.Int {
    r := new(big.Int).Sub(x, y)
    r.Mod(r, p)
    return r
}

func divMod(x, y *big.Int) *big.Int { // ModInverse
    y_inv := new(big.Int).ModInverse(y, p)
    r := mul(x, y_inv)
    return r
}

func Check(p Position) int {
    // v^2 = u^3 + A*u^2 + u
    u3 := pow(p.X, THREE)
    Au2 := mul(A, pow(p.X, TWO))
    r := add(add(u3, Au2), p.X)

    l := pow(p.Y, TWO)
    return l.Cmp(r)
}
