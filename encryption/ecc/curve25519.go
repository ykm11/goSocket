package ecc

import (
    "math/big"
    "fmt"
    "crypto/rand"
)

func Export_PubKey(p Position) []byte {
    /*
        RFC5480
        | \x04 || X.Bytes() || Y.Bytes() | == 65; (1 + 32 + 32)
    */
    key := make([]byte, 65)
    key[0] = '\x04'
    x := p.X.Bytes()
    y := p.Y.Bytes()
    for j := 0; j < len(x); j++ {
        key[32 - j] = x[31 - j]
    }
    for j := 0; j < len(y); j++ {
        key[32*2 - j] = y[31 - j]
    }
    return key
}

func Import_PubKey(key []byte) Position {
    if (len(key) != 65 || key[0] != '\x04') {
        fmt.Printf("[FATAL] key length : %d\n", len(key))
        fmt.Printf("[FATAL] key : % x\n", key)
        panic("ECC PubKey Importing Error (RFC5480 format)")
    }
    x := new(big.Int).SetBytes(key[1:1+32])
    y := new(big.Int).SetBytes(key[1+32:])
    return Position{x, y}
}

func make_divlist(n *big.Int) []int {
    div := []int{}
    for ; n.Cmp(ONE) != 0; {
        t := 0
        if r := new(big.Int).Mod(n, TWO); r.Cmp(ONE) == 0 {
            n.Sub(n, ONE)
            div = append(div, 0)
        }
        for ;; {
            if r := new(big.Int).Mod(n, TWO); r.Cmp(ONE) == 0 {
                break
            }
            n.Div(n, TWO)
            t = t + 1
        }

        div = append(div, t)
    }
    return div
}
func EC_xP(x *big.Int, p Position) Position {
    base_p := Position{p.X, p.Y}
    n := new(big.Int).SetBytes(x.Bytes()) // Not to change 'a' (address) value

    div := make_divlist(n)
    for idx := len(div)-1; idx >= 0; idx-- {
        if div[idx] == 0 {
            p = EC_Add(p, base_p)
        } else {
            for i := 0; i < div[idx]; i++ {
                p = EC_Doubling(p)
            }
        }
    }
    return p
}

func EC_Add(p1, p2 Position) Position {
    x2_x1 := sub(p2.X, p1.X)
    y2_y1 := sub(p2.Y, p1.Y)

    numerator_x := pow(y2_y1, TWO)
    denominator_x := pow(x2_x1, TWO)
    x := sub(sub(sub(divMod(numerator_x, denominator_x), A), p1.X), p2.X)

    ay1 := mul(add(add(p2.X, mul(TWO, p1.X)), A), sub(p2.Y, p1.Y))
    y := sub(sub(divMod(ay1, x2_x1), divMod(pow(y2_y1 ,THREE), pow(x2_x1, THREE))), p1.Y)
    return Position{x, y}
}

func EC_Doubling(p Position) Position {
    numerator := add(add(mul(THREE, pow(p.X, TWO)), mul(mul(A, TWO), p.X)), ONE)
    denominator := mul(TWO, p.Y)
    lmd := divMod(numerator, denominator)

    x := sub(sub(pow(lmd, TWO), mul(TWO, p.X)), A)
    y := sub(sub(mul(lmd, add(A, mul(THREE, p.X))), pow(lmd, THREE)), p.Y)
    return Position{x, y}
}

func ECDHE_Key_Gen() (*big.Int, Position) {
    a, err := rand.Int(rand.Reader, p)
    if err != nil {
        panic("[FATAL] Error Occured during generating random-number")
    }
    return a, Position{U, V}
}
