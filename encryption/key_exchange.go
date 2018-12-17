package encryption

import (
    "math/big"
    "crypto/rand"
)

func FFDHE_key_gen(bits string) (*big.Int, *big.Int, *big.Int) {
    init_base := big.NewInt(2)
    p := new(big.Int)

    switch bits {
    case "4096":
    case "3072":
    default: // 2048
        _, ok := p.SetString("FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B423861285C97FFFFFFFFFFFFFFFF", 16)
        if !ok {
            panic("ERRORRR")
        }
    }
    e, err := rand.Int(rand.Reader, p)
    if err != nil {
        panic("ERRORRR")
    }
    return init_base, e, p
}

func FFDHE(base, e, p *big.Int) *big.Int {
    return new(big.Int).Exp(base, e, p)
}

/*
func main() {
    e1, p := FFDHE_key_gen("2048")
    e2, _ := FFDHE_key_gen("2048")
    base := big.NewInt(2)

    A_pub := FFDHE(base, e1, p)
    B_pub := FFDHE(base, e2, p)

    A_pri := FFDHE(B_pub, e1, p)
    B_pri := FFDHE(A_pub, e2, p)

    fmt.Println(A_pri.Cmp(B_pri) == 0)

    fmt.Printf("% x\n", A_pri.Bytes())
}
*/
