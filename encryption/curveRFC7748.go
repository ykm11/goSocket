package encryption

import (
    "math/big"
    "crypto/rand"
)

func DecodeUCoordinate(u []byte, bits int) *big.Int {
    u_list := make([]byte, len(u))
    for idx := 0; idx < len(u); idx++ {
        u_list[idx] = u[idx]
    }
    if (bits % 8 != 0) {
        u_list[len(u_list)-1] &= uint8((1<<(uint(bits)%8))-1)
    }
    return DecodeLittleEndian(u_list, bits)
}

func EncodeUCoordinate(u *big.Int, bits int) []byte {
    ret := make([]byte, (bits+7)/8)
    u_bytes := u.Bytes()
    for idx := 0; idx < len(u_bytes); idx++ {
        ret[idx] = u_bytes[len(u_bytes)-idx-1]
    }
    return ret
}

func DecodeLittleEndian(b []byte, bits int) *big.Int {
    var tmp *big.Int
    s := ZERO
    for i := 0; i < (bits+7)/8; i++ {
        tmp = new(big.Int).SetBytes([]byte{b[i]})
        tmp.Lsh(tmp, uint(8*i))
        s = Add(s, tmp, nil)
    }
    return s
}

func DecodeScalar25519(k []byte) *big.Int {
    k_list := make([]byte, len(k))
    for idx := 0; idx < len(k); idx++ {
        k_list[idx] = k[idx]
    }
    k_list[0] &= 248
    k_list[31] &= 127
    k_list[31] |= 64
    return DecodeLittleEndian(k_list, 255)
}

func DecodeScalar448(k []byte) *big.Int {
    k_list := make([]byte, len(k))
    for idx := 0; idx < len(k); idx++ {
        k_list[idx] = k[idx]
    }
    k_list[0] &= 252
    k_list[55] |= 128
    return DecodeLittleEndian(k_list, 448)
}
/*
   def decodeScalar448(k):
       k_list = [ord(b) for b in k]
       k_list[0] &= 252
       k_list[55] |= 128
       return decodeLittleEndian(k_list, 448)
*/

func cswap(swap, x_2, x_3, p *big.Int) (*big.Int, *big.Int) {
    dummy := Mul(swap, Sub(x_2, x_3, p), p)
    x_2 = Sub(x_2, dummy, p)
    x_3 = Add(x_3, dummy, p)

    return x_2, x_3
}

func xMul(k, u *big.Int, bits int, a24, p *big.Int) *big.Int {
    x_1 := ValCopy(u)
    x_2 := ONE
    z_2 := ZERO
    x_3 := ValCopy(u)
    z_3 := ONE
    swap := ZERO

    var tmp_k, k_t *big.Int
    var A, AA, B, BB, C, CB, D, DA, E *big.Int

    for t := bits-1; t >= 0; t-- {
        tmp_k = new(big.Int).Rsh(k, uint(t))
        k_t = tmp_k.And(tmp_k, ONE)
        swap = new(big.Int).Xor(swap, k_t)
        x_2, x_3 = cswap(swap, x_2, x_3, p)
        z_2, z_3 = cswap(swap, z_2, z_3, p)
        swap = k_t

        A = Add(x_2, z_2, p)
        AA = Exp(A, TWO, p)
        B = Sub(x_2, z_2, p)
        BB = Exp(B, TWO, p)
        E = Sub(AA, BB, p)
        C = Add(x_3, z_3, p)
        D = Sub(x_3, z_3, p)
        DA = Mul(D, A, p)
        CB = Mul(C, B, p)

        x_3 = Exp(Add(DA, CB, p), TWO, p)
        z_3 = Mul(x_1, Exp(Sub(DA, CB, p), TWO, p), p)
        x_2 = Mul(AA, BB, p)
        z_2 = Mul(E, Add(AA, Mul(a24, E, p), p), p)
    }
    x_2, x_3 = cswap(swap, x_2, x_3, p)
    z_2, z_3 = cswap(swap, z_2, z_3, p)
    res := Mul(x_2, Exp(z_2, Sub(p, TWO, p), p), p)
    return res
}

func X25519(k, u []byte) []byte { // RFC7748
    bits := 255
    k_ := DecodeScalar25519(k)
    u_ := DecodeUCoordinate(u, bits)

    a24 := big.NewInt(121665)
    res := xMul(k_, u_, bits, a24, p_x25519)
    return EncodeUCoordinate(res, bits)
}

func X448(k, u []byte) []byte { // RFC7748
    bits := 448
    k_ := DecodeScalar448(k) // Not Implemented
    u_ := DecodeUCoordinate(u, bits)

    a24 := big.NewInt(39081)
    res := xMul(k_, u_, bits, a24, p_x448)
    return EncodeUCoordinate(res, bits)
}

func X25519_Key_Gen() ([]byte, []byte) { // 32 random bytes in a[0] to a[31]
    a, err := rand.Int(rand.Reader, p_x25519)
    if err != nil {
        panic("[FATAL] Error Occured during generating random-number")
    }
    return a.Bytes(), EncodeUCoordinate(U_x25519, 255)
}
