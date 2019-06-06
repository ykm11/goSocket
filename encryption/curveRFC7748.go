package encryption

import (
    "math/big"
    "crypto/rand"
)

func swap_array(array []byte) []byte {
    ret_array := make([]byte, len(array))
    for idx := 0; idx < len(array) ; idx++ {
        ret_array[idx] = array[len(array)-idx-1]
    }
    return ret_array
}

func DecodeUCoordinate(u []byte, bits int) *big.Int {
    u_list := make([]byte, len(u))
    for idx := 0; idx < len(u); idx++ {
        u_list[idx] = u[idx]
    }
    if (bits % 8 == 0) {
        u_list[len(u_list)-1] &= uint8((1<<(uint(bits)%8))-1)
    }
    return DecodeLittleEndian(u_list)
}

func EncodeUCoordinate(u *big.Int, bits int) []byte {
    ret := make([]byte, (bits+7)/8)
    u_bytes := u.Bytes()
    for idx := 0; idx < len(u_bytes); idx++ {
        ret[idx] = u_bytes[len(u_bytes)-idx-1]
    }
    return ret
}

func DecodeLittleEndian(b []byte) *big.Int {
    b_reverse := swap_array(b)
    return new(big.Int).SetBytes(b_reverse)
}

func DecodeScalar25519(k []byte) *big.Int {
    k_list := make([]byte, len(k))
    for idx := 0; idx < len(k); idx++ {
        k_list[idx] = k[idx]
    }
    k_list[0] &= 248
    k_list[31] &= 127
    k_list[31] |= 64
    return DecodeLittleEndian(k_list)
}

func cswap(swap, x_2, x_3 *big.Int) (*big.Int, *big.Int) {
    dummy := Mul(swap, Sub(x_2, x_3, p_x25519), p_x25519)
    x_2 = Sub(x_2, dummy, p_x25519)
    x_3 = Add(x_3, dummy, p_x25519)

    return x_2, x_3
}

func x25519mul(k, u *big.Int, bits int, a24 *big.Int) *big.Int {
    x_1 := new(big.Int).SetBytes(u.Bytes())
    x_2 := ONE
    z_2 := ZERO
    x_3 := new(big.Int).SetBytes(u.Bytes())
    z_3 := ONE
    swap := ZERO

    for t := bits-1; t >= 0; t-- {
        tmp_k := new(big.Int).Rsh(k, uint(t))
        k_t := tmp_k.And(tmp_k, ONE)
        swap = new(big.Int).Xor(swap, k_t)
        x_2, x_3 = cswap(swap, x_2, x_3)
        z_2, z_3 = cswap(swap, z_2, z_3)
        swap = k_t

        A := Add(x_2, z_2, p_x25519)
        AA := Exp(A, TWO, p_x25519)
        B := Sub(x_2, z_2, p_x25519)
        BB := Exp(B, TWO, p_x25519)
        E := Sub(AA, BB, p_x25519)
        C := Add(x_3, z_3, p_x25519)
        D := Sub(x_3, z_3, p_x25519)
        DA := Mul(D, A, p_x25519)
        CB := Mul(C, B, p_x25519)

        x_3 = Exp(Add(DA, CB, p_x25519), TWO, p_x25519)
        z_3 = Mul(x_1, Exp(Sub(DA, CB, p_x25519), TWO, p_x25519), p_x25519)
        x_2 = Mul(AA, BB, p_x25519)
        z_2 = Mul(E, Add(AA, Mul(a24, E, p_x25519), p_x25519), p_x25519)
    }
    x_2, x_3 = cswap(swap, x_2, x_3)
    z_2, z_3 = cswap(swap, z_2, z_3)
    res := Mul(x_2, Exp(z_2, (Sub(p_x25519, TWO, p_x25519)), p_x25519), p_x25519)
    return res
}

func X25519(k, u []byte) []byte { // RFC7748
    bits := 255
    k_ := DecodeScalar25519(k)
    u_ := DecodeUCoordinate(u, bits)

    a24 := big.NewInt(121665)
    res := x25519mul(k_, u_, bits, a24)
    return EncodeUCoordinate(res, 255)
}

func X25519_Key_Gen() ([]byte, []byte) {
    a, err := rand.Int(rand.Reader, p_x25519)
    if err != nil {
        panic("[FATAL] Error Occured during generating random-number")
    }
    return a.Bytes(), EncodeUCoordinate(U, 255)
}
