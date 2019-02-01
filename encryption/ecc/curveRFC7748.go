package ecc


import (
    "math/big"
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
    dummy := mul(swap, sub(x_2, x_3))
    x_2 = sub(x_2, dummy)
    x_3 = add(x_3, dummy)

    return x_2, x_3
}
func x25519mul(k, u *big.Int, bits int, a24 *big.Int) *big.Int {
    x_1 := new(big.Int).SetBytes(u.Bytes())
    x_2 := ONE
    z_2 := big.NewInt(0)
    x_3 := new(big.Int).SetBytes(u.Bytes())
    z_3 := ONE
    swap := big.NewInt(0)

    for t := bits-1; t >= 0; t-- {
        tmp_k := new(big.Int).Rsh(k, uint(t))
        k_t := tmp_k.And(tmp_k, ONE)
        swap.Xor(swap, k_t)
        x_2, x_3 = cswap(swap, x_2, x_3)
        z_2, z_3 = cswap(swap, z_2, z_3)
        swap = k_t

        A := add(x_2, z_2)
        AA := pow(A, TWO)
        B := sub(x_2, z_2)
        BB := pow(B, TWO)
        E := sub(AA, BB)
        C := add(x_3, z_3)
        D := sub(x_3, z_3)
        DA := mul(D, A)
        CB := mul(C, B)

        x_3 = pow(add(DA, CB), TWO)
        z_3 = mul(x_1, pow(sub(DA, CB), TWO))
        x_2 = mul(AA, BB)
        z_2 = mul(E, add(AA, mul(a24, E)))
    }
    x_2, x_3 = cswap(swap, x_2, x_3)
    z_2, z_3 = cswap(swap, z_2, z_3)
    res := mul(x_2, pow(z_2, (sub(p, TWO))))
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
