package encryption

func add(x, y uint32) uint32 {
    return x + y
}

func xor(x, y uint32) uint32 {
    return x ^ y
}

func leftRotate(data uint32, n uint8) uint32 {
    left := data << n
    right := data >> (32 - n)
    return left | right
}

func QuarterRound(a, b, c, d uint32) (uint32, uint32, uint32, uint32) {
    /*
        1.  a += b; d ^= a; d <<<= 16;
        2.  c += d; b ^= c; b <<<= 12;
        3.  a += b; d ^= a; d <<<= 8;
        4.  c += d; b ^= c; b <<<= 7;
    */
    a = add(a, b); d = xor(d, a); d = leftRotate(d, 16)
    c = add(c, d); b = xor(b, c); b = leftRotate(b, 12)
    a = add(a, b); d = xor(d, a); d = leftRotate(d, 8)
    c = add(c, d); b = xor(b, c); b = leftRotate(b, 7)

    return a, b, c, d
}

func Clamp(r []byte) {
    // clamp(r): r &= 0x0ffffffc0ffffffc0ffffffc0fffffff
    if len(r) != 16 {
        panic("r length should be 16")
    }
    r[3] &= 15
    r[7] &= 15
    r[11] &= 15
    r[15] &= 15
    r[4] &= 252
    r[8] &= 252
    r[12] &= 252
}
