package encryption

import (
    "fmt"
    "math/big"
)

func Poly1305_key_gen(key, nonce []byte) []byte {
    /*
        poly1305_key_gen(key,nonce):
            counter = 0
            block = chacha20_block(key,counter,nonce)
            return block[0..31]
            end
    */
    le_key := Le_4_arrays(key)
    le_nonce := Le_4_arrays(nonce)
    state := Chacha20_block(le_key, 0, le_nonce)
    poly_key := State_2_Key(state)

    return poly_key
}

func Poly1305_mac(msg, key []byte) []byte {
    /*
        poly1305_mac(msg, key):
            r = (le_bytes_to_num(key[0..15])
            clamp(r)
            s = le_num(key[16..31])
            accumulator = 0
            p = (1<<130)-5
            for i=1 upto ceil(msg length in bytes / 16)
               n = le_bytes_to_num(msg[((i-1)*16)..(i*16)] | [0x01])
               a += n
               a = (r * a) % p
               end
            a += s
            return num_to_16_le_bytes(a)
            end
    */
    if len(key) != 32 {
        panic("Key length should be 32")
    }
    s := Le_bytes_to_num(key[16:])
    r_bytes := key[:16]
    Clamp(r_bytes)
    r := Le_bytes_to_num(r_bytes)
    fmt.Printf("[+] r :%x\n", r)
    fmt.Printf("[+] s :%x\n\n\n", s)


    base := big.NewInt(2)
    e := big.NewInt(130)
    five := big.NewInt(5)
    p := big.NewInt(0)
    p.Exp(base, e, nil).Sub(p, five)


    acc := big.NewInt(0)
    for i := 1; i < len(msg)/16+1; i++ {
        val := make([]byte, 16)
        copy(val, msg[(i-1)*16 : i*16])
        val = append(val, 0x01)
        fmt.Printf("[+] Val : %x\n", val)

        n := Le_bytes_to_num(val)
        fmt.Printf("[+] n : %x\n", n)

        acc.Add(acc, n)
        fmt.Printf("[+] Acc : %x\n", acc)
        acc.Mul(acc, r)
        fmt.Printf("[+] Acc * n : %x\n", acc)
        acc.Mod(acc, p)
        fmt.Printf("[+] Acc * n mod P: %x\n", acc)

        fmt.Println()
    }
    if len(msg) % 16 != 0 {
        val := make([]byte, len(msg)%16)
        i := len(msg)/16
        copy(val, msg[ i*16 : i*16 + len(msg)%16])
        val = append(val, 0x01)
        fmt.Printf("[+] Val : %x\n", val)

        n := Le_bytes_to_num(val)
        fmt.Printf("[+] n : %x\n", n)

        acc.Add(acc, n)
        fmt.Printf("[+] Acc : %x\n", acc)
        acc.Mul(acc, r)
        fmt.Printf("[+] Acc * n : %x\n", acc)
        acc.Mod(acc, p)
        fmt.Printf("[+] Acc * n mod P: %x\n", acc)

        fmt.Println()
    }
    acc.Add(acc, s)
    fmt.Printf("[+] Acc + s : %x\n", acc)
    acc.Mod(acc, new(big.Int).Lsh(base, 127))

    tag := Le_num_to_bytes(acc)

    return tag
}
