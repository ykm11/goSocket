package encryption

import (
    "math/big"
    "encoding/hex"
)

func Le_4(data uint32) uint32 {
    d1 := (data & 0xFF) << 0x18
    d2 := (data >> 0x08 & 0xFF) << 0x10
    d3 := (data >> 0x10 & 0xFF) << 0x08
    d4 := (data >> 0x18 & 0xFF)
    return d1 | d2 | d3 | d4
}

func Le_4_arrays(data []byte) []uint32 {
    if len(data) % 4 != 0 {
        panic("Data length should be 16 * t bytes")
    }
    results := make([]uint32, len(data)/4)

    for i := 0; i < len(data)/4; i++ {
        d1 := uint32(data[4*i + 0]) << 0x00
        d2 := uint32(data[4*i + 1]) << 0x08
        d3 := uint32(data[4*i + 2]) << 0x10
        d4 := uint32(data[4*i + 3]) << 0x18
        results[i] = d1 | d2 | d3 | d4
    }

    return results
}

func Le_bytes(data []byte) {
    for i := 0; i < len(data)/2; i++ { // Just swapping
        data[i], data[len(data)-i-1] = data[len(data)-i-1], data[i]
    }
}

func Le_bytes_to_num(data []byte) *big.Int{
    n := big.NewInt(0)
    for i := 0; i < len(data); i++ {
        val := big.NewInt(int64(data[i]))
        val.Lsh(val, uint(i*0x08))
        n.Add(n, val)
    }

    return n
}

func Le_num_to_bytes(x *big.Int) []byte {
    y := big.NewInt(0)
    for i := 0; i < 16; i++ {
        y.Lsh(y, uint(0x08))
        y.Add(y, new(big.Int).And(x, big.NewInt(0xFF)))

        x.Rsh(x, uint(0x08))
    }
    return y.Bytes()
}

func Length_8_bytes(bytes []byte) []byte {
    // リトルエンディアン (Chacha20のAEAD)
    x := uint64(len(bytes))
    data := make([]byte, 8)
    for i := 0; i < 8; i++ {
        data[i] = byte(x >> uint64(i*0x08) & 0xFF)
    }
    return data
}

func NumTo2Bytes(x uint16) []byte {
    data := make([]byte, 2)
    data[0] = byte(x >> 0x08 & 0xFF)
    data[1] = byte(x >> 0x00 & 0xFF)
    return data
}

func State_2_Key(state []uint32) []byte {
    key := make([]byte, 32)

    for i := 0; i < 8; i++ {
        block := state[i]
        key[4*i + 3] = byte(block >> 0x00 & 0xFF)
        key[4*i + 2] = byte(block >> 0x08 & 0xFF)
        key[4*i + 1] = byte(block >> 0x10 & 0xFF)
        key[4*i + 0] = byte(block >> 0x18 & 0xFF)
    }

    return key
}

func Pad16(x []byte) []byte {
    if len(x) % 16 == 0 {
        return []byte{}
    }
    padding := make([]byte, 16 - len(x) % 16)
    return padding
}

func Hex2Bytes(s string) []byte {
    decoded, err := hex.DecodeString(s)
    if err != nil {
        panic("Error occured during decoding string.")
    }
    return decoded
}

func Str2Int(str string, base int) *big.Int {
    n, ok := new(big.Int).SetString(str, base)
    if !ok {
        panic("UWAAAAAAAAAAA")
    }
    return n
}

