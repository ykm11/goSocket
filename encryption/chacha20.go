package encryption

import "fmt"


func Chacha20_inner_block(state []uint32) {
    /*
        state : c + k + b + n
	    1.  QUARTERROUND ( 0, 4, 8,12)
      	2.  QUARTERROUND ( 1, 5, 9,13)
	    3.  QUARTERROUND ( 2, 6,10,14)
	    4.  QUARTERROUND ( 3, 7,11,15)
	    5.  QUARTERROUND ( 0, 5,10,15)
	    6.  QUARTERROUND ( 1, 6,11,12)
      	7.  QUARTERROUND ( 2, 7, 8,13)
        8.  QUARTERROUND ( 3, 4, 9,14)
    */

    // Column
    state[0], state[4], state[8], state[12] = QuarterRound(state[0], state[4], state[8], state[12])
    state[1], state[5], state[9], state[13] = QuarterRound(state[1], state[5], state[9], state[13])
    state[2], state[6], state[10], state[14] = QuarterRound(state[2], state[6], state[10], state[14])
    state[3], state[7], state[11], state[15] = QuarterRound(state[3], state[7], state[11], state[15])

    // Diagonal
    state[0], state[5], state[10], state[15] = QuarterRound(state[0], state[5], state[10], state[15])
    state[1], state[6], state[11], state[12] = QuarterRound(state[1], state[6], state[11], state[12])
    state[2], state[7], state[8], state[13] = QuarterRound(state[2], state[7], state[8], state[13])
    state[3], state[4], state[9], state[14] = QuarterRound(state[3], state[4], state[9], state[14])
}

func Chacha20_block(key []uint32, conter uint32, nonce []uint32) []uint32 {
    /*
        state = constants | key | counter | nonce
        working_state = state
        for i=1 upto 10
           inner_block(working_state)
           end
        state += working_state
        return serialize(state)
        end
    */
    constants := []uint32 {
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
    }
    counter_block := []uint32 { conter }
    state := append(constants, key...)
    state = append(state, counter_block...)
    state = append(state, nonce...)

    fmt.Printf("[+] Initial State : %x\n", state)
    working_state := make([]uint32, 16)
    copy(working_state, state)

    for i := 0; i < 10; i++ {
        Chacha20_inner_block(working_state)
    }

    for i:= 0; i < 16; i++ {
        state[i] = state[i] + working_state[i]
    }

    for i:= 0; i < 16; i++ {
        state[i] = Le_4(state[i])
    }

    fmt.Printf("[+] State : %x\n", state)
    return state
}

func Chacha20_encrypt(key []byte, counter uint32, nonce []byte, plaintext []byte) []byte {
    /*
        for j = 0 upto floor(len(plaintext)/64)-1
           key_stream = chacha20_block(key, counter+j, nonce)
           block = plaintext[(j*64)..(j*64+63)]
           encrypted_message +=  block ^ key_stream
           end
        if ((len(plaintext) % 64) != 0)
           j = floor(len(plaintext)/64)
           key_stream = chacha20_block(key, counter+j, nonce)
           block = plaintext[(j*64)..len(plaintext)-1]
           encrypted_message += (block^key_stream)[0..len(plaintext)%64]
           end
        return encrypted_message
        end
    */
    if len(key) != 32 {
        panic("Key length should be 32")
    }
    if len(nonce) != 12 {
        panic("Nonce length should be 12")
    }

    le_key := Le_4_arrays(key)
    le_nonce := Le_4_arrays(nonce)
    enc := []byte{}
    for j := 0; j < len(plaintext)/64; j++ {
        key_stream := Chacha20_block(le_key, counter+uint32(j), le_nonce)
        block := plaintext[j*64 : j*64+64]
        fmt.Printf("[+] Key Strem: %x\n", key_stream)
        fmt.Printf("[+] Block: % x\n", block)
        fmt.Printf("[+] Block len: %d\n\n", len(block))

        d := EncXor(key_stream, block)
        enc = append(enc, d...)
    }
    if len(plaintext) % 64 != 0 {
        j := len(plaintext)/64
        key_stream := Chacha20_block(le_key, counter+uint32(j), le_nonce)
        block := plaintext[j*64 : (j*64)+(len(plaintext)%64)]
        fmt.Printf("[+] Key Strem: %x\n", key_stream)
        fmt.Printf("[+] Block: % x\n", block)
        fmt.Printf("[+] Block len: %d\n\n", len(block))

        d := EncXor(key_stream, block)
        enc = append(enc, d...)
    }
    return enc
}

func EncXor(key []uint32, block []byte) []byte {
    stream := []byte{}

    for i := 0; i < len(block); i++ {
        val := uint8((key[i / 4] >> uint32(0x08*(3 - (i % 4)))) & 0xFF)
        stream = append(stream, val ^ block[i])
    }
    return stream
}

func Chacha20_aead_encrypt(aad, key, iv, constant, plaintext []byte) ([]byte, []byte) {
    /*
        chacha20_aead_encrypt(aad, key, iv, constant, plaintext):
            nonce = constant | iv
            otk = poly1305_key_gen(key, nonce)
            ciphertext = chacha20_encrypt(key, 1, nonce, plaintext)
            mac_data = aad | pad16(aad)
            mac_data |= ciphertext | pad16(ciphertext)
            mac_data |= num_to_4_le_bytes(aad.length)
            mac_data |= num_to_4_le_bytes(ciphertext.length)
            tag = poly1305_mac(mac_data, otk)
            return (ciphertext, tag)
    */
    nonce := append(constant, iv...)
    otk := Poly1305_key_gen(key, nonce)
    ciphertext := Chacha20_encrypt(key, 1, nonce, plaintext)
    mac_data := append(aad, Pad16(aad)...)
    mac_data = append(mac_data, ciphertext...)
    mac_data = append(mac_data, Pad16(ciphertext)...)
    mac_data = append(mac_data, Length_8_bytes(aad)...)
    mac_data = append(mac_data, Length_8_bytes(ciphertext)...)
    tag := Poly1305_mac(mac_data, otk)

    fmt.Printf("[+] AEAD : %x\n", mac_data)
    return ciphertext, tag
}
