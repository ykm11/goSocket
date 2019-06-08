package utils

import (
    "hash"
    "crypto/sha256"
    "crypto/sha512"
    "crypto/hmac"

    "../encryption"
    "fmt"
)


func b2i(b bool) uint64 {
    if b {
        return uint64(1)
    } else {
        return uint64(0)
    }
}

func divceil(divident, divisor uint64) uint64 {
    return (divident / divisor) + b2i(divident % divisor != 0)
}

func SecureHash(data []byte, hash_algorithm string) []byte {
    var hashData []byte
    var hasher hash.Hash

    switch hash_algorithm {
    case "sha256", "SHA256":
        hasher = sha256.New()
    case "sha384", "SHA384":
        hasher = sha512.New384()
    case "sha512", "SHA512":
        hasher = sha512.New()
    default:
        hasher = sha256.New()
    }

    hasher.Write(data)
    hashData = hasher.Sum(nil)
    return hashData
}

func SecureHMAC(key, message []byte, hash_algorithm string) []byte {
    var mac hash.Hash
    switch hash_algorithm {
    case "sha256", "SHA256":
        mac = hmac.New(sha256.New, key)
    case "sha512", "SHA512":
        mac = hmac.New(sha512.New, key)
    default:
        mac = hmac.New(sha256.New, key)
    }
    mac.Write(message)
    return mac.Sum(nil)
}

/*
    HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
    https://tools.ietf.org/html/rfc5869
*/
func HKDF_extract(salt, IKM []byte, hash_algorithm string) []byte {
    /*
       HKDF-Extract(salt, IKM) -> PRK

       Options:
          Hash     a hash function; HashLen denotes the length of the
                   hash function output in octets

       Inputs:
          salt     optional salt value (a non-secret random value);
                   if not provided, it is set to a string of HashLen zeros.
          IKM      input keying material

       Output:
          PRK      a pseudorandom key (of HashLen octets)

       The output PRK is calculated as follows:

       PRK = HMAC-Hash(salt, IKM)

    */
    return SecureHMAC(salt, IKM, hash_algorithm)
}

func HKDF_expand(PRK, info []byte, L uint64, hash_algorithm string) []byte {
    /*
        HKDF-Expand(PRK, info, L) -> OKM

        Options:
            Hash     a hash function; HashLen denotes the length of the
                   hash function output in octets

        Inputs:
            PRK      a pseudorandom key of at least HashLen octets
                   (usually, the output from the extract step)
            info     optional context and application specific information
                   (can be a zero-length string)
            L        length of output keying material in octets
                   (<= 255*HashLen)

        Output:
            OKM      output keying material (of L octets)

            The output OKM is calculated as follows:

            N = ceil(L/HashLen)
            T = T(1) | T(2) | T(3) | ... | T(N)
            OKM = first L octets of T

            where:
            T(0) = empty string (zero length)
            T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
            T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
            T(3) = HMAC-Hash(PRK, T(2) | info | 0x03)
            ...

            (where the constant concatenated to the end of each T(n) is a
            single octet.)

    */
    var hashSize uint64
    switch hash_algorithm {
    case "sha256", "SHA256":
        hashSize = sha256.Size
    case "sha512", "SHA512":
        hashSize = sha512.Size
    default:
        hashSize = sha256.Size
    }

    N := divceil(L, hashSize)
    T := []byte{}
    T_prev := []byte{}
    for i := 1; i < int(N) + 2; i++ {
        T = append(T, T_prev...)
        tmp := append(T_prev, info...)
        tmp = append(tmp, []byte{byte(i)}...)
        T_prev = SecureHMAC(PRK, tmp, hash_algorithm)
    }
    return T[:L]
}


func HKDF_expand_label(secret, label, hashValue []byte, length uint64, hash_algorithm string) []byte {
    /*
    def HKDF_expand_label(secret, label,
                          hashValue, length,
                          hash_algorithm='sha256') -> bytearray:

        TLS1.3 key derivation function (HKDF-Expand-Label).
        :param bytearray secret: the key from which to derive the keying material
        :param bytearray label: label used to differentiate the keying materials
        :param bytearray hashValue: bytes used to "salt" the produced keying
            material
        :param int length: number of bytes to produce
        :param str hash_algorithm: name of the secure hash hash_algorithm used as the
            basis of the HKDF
        :rtype: bytearray

        HKDF-Expand-Label(Secret, Label, Context, Length) =
            HKDF-Expand(Secret, HkdfLabel, Length)

            Where HkdfLabel is specified as:

            struct {
                uint16 length = Length;
                opaque label<7..255> = "tls13 " + Label;
                opaque context<0..255> = Context;
            } HkdfLabel;
    */
    label_ := append([]byte("tls13 "), label...)
    bytes_length := encryption.NumTo2Bytes(uint16(length))

    HkdfLabel := []byte{}
    HkdfLabel = append(HkdfLabel, bytes_length...)
    HkdfLabel = append(HkdfLabel, byte(len(label_)))
    HkdfLabel = append(HkdfLabel, label_...)
    HkdfLabel = append(HkdfLabel, byte(len(hashValue)))
    HkdfLabel = append(HkdfLabel, hashValue...)

    fmt.Printf("[+] HKDF Label: %x\n", HkdfLabel)
    return HKDF_expand(secret, HkdfLabel, length, hash_algorithm)
}

func Derive_secret(secret, label []byte, messages [][]byte, hash_algorithm string) []byte {
    /*

    */
    var hashSize uint64
    switch hash_algorithm {
    case "sha256", "SHA256":
        hashSize = sha256.Size
    default:
        hashSize = sha256.Size
    }

    if len(messages) == 0 {
        messages_hash := SecureHash([]byte{}, hash_algorithm)
        return HKDF_expand_label(secret, label, messages_hash, hashSize, hash_algorithm)
    } else {
        messages_hash := Transcript_hash(messages, hash_algorithm)
        return HKDF_expand_label(secret, label, messages_hash, hashSize, hash_algorithm)
    }
}

func Transcript_hash(messages [][]byte, hash_algorithm string) []byte {
    /*

    */
    data := []byte{}
    if len(messages) == 1 {
        data = append(data, messages[0]...)
    } else {
        for i := 0; i < len(messages); i++ {
            data = append(data, messages[i]...)
        }
    }
    hs_val := SecureHash(data, hash_algorithm)
    return hs_val
}

func Gen_key_and_iv(secret []byte, key_size, nonce_size uint64, hash_algorithm string) ([]byte, []byte) {
    /*

    */
    write_key := HKDF_expand_label(secret, []byte("key"), []byte{}, key_size, hash_algorithm)
    write_iv := HKDF_expand_label(secret, []byte("iv"), []byte{}, nonce_size, hash_algorithm)
    return write_key, write_iv
}
