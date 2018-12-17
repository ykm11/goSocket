package testdata

import (
    "testing"
    "reflect"
    "../encryption"
)

func TestPoly1(t *testing.T) {
    key := []byte{
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    }
    nonce := []byte{
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    }
    poly_key := encryption.Poly1305_key_gen(key, nonce)
    expected_key := []byte{
        0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90,
        0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd, 0x28,
        0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a,
        0xa8, 0x36, 0xef, 0xcc, 0x8b, 0x77, 0x0d, 0xc7,
    }
    if !reflect.DeepEqual(poly_key, expected_key) {
        t.Fatal("Wrong")
    }
}

func TestPoly2(t *testing.T) {
    key := []byte{
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    }
    nonce := []byte{
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x02,
    }
    poly_key := encryption.Poly1305_key_gen(key, nonce)
    expected_key := []byte{
        0xec, 0xfa, 0x25, 0x4f, 0x84, 0x5f, 0x64, 0x74,
        0x73, 0xd3, 0xcb, 0x14, 0x0d, 0xa9, 0xe8, 0x76,
        0x06, 0xcb, 0x33, 0x06, 0x6c, 0x44, 0x7b, 0x87,
        0xbc, 0x26, 0x66, 0xdd, 0xe3, 0xfb, 0xb7, 0x39,
    }
    if !reflect.DeepEqual(poly_key, expected_key) {
        t.Fatal("Wrong")
    }
}

func TestPoly3(t *testing.T) {
    key := []byte{
        0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a,
        0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
        0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09,
        0x9d, 0xca, 0x5c, 0xbc, 0x20, 0x70, 0x75, 0xc0,
    }
    nonce := []byte{
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x02,
    }
    poly_key := encryption.Poly1305_key_gen(key, nonce)
    expected_key := []byte{
        0x96, 0x5e, 0x3b, 0xc6, 0xf9, 0xec, 0x7e, 0xd9,
        0x56, 0x08, 0x08, 0xf4, 0xd2, 0x29, 0xf9, 0x4b,
        0x13, 0x7f, 0xf2, 0x75, 0xca, 0x9b, 0x3f, 0xcb,
        0xdd, 0x59, 0xde, 0xaa, 0xd2, 0x33, 0x10, 0xae,
    }
    if !reflect.DeepEqual(poly_key, expected_key) {
        t.Fatal("Wrong")
    }
}

func TestPolyTag1(t *testing.T) {
    key := []byte{
        0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a,
        0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
        0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09,
        0x9d, 0xca, 0x5c, 0xbc, 0x20, 0x70, 0x75, 0xc0,
    }
    msg := []byte{
        0x27, 0x54, 0x77, 0x61, 0x73, 0x20, 0x62, 0x72,
        0x69, 0x6c, 0x6c, 0x69, 0x67, 0x2c, 0x20, 0x61,
        0x6e, 0x64, 0x20, 0x74, 0x68, 0x65, 0x20, 0x73,
        0x6c, 0x69, 0x74, 0x68, 0x79, 0x20, 0x74, 0x6f,
        0x76, 0x65, 0x73, 0x0a, 0x44, 0x69, 0x64, 0x20,
        0x67, 0x79, 0x72, 0x65, 0x20, 0x61, 0x6e, 0x64,
        0x20, 0x67, 0x69, 0x6d, 0x62, 0x6c, 0x65, 0x20,
        0x69, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x77,
        0x61, 0x62, 0x65, 0x3a, 0x0a, 0x41, 0x6c, 0x6c,
        0x20, 0x6d, 0x69, 0x6d, 0x73, 0x79, 0x20, 0x77,
        0x65, 0x72, 0x65, 0x20, 0x74, 0x68, 0x65, 0x20,
        0x62, 0x6f, 0x72, 0x6f, 0x67, 0x6f, 0x76, 0x65,
        0x73, 0x2c, 0x0a, 0x41, 0x6e, 0x64, 0x20, 0x74,
        0x68, 0x65, 0x20, 0x6d, 0x6f, 0x6d, 0x65, 0x20,
        0x72, 0x61, 0x74, 0x68, 0x73, 0x20, 0x6f, 0x75,
        0x74, 0x67, 0x72, 0x61, 0x62, 0x65, 0x2e,
    }
    expected_tag := []byte{
        0x45, 0x41, 0x66, 0x9a, 0x7e, 0xaa, 0xee, 0x61,
        0xe7, 0x08, 0xdc, 0x7c, 0xbc, 0xc5, 0xeb, 0x62,
    }
    tag := encryption.Poly1305_mac(msg, key)

    if !reflect.DeepEqual(tag, expected_tag) {
        t.Fatal("Wrong")
    }
}
