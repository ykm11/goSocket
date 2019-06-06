package testdata


import (
    "testing"
    "reflect"
    "../encryption"
)

var (
    base_point_x25519 = encryption.EncodeUCoordinate(encryption.U_x25519, 255)
    base_point_x448 = encryption.EncodeUCoordinate(encryption.U_x448, 448)
)

// https://tools.ietf.org/html/rfc7748#section-6.1
func TestECDHE1(t *testing.T) {

    alice_sec_bytes := encryption.Hex2Bytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    alice_pub := encryption.X25519(alice_sec_bytes, base_point_x25519)
    expected_alice_pub := encryption.Hex2Bytes("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")

    bob_sec_bytes := encryption.Hex2Bytes("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    bob_pub := encryption.X25519(bob_sec_bytes, base_point_x25519)
    expected_bob_pub := encryption.Hex2Bytes("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")

    alice_shared_key := encryption.X25519(alice_sec_bytes, bob_pub)
    bob_shared_key := encryption.X25519(bob_sec_bytes, alice_pub)

    if !reflect.DeepEqual(expected_alice_pub, alice_pub) {
        t.Fatal("Alice's Pub key is not correct")
    }
    if !reflect.DeepEqual(expected_bob_pub, bob_pub) {
        t.Fatal("Bob's Pub key is not correct")
    }
    if !reflect.DeepEqual(alice_shared_key, bob_shared_key) {
        t.Fatal("Shared keys are not same")
    }

    expected_shared_key := encryption.Hex2Bytes("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
    if !reflect.DeepEqual(expected_shared_key, alice_shared_key) {
        t.Fatal("Shared keys are not same")
    }
}

func TestECDHE2(t *testing.T) {

    alice_sec_bytes := encryption.Hex2Bytes("9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b")
    alice_pub := encryption.X448(alice_sec_bytes, base_point_x448)
    expected_alice_pub := encryption.Hex2Bytes("9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0")

    bob_sec_bytes := encryption.Hex2Bytes("1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d")
    bob_pub := encryption.X448(bob_sec_bytes, base_point_x448)
    expected_bob_pub := encryption.Hex2Bytes("3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609")

    alice_shared_key := encryption.X448(alice_sec_bytes, bob_pub)
    bob_shared_key := encryption.X448(bob_sec_bytes, alice_pub)

    if !reflect.DeepEqual(expected_alice_pub, alice_pub) {
        t.Fatal("Alice's Pub key is not correct")
    }
    if !reflect.DeepEqual(expected_bob_pub, bob_pub) {
        t.Fatal("Bob's Pub key is not correct")
    }
    if !reflect.DeepEqual(alice_shared_key, bob_shared_key) {
        t.Fatal("Shared keys are not same")
    }

    expected_shared_key := encryption.Hex2Bytes("07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d")
    if !reflect.DeepEqual(expected_shared_key, alice_shared_key) {
        t.Fatal("Shared keys are not same")
    }

}
