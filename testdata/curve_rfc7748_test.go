package testdata


import (
    "testing"
    "reflect"
    "math/big"
    curve "../encryption/ecc"
    "../encryption"
)

var (
    base_point = curve.EncodeUCoordinate(curve.U, 255)
)

// https://tools.ietf.org/html/rfc7748#section-6.1
func TestEcc1(t *testing.T) {

    alice_sec := new(big.Int)
    alice_sec, _ = alice_sec.SetString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", 16)
    alice_sec_bytes := alice_sec.Bytes()
    alice_pub := curve.X25519(alice_sec_bytes, base_point)
    expected_alice_pub := encryption.Hex2Bytes("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")

    bob_sec := new(big.Int)
    bob_sec, _ = bob_sec.SetString("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb", 16)
    bob_sec_bytes := bob_sec.Bytes()
    bob_pub := curve.X25519(bob_sec_bytes, base_point)
    expected_bob_pub := encryption.Hex2Bytes("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")

    alice_shared_key := curve.X25519(alice_sec_bytes, bob_pub)
    bob_shared_key := curve.X25519(bob_sec_bytes, alice_pub)

    if !reflect.DeepEqual(expected_alice_pub, alice_pub) {
        t.Fatal("Shared keys are not same")
    }
    if !reflect.DeepEqual(expected_bob_pub, bob_pub) {
        t.Fatal("Shared keys are not same")
    }
    if !reflect.DeepEqual(alice_shared_key, bob_shared_key) {
        t.Fatal("Shared keys are not same")
    }
}
