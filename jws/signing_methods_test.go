package jws

import (
	"crypto"
	_ "crypto/sha256"
	"testing"

	c "github.com/SermoDigital/jose/crypto"
)

// MySigningMethod is a custom signing method that does not require hashing.
var MySigningMethod = &TestSigningMethod{
	Name: "SuperSignerAlgorithm1000",
	Hash: crypto.Hash(0),
}

type TestSigningMethod struct {
	Name string
	Hash crypto.Hash
}

func (m *TestSigningMethod) Verify(_ []byte, _ c.Signature, _ interface{}) error {
	return nil
}

func (m *TestSigningMethod) Sign(_ []byte, _ interface{}) (c.Signature, error) {
	return nil, nil
}

func (m *TestSigningMethod) Alg() string         { return m.Name }
func (m *TestSigningMethod) Sum(b []byte) []byte { return nil }
func (m *TestSigningMethod) Hasher() crypto.Hash { return m.Hash }

func TestZeroHashNotRegistered(t *testing.T) {
	if crypto.Hash(0).Available() {
		t.Error("the zero hash must remain unregistered")
	}
}

func TestRegisterSigningMethod(t *testing.T) {
	methods := []*TestSigningMethod{
		MySigningMethod,
		{Name: "SHA256Algorithm", Hash: crypto.SHA256},
	}

	for _, method := range methods {
		RegisterSigningMethod(method)
		defer RemoveSigningMethod(method)

		if got := GetSigningMethod(method.Alg()); got != method {
			t.Errorf("GetSigningMethod(%q) = %v, want %v", method.Alg(), got, method)
		}
	}
}

func TestRemoveSigningMethod(t *testing.T) {
	RegisterSigningMethod(MySigningMethod)

	if GetSigningMethod("SuperSignerAlgorithm1000") == nil {
		t.Error("Expected SuperSignerAlgorithm1000, got nil")
	}

	RemoveSigningMethod(MySigningMethod)

	if a := GetSigningMethod("SuperSignerAlgorithm1000"); a != nil {
		t.Errorf("Expected nil, got %v", a)
	}
}

func TestRegisterSigningMethodUnavailableHash(t *testing.T) {
	sm := &TestSigningMethod{
		Name: "UnavailableHashAlgorithm",
		Hash: crypto.MD4,
	}

	if sm.Hasher().Available() {
		t.Skip("crypto.MD4 is registered in this build")
	}

	defer RemoveSigningMethod(sm)
	defer func() {
		if got := recover(); got != "jose/jws: specific hash is unavailable" {
			t.Errorf("expected unavailable-hash panic, got %v", got)
		}
		if got := GetSigningMethod(sm.Alg()); got != nil {
			t.Errorf("an unavailable-hash signing method was registered: %v", got)
		}
	}()

	RegisterSigningMethod(sm)
}
