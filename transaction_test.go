package transaction

import (
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/ed25519"
)

func TestTransaction(t *testing.T) {
	public, priv, _ := ed25519.GenerateKey(rand.Reader)

	signer := SignerEd25519(priv)
	verifier := VerifierEd25519(public)

	transaction := Transaction{
		msg: []byte("I owe Bob a coin"),
	}

	err := signer.Sign(&transaction)
	if err != nil {
		t.Error(err.Error())
	}
	err = verifier.Verify(&transaction)
	if err != nil {
		t.Error(err.Error())
	}
}

func TestInvalidTransaction(t *testing.T) {
	public, _, _ := ed25519.GenerateKey(rand.Reader)

	verifier := VerifierEd25519(public)

	transaction := Transaction{
		msg: []byte("I owe Bob a coin"),
	}

	transaction.sig = []byte{}
	err := verifier.Verify(&transaction)
	if err != NOT_SIGNED {
		t.Error(err.Error())
	}

	transaction.sig = []byte("an invalid signature")
	err = verifier.Verify(&transaction)
	if err != INVALID_SIG {
		t.Error(err.Error())
	}
}
