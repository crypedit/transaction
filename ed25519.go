package transaction

import "golang.org/x/crypto/ed25519"

func SignerEd25519(privkey []byte) Signer {
	return signerEd25519{privkey}
}

func VerifierEd25519(publickey []byte) Verifier {
	return verifierEd25519{publickey}
}

type signerEd25519 struct {
	privkey []byte
}

type verifierEd25519 struct {
	publickey []byte
}

func (s signerEd25519) Sign(t *Transaction) (err error) {
	t.sig, err = s.sign(s.privkey, t.msg)
	return err
}

func (s signerEd25519) sign(key []byte, msg []byte) (signature []byte, err error) {
	priv := ed25519.PrivateKey(key)
	signature = ed25519.Sign(priv, msg)
	return
}

func (v verifierEd25519) Verify(t *Transaction) error {
	if len(t.sig) == 0 {
		return NOT_SIGNED
	}
	return v.verify(v.publickey, t.msg, t.sig)
}

func (v verifierEd25519) verify(key []byte, msg []byte, sig []byte) error {
	public := ed25519.PublicKey(key)
	valid := ed25519.Verify(public, msg, sig)
	if !valid {
		return INVALID_SIG
	}
	return nil
}
