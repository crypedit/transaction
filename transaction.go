package transaction

import "fmt"

var NOT_SIGNED = fmt.Errorf("not signed")
var INVALID_SIG = fmt.Errorf("invalid signature")

type Signer interface {
	Sign(*Transaction) error
}
type Verifier interface {
	Verify(*Transaction) error
}

type Transaction struct {
	msg []byte
	sig []byte
}
