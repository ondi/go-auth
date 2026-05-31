//
//
//

package auth

import (
	"bytes"

	"github.com/ondi/go-jwt"
)

type Key_t struct {
	Value []byte
	Id    string
	Hmac  bool // use symmetric HMAC, if true options below ignored
	Cert  bool // use ParseCertificate or ParsePublicKey
	DER   bool // format, default PEM
}

type Signer interface {
	Sign(bits int64, payload []byte, out *bytes.Buffer) error
}

type Sign_t struct {
	signer jwt.Signer
}

func NewSign(key Key_t) (out *Sign_t, err error) {
	var res jwt.Signer
	switch {
	case key.Hmac:
		res, err = jwt.NewHmacKey(key.Id, key.Value)
	case key.DER:
		res, err = jwt.NewSignDer(key.Id, key.Value)
	default:
		res, err = jwt.NewSignPem(key.Id, key.Value)
	}
	if err != nil {
		return
	}
	out = &Sign_t{signer: res}
	return
}

func (self *Sign_t) Sign(bits int64, payload []byte, out *bytes.Buffer) error {
	return jwt.Sign(self.signer, bits, payload, out)
}

type NoSing_t struct{}

func (NoSing_t) Sign(bits int64, payload []byte, out *bytes.Buffer) error {
	return nil
}
