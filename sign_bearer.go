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

func NewSign(in Key_t) (out *Sign_t, err error) {
	var res jwt.Signer
	switch {
	case in.Hmac:
		res, err = jwt.NewHmacKey(in.Value)
	case in.DER:
		res, err = jwt.NewSignDer(in.Value)
	default:
		res, err = jwt.NewSignPem(in.Value)
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
