//
//
//

package auth

import (
	"bytes"
	"os"
	"strings"

	"github.com/ondi/go-jwt"
)

type Type int

const (
	TYPE_PEM Type = 1
	TYPE_DER Type = 2
)

type Key_t struct {
	Value []byte
	Type  Type
	Hmac  bool
	Cert  bool
}

type Signer interface {
	Sign(bits int64, payload []byte, out *bytes.Buffer) error
}

type Sign_t struct {
	signer jwt.Signer
}

func ReadFile(in string) (out Key_t, err error) {
	if out.Value, err = os.ReadFile(in); err != nil {
		return
	}
	if strings.Contains(in, "cert") {
		out.Cert = true
	}
	if strings.Contains(in, "hmac") {
		out.Hmac = true
	}
	if strings.HasSuffix(in, ".der") {
		out.Type = TYPE_DER
	} else {
		out.Type = TYPE_PEM
	}
	return
}

func NewSign(in Key_t) (out *Sign_t, err error) {
	var res jwt.Signer
	switch {
	case in.Hmac:
		res, err = jwt.NewHmacKey(in.Value)
	case in.Type == TYPE_DER:
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
