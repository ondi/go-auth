//
//
//

package auth

import (
	"bytes"
	"os"
	"path/filepath"

	"github.com/ondi/go-jwt"
)

type Key_t struct {
	Value []byte
	Hmac  bool // use symmetric HMAC, if true options below ignored
	Cert  bool // use ParseCertificate or ParsePublicKey
	DER   bool // format, default PEM
}

func AppendKeysGlob(in []Key_t, pattern string, Hmac bool, Cert bool, DER bool) ([]Key_t, error) {
	matched, err := filepath.Glob(pattern)
	if err != nil {
		return in, err
	}
	key := Key_t{
		Hmac: Hmac,
		Cert: Cert,
		DER:  DER,
	}
	for _, v := range matched {
		if key.Value, err = os.ReadFile(v); err != nil {
			return in, err
		}
		in = append(in, key)
	}
	return in, err
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
