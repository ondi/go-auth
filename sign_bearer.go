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

type Signer interface {
	Sign(bits int64, payload []byte, out *bytes.Buffer) error
}

type Sign_t struct {
	signer jwt.Signer
}

func NewSign(file string) (out *Sign_t, err error) {
	buf, err := os.ReadFile(file)
	if err != nil {
		return
	}
	var res jwt.Signer
	if strings.Contains(file, "hmac") {
		res, err = jwt.NewHmacKey(buf)
	} else if strings.HasSuffix(file, ".der") {
		res, err = jwt.NewSignDer(buf)
	} else {
		res, err = jwt.NewSignPem(buf)
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