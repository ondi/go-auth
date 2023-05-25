//
//
//

package auth

import (
	"bytes"
	"errors"
	"io/ioutil"
	"strings"

	"github.com/ondi/go-jwt"
)

var NOT_INITIALIZED = errors.New("NOT INITIALIZED")

type Signer interface {
	Sign(bits int64, payload []byte, out *bytes.Buffer) error
}

type Sign_t struct {
	jwt.Signer
}

func NewSign(file string) (out Signer, err error) {
	buf, err := ioutil.ReadFile(file)
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
	out = &Sign_t{Signer: res}
	return
}

func (self Sign_t) Sign(bits int64, payload []byte, out *bytes.Buffer) error {
	return jwt.Sign(self.Signer, bits, payload, out)
}

type NoSing_t struct{}

func (NoSing_t) Sign(bits int64, payload []byte, out *bytes.Buffer) error {
	return NOT_INITIALIZED
}
