//
//
//

package auth

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/ondi/go-jwt"
)

type Signer interface {
	Sign(bits int64, payload []byte, out *bytes.Buffer) error
}

type Sign_t struct {
	jwt.Signer
}

func NewSign(file string) (res Sign_t, err error) {
	var buf []byte
	if buf, err = ioutil.ReadFile(file); err != nil {
		return
	}
	if strings.HasSuffix(file, ".der") {
		res.Signer, err = jwt.NewSignDer(buf)
	} else {
		res.Signer, err = jwt.NewSignPem(buf)
	}
	return
}

func (self Sign_t) Sign(bits int64, payload []byte, out *bytes.Buffer) error {
	return jwt.Sign(self.Signer, bits, payload, out)
}

type NoSing_t struct{}

func (NoSing_t) Sign(bits int64, payload []byte, out *bytes.Buffer) error {
	return fmt.Errorf("NOT INITIALIZED")
}
