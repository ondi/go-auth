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

var NOT_INITIALIZED = fmt.Errorf("NOT INITIALIZED")

type Signer interface {
	Sign(bits int64, payload []byte, out *bytes.Buffer) error
}

type Sign_t struct {
	jwt.Signer
}

func ReturnNoSignOnError(in jwt.Signer, err error) (Signer, error) {
	if err != nil {
		return NoSing_t{}, err
	}
	return Sign_t{Signer: in}, err
}

func NewSign(file string) (res Signer, err error) {
	buf, err := ioutil.ReadFile(file)
	if err != nil {
		return NoSing_t{}, err
	}
	if strings.HasSuffix(file, ".der") {
		res, err = ReturnNoSignOnError(jwt.NewSignDer(buf))
	} else {
		res, err = ReturnNoSignOnError(jwt.NewSignPem(buf))
	}
	return
}

func (self Sign_t) Sign(bits int64, payload []byte, out *bytes.Buffer) error {
	return jwt.Sign(self.Signer, bits, payload, out)
}

type NoSing_t struct{}

func (NoSing_t) Sign(bits int64, payload []byte, out *bytes.Buffer) error {
	return NOT_INITIALIZED
}
