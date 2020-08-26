//
//
//

package auth

import (
	"bytes"
	"io/ioutil"

	"github.com/ondi/go-jwt"
)

type Sign_t struct {
	sign jwt.Signer
}

func NewSign(AuthKey string) (res Sign_t, err error) {
	var buf []byte
	if buf, err = ioutil.ReadFile(AuthKey); err != nil {
		return
	}
	res.sign, err = jwt.NewSignPem(buf)
	return
}

func (self Sign_t) Sign(bits int64, payload map[string]interface{}) (bytes.Buffer, error) {
	return jwt.Sign(self.sign, bits, payload)
}
