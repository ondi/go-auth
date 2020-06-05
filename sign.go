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
	res.sign = &jwt.Sign_t{}
	if buf, err = ioutil.ReadFile(AuthKey); err != nil {
		return
	}
	err = res.sign.LoadKeyPem(buf)
	return
}

func (self Sign_t) Sign(bits int64, payload map[string]interface{}) (bytes.Buffer, error) {
	return jwt.Sign(self.sign, bits, payload)
}
