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

func NewSign(self *Sign_t, AuthKey string) (res Sign_t, err error) {
	res.sign = &jwt.Sign_t{}
	var buf []byte
	if buf, err = ioutil.ReadFile(AuthKey); err != nil {
		return
	}
	err = res.sign.LoadKeyPem(buf)
	return
}

func (self Sign_t) Sign(bits int, payload map[string]interface{}) (bytes.Buffer, error) {
	return jwt.Sign(self.sign, bits, payload)
}
