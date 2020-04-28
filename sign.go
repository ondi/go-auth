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

func SetupSign(self *Sign_t, AuthKey string) (err error) {
	var buf []byte
	self.sign = &jwt.Sign_t{}
	if buf, err = ioutil.ReadFile(AuthKey); err != nil {
		return
	}
	return self.sign.LoadKeyPem(buf)
}

func (self Sign_t) Sign(bits int, payload map[string]interface{}) (bytes.Buffer, error) {
	return jwt.Sign(self.sign, bits, payload)
}
