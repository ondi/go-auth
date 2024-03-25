//
//
//

package auth

import (
	"path/filepath"
	"strings"

	"github.com/ondi/go-jwt"
)

type ParseBearer_t struct {
	verify   []jwt.Verifier
	required int
}

func KeysGlob(pattern string, in []Key_t) ([]Key_t, error) {
	matched, err := filepath.Glob(pattern)
	if err != nil {
		return in, err
	}
	var key Key_t
	for _, v := range matched {
		if key, err = ReadFile(v); err != nil {
			return in, err
		}
		in = append(in, key)
	}
	return in, err
}

func NewParseBearer(required int, keys []Key_t) (res *ParseBearer_t, err error) {
	res = &ParseBearer_t{
		required: required,
	}
	var verify jwt.Verifier
	for _, key := range keys {
		if key.Hmac {
			verify, err = jwt.NewHmacKey(key.Value)
		} else if key.Cert {
			if key.DER {
				verify, err = jwt.NewVerifyCertDer(key.Value)
			} else {
				verify, err = jwt.NewVerifyCertPem(key.Value)
			}
		} else {
			if key.DER {
				verify, err = jwt.NewVerifyKeyDer(key.Value)
			} else {
				verify, err = jwt.NewVerifyKeyPem(key.Value)
			}
		}
		if err != nil {
			return
		}
		res.verify = append(res.verify, verify)
	}
	return
}

func (self *ParseBearer_t) Len() int {
	return len(self.verify)
}

func (self *ParseBearer_t) Names() (res []string) {
	for _, v := range self.verify {
		res = append(res, v.Name())
	}
	return
}

func (self *ParseBearer_t) Verify(path string, in []byte) (payload []byte, err error) {
	alg, bits, _, payload, signature, err := jwt.Parse(in)
	if err != nil {
		return
	}
	for _, v := range self.verify {
		if strings.HasPrefix(alg, v.Name()) == false {
			continue
		}
		if jwt.Verify(v, bits, signature, in) {
			return
		}
	}
	return payload, ERROR_VERIFY
}

func (self *ParseBearer_t) Approve(path string, found []Token) (ok bool) {
	if len(found) >= self.required {
		return true
	}
	return
}
