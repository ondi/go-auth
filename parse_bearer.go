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

func KeysGlob(pattern string) (keys []KeyType_t, err error) {
	matched, err := filepath.Glob(pattern)
	if err != nil {
		return
	}
	var key KeyType_t
	for _, v := range matched {
		if key, err = ReadFile(v); err != nil {
			return
		}
		keys = append(keys, key)
	}
	return
}

func NewParseBearer(required int, keys []KeyType_t) (res *ParseBearer_t, err error) {
	res = &ParseBearer_t{
		required: required,
	}
	var verify jwt.Verifier
	for _, key := range keys {
		if key.Hmac {
			verify, err = jwt.NewHmacKey(key.Data)
		} else if key.Cert {
			if key.Type == TYPE_DER {
				verify, err = jwt.NewVerifyCertDer(key.Data)
			} else {
				verify, err = jwt.NewVerifyCertPem(key.Data)
			}
		} else {
			if key.Type == TYPE_DER {
				verify, err = jwt.NewVerifyKeyDer(key.Data)
			} else {
				verify, err = jwt.NewVerifyKeyPem(key.Data)
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

func (self *ParseBearer_t) Verify(path string, in []byte) (payload []byte, ok bool) {
	alg, bits, _, payload, signature, err := jwt.Parse(in)
	if err != nil {
		return
	}
	for _, v := range self.verify {
		if strings.HasPrefix(alg, v.Name()) == false {
			continue
		}
		if ok = jwt.Verify(v, bits, signature, in); ok {
			return
		}
	}
	return
}

func (self *ParseBearer_t) Approve(path string, found []Token) (ok bool) {
	if len(found) >= self.required {
		return true
	}
	return
}
