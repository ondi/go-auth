//
//
//

package auth

import (
	"path/filepath"
	"strings"

	"github.com/ondi/go-jwt"
	"github.com/ondi/go-tst"
)

type ParseBearer_t struct {
	verify   []jwt.Verifier
	required *tst.Tree3_t[int]
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

func NewParseBearer(keys []Key_t, required map[string]int) (self *ParseBearer_t, err error) {
	self = &ParseBearer_t{
		required: tst.NewTree3[int](),
	}

	for k, v := range required {
		self.required.Add(k, v)
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
		self.verify = append(self.verify, verify)
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

func (self *ParseBearer_t) Approve(path string, found []Token) bool {
	req, _ := self.required.Search(path)
	if len(found) >= req {
		return true
	}
	return false
}
