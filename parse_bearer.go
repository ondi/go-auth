//
//
//

package auth

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ondi/go-jwt"
	"github.com/ondi/go-tst"
)

type ParseBearer_t struct {
	verify   []jwt.Verifier
	required *tst.Tree3_t[*regexp.Regexp]
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

func NewParseBearer(keys []Key_t, required map[string]string) (self *ParseBearer_t, err error) {
	self = &ParseBearer_t{
		required: tst.NewTree3[*regexp.Regexp](),
	}

	var re *regexp.Regexp
	for k, v := range required {
		if len(v) > 0 {
			if re, err = regexp.Compile(v); err != nil {
				return
			}
			self.required.Add(k, re)
		} else {
			self.required.Add(k, nil)
		}
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

func (self *ParseBearer_t) Verify(in []byte) (payload []byte, err error) {
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
	re, ok := self.required.Search(path)
	if re == nil {
		return ok
	}
	for _, v := range found {
		if re.MatchString(v.GetName()) {
			return true
		}
	}
	return false
}
