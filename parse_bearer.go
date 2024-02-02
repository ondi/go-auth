//
//
//

package auth

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/ondi/go-jwt"
)

type ParseBearer_t struct {
	verify   []jwt.Verifier
	required int
}

func NewParseBearerGlob(required int, pattern string) (res *ParseBearer_t, err error) {
	matched, err := filepath.Glob(pattern)
	if err != nil {
		return
	}
	return NewParseBearer(required, matched...)
}

func NewParseBearer(required int, files ...string) (res *ParseBearer_t, err error) {
	res = &ParseBearer_t{
		required: required,
	}
	var buf []byte
	var verify jwt.Verifier
	for _, file := range files {
		if buf, err = os.ReadFile(file); err != nil {
			return
		}
		if strings.Contains(file, "hmac") {
			verify, err = jwt.NewHmacKey(buf)
		} else if strings.Contains(file, "key") {
			if strings.HasSuffix(file, ".der") {
				verify, err = jwt.NewVerifyKeyDer(buf)
			} else {
				verify, err = jwt.NewVerifyKeyPem(buf)
			}
		} else {
			if strings.HasSuffix(file, ".der") {
				verify, err = jwt.NewVerifyCertDer(buf)
			} else {
				verify, err = jwt.NewVerifyCertPem(buf)
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

func (self *ParseBearer_t) Parse(path string, in []byte) (payload []byte, ok bool) {
	alg, bits, _, payload, signature, err := jwt.Parse(in)
	if err != nil {
		return
	}
	for _, v := range self.verify {
		if !strings.HasPrefix(alg, v.Name()) {
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
