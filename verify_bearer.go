//
//
//

package auth

import (
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/ondi/go-jwt"
)

type VerifyBearer_t struct {
	verify   []jwt.Verifier
	required List_t
}

func NewVerifyBearerGlob(required List_t, pattern string) (res *VerifyBearer_t, err error) {
	matched, err := filepath.Glob(pattern)
	if err != nil {
		return
	}
	return NewVerifyBearer(required, matched...)
}

func NewVerifyBearer(required List_t, files ...string) (res *VerifyBearer_t, err error) {
	res = &VerifyBearer_t{
		required: required,
	}
	var buf []byte
	var verify jwt.Verifier
	for _, file := range files {
		if buf, err = ioutil.ReadFile(file); err != nil {
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

func (self *VerifyBearer_t) Len() int {
	return len(self.verify)
}

func (self *VerifyBearer_t) Names() (res []string) {
	for _, v := range self.verify {
		res = append(res, v.Name())
	}
	return
}

func (self *VerifyBearer_t) Verify(path string, in []byte) (payload []byte, ok bool) {
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

func (self *VerifyBearer_t) Required(path string, found List_t) (ok bool) {
	if len(found) > 0 {
		if len(self.required) > 0 {
			return len(self.required) == self.required.Intersect(found)
		}
		return true
	}
	return
}
