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

type Verifier_t []jwt.Verifier

func NewVerifierGlob(pattern string) (res Verifier_t, err error) {
	var matched []string
	if matched, err = filepath.Glob(pattern); err != nil {
		return
	}
	return NewVerifier(matched...)
}

func NewVerifier(files ...string) (res Verifier_t, err error) {
	var buf []byte
	var verify jwt.Verifier
	for _, file := range files {
		if buf, err = ioutil.ReadFile(file); err != nil {
			return
		}
		if strings.Contains(file, "cert") {
			if strings.HasSuffix(file, ".der") {
				verify, err = jwt.NewVerifyCertDer(buf)
			} else {
				verify, err = jwt.NewVerifyCertPem(buf)
			}
		} else if strings.Contains(file, "hmac") {
			verify, err = jwt.NewHmacKey(buf)
		} else {
			if strings.HasSuffix(file, ".der") {
				verify, err = jwt.NewVerifyKeyDer(buf)
			} else {
				verify, err = jwt.NewVerifyKeyPem(buf)
			}
		}
		if err != nil {
			return
		}
		res = append(res, verify)
	}
	return
}

func (self Verifier_t) Len() int {
	return len(self)
}

func (self Verifier_t) Names() (res []string) {
	for _, v := range self {
		res = append(res, v.Name())
	}
	return
}

func (self Verifier_t) Verify(token []byte) (payload []byte, err error) {
	alg, bits, _, payload, signature, err := jwt.Parse([]byte(token))
	if err != nil {
		return
	}
	for _, v := range self {
		if !strings.HasPrefix(alg, v.Name()) {
			continue
		}
		if err = jwt.Verify(v, bits, signature, token); err == nil {
			return
		}
	}
	return payload, ERROR_MATCH
}
