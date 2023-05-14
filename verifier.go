//
//
//

package auth

import (
	"io/ioutil"
	"net/http"
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
		if strings.Contains(file, "key") {
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
		res = append(res, verify)
	}
	if len(res) == 0 {
		return res, ERROR_MATCH
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

func (self Verifier_t) Verify(r *http.Request, token string) (payload []byte, err error) {
	ix := strings.IndexByte(token, ' ')
	if ix == -1 {
		return nil, ERROR_MATCH
	}
	alg, bits, _, payload, signature, err := jwt.Parse([]byte(token[ix+1:]))
	if err != nil {
		return
	}
	for _, v := range self {
		if !strings.HasPrefix(alg, v.Name()) {
			continue
		}
		if err = jwt.Verify(v, bits, signature, []byte(token[ix+1:])); err == nil {
			return
		}
	}
	return
}
