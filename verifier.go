//
//
//

package auth

import (
	"io/ioutil"
	"net/http"
	"path/filepath"
	"strings"
	"time"

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
	return
}

func (self Verifier_t) Names() (res []string) {
	for _, v := range self {
		res = append(res, v.Name())
	}
	return
}

func (self Verifier_t) Verify(r *http.Request, ts time.Time, validate Validator) (out *http.Request, err error) {
	var alg string
	var bits int64
	var payload, signature []byte
	for _, token := range validate.GetToken(r) {
		ix := strings.IndexByte(token, ' ')
		if ix == -1 {
			continue
		}
		if alg, bits, _, payload, signature, err = jwt.Parse([]byte(token[ix+1:])); err != nil {
			continue
		}
		for _, v := range self {
			if !strings.HasPrefix(alg, v.Name()) {
				continue
			}
			if err = jwt.Verify(v, bits, signature, []byte(token[ix+1:])); err == nil {
				if out, err = validate.Validate(r, ts, payload); err == nil {
					return
				}
			}
		}
	}
	if err == nil {
		err = ERROR_MATCH
	}
	return
}
