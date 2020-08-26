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
	for _, certfile := range files {
		var verify jwt.Verify_t
		if buf, err = ioutil.ReadFile(certfile); err == nil {
			if strings.HasSuffix(certfile, ".crt") {
				verify, err = jwt.NewVerifyPem(buf)
			} else {
				verify, err = jwt.NewVerifyDer(buf)
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

func (self Verifier_t) Check(tokens []string, ts_nbf int64, ts_exp int64) (payload map[string]interface{}, ok bool, err error) {
	var header jwt.Header_t
	var signature []byte
	for _, token := range tokens {
		ix := strings.LastIndexByte(token, ' ')
		if ix == -1 {
			continue
		}
		if header, payload, signature, err = jwt.Parse([]byte(token[ix+1:])); err != nil {
			continue
		}
		for _, v := range self {
			if !strings.HasPrefix(header.Alg, v.Name()) {
				continue
			}
			if ok, err = jwt.Verify(v, header.HashBits, signature, []byte(token[ix+1:])); err == nil && ok {
				if err = jwt.Validate(payload, ts_nbf, ts_exp); err == nil {
					return
				}
			}
		}
	}
	return
}
