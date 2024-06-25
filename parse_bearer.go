//
//
//

package auth

import (
	"strings"

	"github.com/ondi/go-jwt"
	"github.com/ondi/go-tst"
)

type ParseBearer_t struct {
	keys *tst.Tree3_t[[]jwt.Verifier]
}

func NewParseBearer(keys map[string][]Key_t) (self *ParseBearer_t, err error) {
	self = &ParseBearer_t{
		keys: tst.NewTree3[[]jwt.Verifier](),
	}

	for k, v := range keys {
		var keys []jwt.Verifier
		var verify jwt.Verifier
		for _, key := range v {
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
			keys = append(keys, verify)
		}
		self.keys.Add(k, keys)
	}
	return
}

func (self *ParseBearer_t) Verify(path string, in []byte) (payload []byte, err error) {
	alg, bits, _, payload, signature, err := jwt.Parse(in)
	if err != nil {
		return
	}
	verify, _ := self.keys.Search(path)
	for _, v := range verify {
		if strings.HasPrefix(alg, v.Name()) == false {
			continue
		}
		if jwt.Verify(v, bits, signature, in) {
			return
		}
	}
	err = ERROR_VERIFY
	return
}

func (self *ParseBearer_t) Approve(path string, found []Token) bool {
	return len(found) > 0
}
