//
//
//

package auth

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/ondi/go-jwt"
)

type VerifyBearer_t struct {
	find    TokenFinder
	verify  []jwt.Verifier
	approve *regexp.Regexp
}

func NewVerifyBearer(keys []Key_t, approve string, find TokenFinder) (self *VerifyBearer_t, err error) {
	self = &VerifyBearer_t{
		find: find,
	}
	if self.approve, err = regexp.Compile(approve); err != nil {
		return
	}
	var verify jwt.Verifier
	for _, key := range keys {
		if key.Hmac {
			verify, err = jwt.NewHmacKey(key.Id, key.Value)
		} else if key.Cert {
			if key.DER {
				verify, err = jwt.NewVerifyCertDer(key.Id, key.Value)
			} else {
				verify, err = jwt.NewVerifyCertPem(key.Id, key.Value)
			}
		} else {
			if key.DER {
				verify, err = jwt.NewVerifyKeyDer(key.Id, key.Value)
			} else {
				verify, err = jwt.NewVerifyKeyPem(key.Id, key.Value)
			}
		}
		if err != nil {
			return
		}
		self.verify = append(self.verify, verify)
	}
	return
}

func (self *VerifyBearer_t) TokenFind(r *http.Request) (keys_found int, out []Token) {
	return self.find.TokenFind(r)
}

func (self *VerifyBearer_t) Verify(token []byte) (payload []byte, key_id string, err error) {
	alg, bits, _, payload, signature, err := jwt.Parse(token)
	if err != nil {
		return
	}
	for _, v := range self.verify {
		if strings.HasPrefix(alg, v.AlgName()) && jwt.Verify(v, bits, signature, token) {
			key_id = v.KeyId()
			return
		}
	}
	err = ERROR_VERIFY_FAILED
	return
}

func (self *VerifyBearer_t) Approve(found []Token) bool {
	for _, v := range found {
		if self.approve.MatchString(v.GetName()) {
			return true
		}
	}
	return false
}
