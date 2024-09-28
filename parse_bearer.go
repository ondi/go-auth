//
//
//

package auth

import (
	"regexp"
	"strings"

	"github.com/ondi/go-jwt"
	"github.com/ondi/go-tst"
)

type keys_bearer_t struct {
	verify  []jwt.Verifier
	approve *regexp.Regexp
}

func (self *keys_bearer_t) Verify(token []byte) (payload []byte, err error) {
	alg, bits, _, payload, signature, err := jwt.Parse(token)
	if err != nil {
		return
	}
	for _, v := range self.verify {
		if strings.HasPrefix(alg, v.Name()) && jwt.Verify(v, bits, signature, token) {
			return
		}
	}
	err = ERROR_VERIFY_FAILED
	return
}

func (self *keys_bearer_t) Approve(found []Token) bool {
	for _, v := range found {
		if self.approve.MatchString(v.GetName()) {
			return true
		}
	}
	return false
}

type KeysBearer_t struct {
	Keys    []Key_t
	Approve string
}

type ParseBearer_t struct {
	args *tst.Tree3_t[*keys_bearer_t]
}

func NewParseBearer(args map[string]KeysBearer_t) (self *ParseBearer_t, err error) {
	self = &ParseBearer_t{
		args: tst.NewTree3[*keys_bearer_t](),
	}

	var verify jwt.Verifier
	for k, v := range args {
		temp := &keys_bearer_t{}
		if temp.approve, err = regexp.Compile(v.Approve); err != nil {
			return
		}
		for _, key := range v.Keys {
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
			temp.verify = append(temp.verify, verify)
		}
		self.args.Add(k, temp)
	}
	return
}

func (self *ParseBearer_t) Verifier(path string) (verifier Verifier, ok bool) {
	verifier, ok = self.args.Search(path)
	return
}
