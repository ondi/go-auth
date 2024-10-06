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

type VerifyBearer_t struct {
	verify  []jwt.Verifier
	approve *regexp.Regexp
}

func NewVerifyBearer(keys []Key_t, approve string) (Verifier, error) {
	var err error
	var verify jwt.Verifier
	self := &VerifyBearer_t{}
	if self.approve, err = regexp.Compile(approve); err != nil {
		return self, err
	}
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
			return self, err
		}
		self.verify = append(self.verify, verify)
	}
	return self, err
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

type KeysBearer_t struct {
	Keys    []Key_t
	Approve string
}

type RoutesBearer_t struct {
	args *tst.Tree3_t[Verifier]
}

func NewRoutesBearer(args map[string]KeysBearer_t) (Routes, error) {
	var err error
	self := &RoutesBearer_t{
		args: tst.NewTree3[Verifier](),
	}
	var temp Verifier
	for k, v := range args {
		if temp, err = NewVerifyBearer(v.Keys, v.Approve); err != nil {
			return self, err
		}
		self.args.Add(k, temp)
	}
	return self, err
}

func (self *RoutesBearer_t) Verifier(path string) (verifier Verifier, ok bool) {
	verifier, ok = self.args.Search(path)
	return
}
