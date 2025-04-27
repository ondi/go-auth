//
//
//

package auth

import (
	"bytes"
	"encoding/base64"
	"regexp"
)

type VerifyBasic_t struct {
	verify  map[string]struct{}
	approve *regexp.Regexp
}

func NewVerifyBasic(keys []string, approve string) (Verifier, error) {
	var err error
	self := &VerifyBasic_t{
		verify: map[string]struct{}{},
	}
	for _, v := range keys {
		self.verify[v] = struct{}{}
	}
	if self.approve, err = regexp.Compile(approve); err != nil {
		return self, err
	}
	return self, err
}

func (self *VerifyBasic_t) Verify(token []byte) (payload []byte, key_id string, err error) {
	payload = make([]byte, base64.URLEncoding.DecodedLen(len(token)))
	n, err := base64.URLEncoding.Decode(payload, token)
	if err != nil {
		return
	}
	payload = payload[:n]
	if _, ok := self.verify[string(token)]; ok {
		if ix := bytes.IndexByte(payload, ':'); ix > -1 {
			key_id = string(payload[:ix])
		}
		return
	}
	err = ERROR_VERIFY_FAILED
	return
}

func (self *VerifyBasic_t) Approve(found []Token) bool {
	for _, v := range found {
		if self.approve.MatchString(v.GetName()) {
			return true
		}
	}
	return false
}
