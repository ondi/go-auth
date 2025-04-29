//
//
//

package auth

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"regexp"
)

type VerifyBasic_t struct {
	find    TokenFinder
	verify  map[string]struct{}
	approve *regexp.Regexp
}

func NewVerifyBasic(keys []string, approve string, find TokenFinder) (self *VerifyBasic_t, err error) {
	self = &VerifyBasic_t{
		find:   find,
		verify: map[string]struct{}{},
	}
	for _, v := range keys {
		self.verify[v] = struct{}{}
	}
	if self.approve, err = regexp.Compile(approve); err != nil {
		return
	}
	return
}

func (self *VerifyBasic_t) TokenFind(r *http.Request) (keys_found int, out []Token) {
	return self.find.TokenFind(r)
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
