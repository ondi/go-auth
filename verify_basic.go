//
//
//

package auth

import (
	"net/http"
	"regexp"
)

type VerifyBasic_t struct {
	find    TokenFinder
	verify  map[string]string
	approve *regexp.Regexp
}

func NewVerifyBasic(keys []string, approve string, find TokenFinder) (self *VerifyBasic_t, err error) {
	self = &VerifyBasic_t{
		find:   find,
		verify: map[string]string{},
	}
	if self.approve, err = regexp.Compile(approve); err != nil {
		return
	}
	for _, v := range keys {
		self.verify[v] = ""
	}
	return
}

func (self *VerifyBasic_t) TokenFind(r *http.Request) (keys_found int, out []Token) {
	return self.find.TokenFind(r)
}

func (self *VerifyBasic_t) Verify(token []byte) (payload []byte, key_id string, err error) {
	var ok bool
	if key_id, ok = self.verify[string(token)]; ok {
		payload = token
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
