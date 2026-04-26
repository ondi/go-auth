//
//
//

package auth

import "net/http"

type VerifyNoAuth_t struct {
}

func NewVerifyNoAuth() (self *VerifyNoAuth_t, err error) {
	self = &VerifyNoAuth_t{}
	return
}

func (self *VerifyNoAuth_t) TokenFind(r *http.Request) (keys_found int, out []Token) {
	return
}

func (self *VerifyNoAuth_t) Verify(token []byte) (payload []byte, key_id string, err error) {
	return
}

func (self *VerifyNoAuth_t) Approve(found []Token) bool {
	return true
}
