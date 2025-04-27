//
//
//

package auth

type keys_noauth_t struct {
}

func (self *keys_noauth_t) Verify(token []byte) (payload []byte, key_id string, err error) {
	return
}

func (self *keys_noauth_t) Approve(found []Token) bool {
	return true
}

func NewVerifyNoAuth() (self *keys_noauth_t, err error) {
	self = &keys_noauth_t{}
	return
}
