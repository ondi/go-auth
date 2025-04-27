//
//
//

package auth

type VerifyNoAuth struct {
}

func (self *VerifyNoAuth) Verify(token []byte) (payload []byte, key_id string, err error) {
	return
}

func (self *VerifyNoAuth) Approve(found []Token) bool {
	return true
}

func NewVerifyNoAuth() (self *VerifyNoAuth, err error) {
	self = &VerifyNoAuth{}
	return
}
