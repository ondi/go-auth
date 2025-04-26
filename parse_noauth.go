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

func NewVerifiersNoAuth(in map[string]struct{}) (out map[string]Verifier, err error) {
	out = map[string]Verifier{}
	for k := range in {
		out[k] = &keys_noauth_t{}
	}
	return
}
