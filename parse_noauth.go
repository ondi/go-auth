//
//
//

package auth

import (
	"github.com/ondi/go-tst"
)

type keys_noauth_t struct {
}

func (self *keys_noauth_t) Verify(token []byte) (payload []byte, err error) {
	return
}

func (self *keys_noauth_t) Approve(found []Token) bool {
	return true
}

type ParseNoAuth_t struct {
	args *tst.Tree3_t[*keys_noauth_t]
}

func NewParseNoAuth(keys map[string]struct{}) (self *ParseNoAuth_t, err error) {
	self = &ParseNoAuth_t{
		args: tst.NewTree3[*keys_noauth_t](),
	}

	for k1 := range keys {
		self.args.Add(k1, &keys_noauth_t{})
	}
	return
}

func (self *ParseNoAuth_t) Verifier(path string) (verifier Verifier, ok bool) {
	verifier, ok = self.args.Search(path)
	return
}
