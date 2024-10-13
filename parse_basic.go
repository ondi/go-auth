//
//
//

package auth

import (
	"bytes"
	"encoding/base64"

	"github.com/ondi/go-tst"
)

type VerifyBasic_t struct {
	verify map[string]struct{}
}

func NewVerifyBasic(keys []string) (Verifier, error) {
	var err error
	self := &VerifyBasic_t{
		verify: map[string]struct{}{},
	}
	for _, v := range keys {
		self.verify[v] = struct{}{}
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
	return len(found) > 0
}

type KeysBasic_t struct {
	Keys []string
}

type RoutesBasic_t struct {
	args *tst.Tree3_t[Verifier]
}

func NewRoutesBasic(keys map[string]KeysBasic_t) (Routes, error) {
	var err error
	self := &RoutesBasic_t{
		args: tst.NewTree3[Verifier](),
	}
	var temp Verifier
	for k, v := range keys {
		if temp, err = NewVerifyBasic(v.Keys); err != nil {
			return self, err
		}
		self.args.Add(k, temp)
	}
	return self, err
}

func (self *RoutesBasic_t) Verifier(path string) (verifier Verifier, ok bool) {
	verifier, _, found := self.args.Search(path)
	ok = found > 0
	return
}
