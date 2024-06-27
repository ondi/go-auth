//
//
//

package auth

import (
	"encoding/base64"
	"regexp"

	"github.com/ondi/go-tst"
)

type keys_basic_t struct {
	verify  map[string]struct{}
	approve *regexp.Regexp
}

func (self *keys_basic_t) Verify(token []byte) (payload []byte, err error) {
	payload = make([]byte, base64.URLEncoding.DecodedLen(len(token)))
	n, err := base64.URLEncoding.Decode(payload, token)
	if err != nil {
		return
	}
	payload = payload[:n]
	if _, ok := self.verify[string(token)]; ok {
		return
	}
	err = ERROR_VERIFY
	return
}

func (self *keys_basic_t) Approve(found []Token) bool {
	return len(found) > 0
}

type KeysBasic_t struct {
	Keys    []string
	Approve string
}

type ParseBasic_t struct {
	args *tst.Tree3_t[*keys_basic_t]
}

func NewParseBasic(keys map[string]KeysBasic_t) (self *ParseBasic_t, err error) {
	self = &ParseBasic_t{
		args: tst.NewTree3[*keys_basic_t](),
	}

	for k1, v1 := range keys {
		temp := &keys_basic_t{verify: map[string]struct{}{}}
		if temp.approve, err = regexp.Compile(v1.Approve); err != nil {
			return
		}
		for _, v2 := range v1.Keys {
			temp.verify[v2] = struct{}{}
		}
		self.args.Add(k1, temp)
	}
	return
}

func (self *ParseBasic_t) Verifier(path string) (verifier Verifier, ok bool) {
	verifier, ok = self.args.Search(path)
	return
}
