//
//
//

package auth

import (
	"encoding/base64"
	"regexp"

	"github.com/ondi/go-tst"
)

type ParseBasic_t struct {
	keys    *tst.Tree3_t[map[string]struct{}]
	approve *regexp.Regexp
}

func NewParseBasic(keys map[string][]string, approve string) (self *ParseBasic_t, err error) {
	self = &ParseBasic_t{
		keys: tst.NewTree3[map[string]struct{}](),
	}

	if self.approve, err = regexp.Compile(approve); err != nil {
		return
	}

	for k1, v1 := range keys {
		m := map[string]struct{}{}
		for _, v2 := range v1 {
			m[v2] = struct{}{}
		}
		self.keys.Add(k1, m)
	}
	return
}

func (self *ParseBasic_t) Verify(path string, in []byte) (payload []byte, err error) {
	payload = make([]byte, base64.URLEncoding.DecodedLen(len(in)))
	n, err := base64.URLEncoding.Decode(payload, in)
	if err != nil {
		return
	}
	payload = payload[:n]
	verify, _ := self.keys.Search(path)
	if _, ok := verify[string(in)]; ok {
		return
	}
	err = ERROR_VERIFY
	return
}

func (self *ParseBasic_t) Approve(path string, found []Token) bool {
	return len(found) > 0
}
