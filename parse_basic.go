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
	keys *tst.Tree3_t[*regexp.Regexp]
}

func NewParseBasic(keys map[string]string) (self *ParseBasic_t, err error) {
	self = &ParseBasic_t{
		keys: tst.NewTree3[*regexp.Regexp](),
	}

	var re *regexp.Regexp
	for k, v := range keys {
		if re, err = regexp.Compile(v); err != nil {
			return
		}
		self.keys.Add(k, re)
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
	verify, ok := self.keys.Search(path)
	if ok && verify.Match(in) {
		return
	}
	err = ERROR_VERIFY
	return
}

func (self *ParseBasic_t) Approve(path string, found []Token) bool {
	return len(found) > 0
}
