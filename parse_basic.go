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
	required *tst.Tree3_t[*regexp.Regexp]
}

func NewParseBasic(required map[string]string) (self *ParseBasic_t, err error) {
	self = &ParseBasic_t{
		required: tst.NewTree3[*regexp.Regexp](),
	}

	var re *regexp.Regexp
	for k, v := range required {
		if len(v) > 0 {
			if re, err = regexp.Compile(v); err != nil {
				return
			}
			self.required.Add(k, re)
		} else {
			self.required.Add(k, nil)
		}
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
	return
}

func (self *ParseBasic_t) Approve(path string, found []Token) bool {
	re, ok := self.required.Search(path)
	if re == nil {
		return ok
	}
	for _, v := range found {
		if re.Match(v.GetValue()) {
			return true
		}
	}
	return false
}
