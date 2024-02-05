//
//
//

package auth

import (
	"regexp"

	"github.com/ondi/go-tst"
)

type ParseBasic_t struct {
	passwords *tst.Tree1_t[*regexp.Regexp]
	required  int
}

func NewParseBasic(required int, passwords map[string]string) (self *ParseBasic_t, err error) {
	self = &ParseBasic_t{
		passwords: &tst.Tree1_t[*regexp.Regexp]{},
		required:  required,
	}

	var re *regexp.Regexp
	for k, v := range passwords {
		if len(v) > 0 {
			if re, err = regexp.Compile(v); err != nil {
				return
			}
			self.passwords.Add(k, re)
		} else {
			self.passwords.Add(k, nil)
		}
	}
	return
}

func (self *ParseBasic_t) Verify(path string, in []byte) (payload []byte, ok bool) {
	re, ok := self.passwords.Search(path)
	if ok && re != nil {
		return in, re.Match(in)
	}
	return
}

func (self *ParseBasic_t) Approve(path string, found []Token) (ok bool) {
	if len(found) >= self.required {
		return true
	}
	re, ok := self.passwords.Search(path)
	if ok {
		return re == nil
	}
	return
}
