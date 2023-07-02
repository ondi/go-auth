//
//
//

package auth

import (
	"regexp"

	"github.com/ondi/go-tst"
)

type VerifyBasic_t struct {
	passwords *tst.Tree1_t[*regexp.Regexp]
	required  List_t
}

func NewVerifyBasic(required List_t, passwords map[string]string) (self *VerifyBasic_t, err error) {
	self = &VerifyBasic_t{
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

func (self *VerifyBasic_t) Verify(path string, in []byte) (payload []byte, ok bool) {
	re, ok := self.passwords.Search(path)
	if ok && re != nil {
		return in, re.Match(in)
	}
	return
}

func (self *VerifyBasic_t) Required(path string, found List_t) (ok bool) {
	if len(found) > 0 {
		if len(self.required) > 0 {
			return len(self.required) == self.required.Intersect(found)
		}
		return true
	}
	re, ok := self.passwords.Search(path)
	if ok {
		return re == nil
	}
	return
}
