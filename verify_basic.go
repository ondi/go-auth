//
//
//

package auth

import (
	"regexp"

	"github.com/ondi/go-tst"
)

type verify_basic_regexp_t struct {
	re     *regexp.Regexp
	length int
}

type VerifyBasic_t struct {
	passwords *tst.Tree1_t[verify_basic_regexp_t]
}

func NewVerifyBasic(passwords map[string]string) (self *VerifyBasic_t, err error) {
	self = &VerifyBasic_t{
		passwords: &tst.Tree1_t[verify_basic_regexp_t]{},
	}

	var re *regexp.Regexp
	for k, v := range passwords {
		if re, err = regexp.Compile(v); err != nil {
			return
		}
		self.passwords.Add(k, verify_basic_regexp_t{re: re, length: len(v)})
	}
	return
}

func (self *VerifyBasic_t) Verify(path string, in []byte) (payload []byte, ok bool) {
	re, ok := self.passwords.Search(path)
	if ok {
		return in, re.re.Match(in)
	}
	return
}

func (self *VerifyBasic_t) Required(path string, in Required_t) (ok bool) {
	if len(in) > 0 {
		return true
	}
	re, ok := self.passwords.Search(path)
	if ok {
		return re.length == 0
	}
	return
}
