//
//
//

package auth

import (
	"regexp"

	"github.com/ondi/go-tst"
)

type regexp_length_t struct {
	re     *regexp.Regexp
	length int
}

type VerifyBasic_t struct {
	passwords *tst.Tree1_t[regexp_length_t]
	required  Required_t
}

func NewVerifyBasic(required Required_t, passwords map[string]string) (self *VerifyBasic_t, err error) {
	self = &VerifyBasic_t{
		passwords: &tst.Tree1_t[regexp_length_t]{},
		required:  required,
	}

	var re *regexp.Regexp
	for k, v := range passwords {
		if re, err = regexp.Compile(v); err != nil {
			return
		}
		self.passwords.Add(k, regexp_length_t{re: re, length: len(v)})
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
	var count int
	for k := range self.required {
		if _, ok = in[k]; ok {
			count++
		}
	}
	if count == len(self.required) {
		return true
	}
	re, ok := self.passwords.Search(path)
	if ok {
		return re.length == 0
	}
	return
}
