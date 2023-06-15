//
//
//

package auth

import (
	"net/http"
	"regexp"
	"time"

	"github.com/ondi/go-tst"
)

type Addr_t func(r *http.Request) string
type Token_t func(r *http.Request) []Token
type Required_t map[string]struct{}

type Token interface {
	GetName() string
	GetValue() []byte
	GetPayload() map[string]interface{}
	Unmarshal(payload []byte) error
}

type Verifier interface {
	Verify(token []byte) (payload []byte, ok bool)
}

type Validator interface {
	Validate(ts time.Time, token_name string, in map[string]interface{}) bool
}

type Validators []Validator

func (self Validators) Validate(ts time.Time, token_name string, in map[string]interface{}) bool {
	for _, v := range self {
		if !v.Validate(ts, token_name, in) {
			return false
		}
	}
	return true
}

type TokenAddr_t struct {
	token_only *TokenOnly_t
	addr_only  *AddrOnly_t
}

func NewTokenAddr(next_ok http.Handler, next_error http.Handler, token Token_t, addr Addr_t, except map[string]string, required Required_t, verify Verifier, validate ...Validator) (self *TokenAddr_t, err error) {
	self = &TokenAddr_t{}
	if self.addr_only, err = NewAddrOnly(next_ok, next_error, addr, except); err != nil {
		return
	}
	self.token_only = NewTokenOnly(next_ok, self.addr_only, token, required, verify, validate...)
	return
}

func (self *TokenAddr_t) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	self.token_only.ServeHttp(w, r)
}

type TokenOnly_t struct {
	token      Token_t
	verify     Verifier
	validate   Validators
	required   Required_t
	next_ok    http.Handler
	next_error http.Handler
}

func NewTokenOnly(next_ok http.Handler, next_error http.Handler, token Token_t, required Required_t, verify Verifier, validate ...Validator) (self *TokenOnly_t) {
	self = &TokenOnly_t{
		token:      token,
		verify:     verify,
		validate:   validate,
		required:   required,
		next_ok:    next_ok,
		next_error: next_error,
	}
	return
}

func (self *TokenOnly_t) ServeHttp(w http.ResponseWriter, r *http.Request) {
	var count int
	ts := time.Now()
	ctx := r.Context()
	required := Required_t{}
	for _, token := range self.token(r) {
		if payload, ok := self.verify.Verify(token.GetValue()); ok {
			if token.Unmarshal(payload) != nil {
				continue
			}
			if !self.validate.Validate(ts, token.GetName(), token.GetPayload()) {
				continue
			}
			count++
			ctx = WithValue(ctx, token.GetName(), token.GetPayload())
			if _, ok = self.required[token.GetName()]; ok {
				required[token.GetName()] = struct{}{}
			}
		}
	}
	if len(self.required) == len(required) {
		self.next_ok.ServeHTTP(w, WithContext(ctx, r, count))
	} else {
		self.next_error.ServeHTTP(w, WithContext(ctx, r, count))
	}
}

type AddrOnly_t struct {
	addr       Addr_t
	except     *tst.Tree1_t[*regexp.Regexp]
	next_ok    http.Handler
	next_error http.Handler
}

func NewAddrOnly(next_ok http.Handler, next_error http.Handler, addr Addr_t, except map[string]string) (self *AddrOnly_t, err error) {
	self = &AddrOnly_t{
		addr:       addr,
		except:     &tst.Tree1_t[*regexp.Regexp]{},
		next_ok:    next_ok,
		next_error: next_error,
	}

	var re *regexp.Regexp
	for k, v := range except {
		if re, err = regexp.Compile(v); err != nil {
			return
		}
		self.except.Add(k, re)
	}

	return
}

func (self *AddrOnly_t) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if re, ok := self.except.Search(r.URL.Path); ok {
		if addr := self.addr(r); re.MatchString(addr) {
			self.next_ok.ServeHTTP(w, r)
			return
		}
	}
	self.next_error.ServeHTTP(w, r)
}
