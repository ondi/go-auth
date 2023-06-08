//
//
//

package auth

import (
	"encoding/json"
	"net/http"
	"regexp"
	"time"

	"github.com/ondi/go-tst"
)

type Addr_t func(r *http.Request) string
type Token_t func(r *http.Request) []TokenValue_t

type Verifier interface {
	Verify(token []byte) (payload []byte, ok bool)
}

type Validator interface {
	Validate(ts time.Time, token_name string, in map[string]interface{}) bool
}

type ValidatorList []Validator

func (self ValidatorList) Validate(ts time.Time, token_name string, in map[string]interface{}) bool {
	for _, v := range self {
		if !v.Validate(ts, token_name, in) {
			return false
		}
	}
	return true
}

type TokenAddr_t struct {
	token      Token_t
	verify     Verifier
	validate   ValidatorList
	addr       Addr_t
	except     *tst.Tree1_t[*regexp.Regexp]
	next_ok    http.Handler
	next_error http.Handler
}

func NewTokenAddr(verify Verifier, except map[string]string, next_ok http.Handler, next_error http.Handler, addr Addr_t, token Token_t, validate ...Validator) (self *TokenAddr_t, err error) {
	self = &TokenAddr_t{
		token:      token,
		verify:     verify,
		validate:   validate,
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

func (self *TokenAddr_t) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var count int
	ts := time.Now()
	ctx := r.Context()
	for _, token := range self.token(r) {
		if payload, ok := self.verify.Verify([]byte(token.Value)); ok {
			var values map[string]interface{}
			if json.Unmarshal(payload, &values) != nil {
				continue
			}
			if !self.validate.Validate(ts, token.Name, values) {
				continue
			}
			ctx = WithValue(ctx, token.Name, values)
			count++
		}
	}
	if count > 0 {
		self.next_ok.ServeHTTP(w, r.WithContext(ctx))
		return
	}
	re, ok := self.except.Search(r.URL.Path)
	if ok {
		if addr := self.addr(r); re.MatchString(addr) {
			self.next_ok.ServeHTTP(w, r)
			return
		}
	}
	self.next_error.ServeHTTP(w, r)
}

type TokenOnly_t struct {
	token      Token_t
	verify     Verifier
	validate   ValidatorList
	next_ok    http.Handler
	next_error http.Handler
}

func NewTokenOnly(verify Verifier, next_ok http.Handler, next_error http.Handler, token Token_t, validate ...Validator) *TokenOnly_t {
	return &TokenOnly_t{
		token:      token,
		verify:     verify,
		validate:   validate,
		next_ok:    next_ok,
		next_error: next_error,
	}
}

func (self *TokenOnly_t) ServeHttp(w http.ResponseWriter, r *http.Request) {
	var count int
	ts := time.Now()
	ctx := r.Context()
	for _, token := range self.token(r) {
		if payload, ok := self.verify.Verify([]byte(token.Value)); ok {
			var values map[string]interface{}
			if json.Unmarshal(payload, &values) != nil {
				continue
			}
			if !self.validate.Validate(ts, token.Name, values) {
				continue
			}
			ctx = WithValue(ctx, token.Name, values)
			count++
		}
	}
	if count > 0 {
		self.next_ok.ServeHTTP(w, r.WithContext(ctx))
		return
	}
	self.next_error.ServeHTTP(w, r)
}

type AddrOnly_t struct {
	re         *regexp.Regexp
	addr       Addr_t
	next_ok    http.Handler
	next_error http.Handler
}

func NewAddrOnly(re *regexp.Regexp, next_ok http.Handler, next_error http.Handler, addr Addr_t) *AddrOnly_t {
	return &AddrOnly_t{
		re:         re,
		addr:       addr,
		next_ok:    next_ok,
		next_error: next_error,
	}
}

func (self *AddrOnly_t) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if addr := self.addr(r); self.re.MatchString(addr) {
		self.next_ok.ServeHTTP(w, r)
	} else {
		self.next_error.ServeHTTP(w, r)
	}
	return
}
