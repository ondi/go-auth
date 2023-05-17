//
//
//

package auth

import (
	"context"
	"net/http"
	"regexp"
	"time"

	"github.com/ondi/go-tst"
)

type Addr_t func(r *http.Request) string
type Token_t func(r *http.Request) []string
type Error_t func(w http.ResponseWriter, r *http.Request, err error)

type Verifier interface {
	Verify(token []byte) (payload []byte, err error)
}

type Validator interface {
	Validate(ctx context.Context, route string, ts time.Time, payload []byte) (out context.Context, err error)
}

type TokenAddr_t struct {
	addr       Addr_t
	token      Token_t
	verify     Verifier
	validate   Validator
	except     *tst.Tree1_t[*regexp.Regexp]
	next_ok    http.Handler
	next_error Error_t
}

func NewTokenAddr(verify Verifier, except map[string]string, next_ok http.Handler, next_error Error_t, addr Addr_t, token Token_t, validate Validator) (self *TokenAddr_t, err error) {
	self = &TokenAddr_t{
		addr:       addr,
		token:      token,
		verify:     verify,
		validate:   validate,
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
	var err error
	var payload []byte
	var ctx context.Context
	ts := time.Now()
	for _, token := range self.token(r) {
		if payload, err = self.verify.Verify([]byte(token)); err == nil {
			if ctx, err = self.validate.Validate(r.Context(), r.URL.Path, ts, payload); err == nil {
				self.next_ok.ServeHTTP(w, r.WithContext(ctx))
				return
			}
		}
	}
	re, ok := self.except.Search(r.URL.Path)
	if ok {
		if addr := self.addr(r); re.MatchString(addr) {
			self.next_ok.ServeHTTP(w, r)
			return
		}
	}
	self.next_error(w, r, err)
}

func VerifyToken(verify Verifier, next_ok http.HandlerFunc, next_error Error_t, token Token_t, validate Validator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var err error
		var payload []byte
		var ctx context.Context
		ts := time.Now()
		for _, token := range token(r) {
			if payload, err = verify.Verify([]byte(token)); err == nil {
				if ctx, err = validate.Validate(r.Context(), r.URL.Path, ts, payload); err == nil {
					next_ok.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}
		}
		next_error(w, r, err)
	}
}

func VerifyAddr(re *regexp.Regexp, next_ok http.HandlerFunc, next_error Error_t, addr Addr_t, validate Validator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if addr := addr(r); re.MatchString(addr) {
			next_ok.ServeHTTP(w, r)
		} else {
			next_error(w, r, nil)
		}
		return
	}
}
