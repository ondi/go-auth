//
//
//

package auth

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"time"

	"github.com/ondi/go-tst"
)

var (
	VALIDATOR             = &Validator_t{Nbf: 60, Exp: -60}
	ERROR_MATCH           = errors.New("NO MATCHING ELEMENTS")
	ERROR_NOT_INITIALIZED = errors.New("NOT INITIALIZED")
)

type Addr_t func(r *http.Request) string
type Token_t func(r *http.Request) []TokenValue_t
type Error_t func(w http.ResponseWriter, r *http.Request, err error)

type Verifier interface {
	Verify(token []byte) (payload []byte, ok bool)
}

type Validator interface {
	Validate(ctx context.Context, ts time.Time, token_name string, payload []byte) (out context.Context, ok bool)
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
	var ok bool
	var count int
	var payload []byte
	var next context.Context
	ts := time.Now()
	prev := r.Context()
	for _, token := range self.token(r) {
		if payload, ok = self.verify.Verify([]byte(token.Value)); ok {
			if next, ok = self.validate.Validate(prev, ts, token.Name, payload); ok {
				prev = next
				count++
			}
		}
	}
	if count > 0 {
		self.next_ok.ServeHTTP(w, r.WithContext(prev))
		return
	}
	re, ok := self.except.Search(r.URL.Path)
	if ok {
		if addr := self.addr(r); re.MatchString(addr) {
			self.next_ok.ServeHTTP(w, r)
			return
		}
	}
	self.next_error(w, r, ERROR_MATCH)
}

func VerifyToken(verify Verifier, next_ok http.HandlerFunc, next_error Error_t, token Token_t, validate Validator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var ok bool
		var count int
		var payload []byte
		var next context.Context
		ts := time.Now()
		prev := r.Context()
		for _, token := range token(r) {
			if payload, ok = verify.Verify([]byte(token.Value)); ok {
				if next, ok = validate.Validate(prev, ts, token.Name, payload); ok {
					prev = next
					count++
				}
			}
		}
		if count > 0 {
			next_ok.ServeHTTP(w, r.WithContext(prev))
			return
		}
		next_error(w, r, ERROR_MATCH)
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
