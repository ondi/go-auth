//
//
//

package auth

import (
	"context"
	"net/http"
	"regexp"

	"github.com/ondi/go-tst"
)

type Token_t func(r *http.Request) (res []string)
type Addr_t func(r *http.Request) (addr string)
type Error_t func(w http.ResponseWriter, r *http.Request, err error)
type Validate_t func(r *http.Request, payload []byte) (res map[string]interface{}, err error)

type TokenAddr_t struct {
	verify     Verifier_t
	except     *tst.Tree1_t[*regexp.Regexp]
	token      Token_t
	addr       Addr_t
	validate   Validate_t
	next_ok    http.Handler
	next_error Error_t
}

func NewTokenAddr(verify Verifier_t, except map[string]string, next_ok http.Handler, next_error Error_t, token Token_t, addr Addr_t, validate Validate_t) (self *TokenAddr_t, err error) {
	self = &TokenAddr_t{
		verify:     verify,
		except:     &tst.Tree1_t[*regexp.Regexp]{},
		token:      token,
		addr:       addr,
		validate:   validate,
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
	payload, err := self.verify.Verify(r, self.token, self.validate)
	if err == nil {
		self.next_ok.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctx_auth, payload)))
		return
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

func VerifyToken(verify Verifier_t, next_ok http.HandlerFunc, next_error Error_t, token Token_t, validate Validate_t) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		payload, err := verify.Verify(r, token, validate)
		if err == nil {
			next_ok.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctx_auth, payload)))
		} else {
			next_error(w, r, err)
		}
	}
}

func VerifyAddr(re *regexp.Regexp, next_ok http.HandlerFunc, next_error Error_t, addr Addr_t) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if addr := addr(r); re.MatchString(addr) {
			next_ok.ServeHTTP(w, r)
		} else {
			next_error(w, r, nil)
		}
		return
	}
}
