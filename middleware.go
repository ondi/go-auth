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

type Error_t func(w http.ResponseWriter, r *http.Request, err error)

type Validator interface {
	GetToken(r *http.Request) (res []string)
	GetAddr(r *http.Request) (addr string)
	Validate(r *http.Request, ts time.Time, payload []byte) (out *http.Request, err error)
}

type TokenAddr_t struct {
	verify     Verifier_t
	except     *tst.Tree1_t[*regexp.Regexp]
	validate   Validator
	next_ok    http.Handler
	next_error Error_t
}

func NewTokenAddr(verify Verifier_t, except map[string]string, next_ok http.Handler, next_error Error_t, validate Validator) (self *TokenAddr_t, err error) {
	if verify.Len() == 0 {
		return nil, ERROR_MATCH
	}

	self = &TokenAddr_t{
		verify:     verify,
		except:     &tst.Tree1_t[*regexp.Regexp]{},
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
	var err error
	var req *http.Request
	for _, token := range self.validate.GetToken(r) {
		req, err = self.verify.Verify(r, time.Now(), token, self.validate)
		if err == nil {
			self.next_ok.ServeHTTP(w, req)
			return
		}
	}
	re, ok := self.except.Search(r.URL.Path)
	if ok {
		if addr := self.validate.GetAddr(r); re.MatchString(addr) {
			self.next_ok.ServeHTTP(w, r)
			return
		}
	}
	self.next_error(w, r, err)
}

func VerifyToken(verify Verifier_t, next_ok http.HandlerFunc, next_error Error_t, validate Validator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		for _, token := range validate.GetToken(r) {
			req, err := verify.Verify(r, time.Now(), token, validate)
			if err == nil {
				next_ok.ServeHTTP(w, req)
			} else {
				next_error(w, r, err)
			}
		}
	}
}

func VerifyAddr(re *regexp.Regexp, next_ok http.HandlerFunc, next_error Error_t, validate Validator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if addr := validate.GetAddr(r); re.MatchString(addr) {
			next_ok.ServeHTTP(w, r)
		} else {
			next_error(w, r, nil)
		}
		return
	}
}
