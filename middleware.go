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

type Ts interface {
	Ts() (nbf int64, exp int64)
}

type TokenAddr_t struct {
	verify     Verifier_t
	except     *tst.Tree1_t
	next_ok    http.Handler
	next_error http.Handler
	ts         Ts
}

func NewTokenAddr(verify Verifier_t, except map[string]string, next_ok http.Handler, next_error http.Handler, ts Ts) (self TokenAddr_t, err error) {
	self.verify = verify
	self.except = &tst.Tree1_t{}
	var re *regexp.Regexp
	for k, v := range except {
		if re, err = regexp.Compile(v); err != nil {
			return
		}
		self.except.Add(k, re)
	}
	self.next_ok = next_ok
	self.next_error = next_error
	self.ts = ts
	return
}

func (self TokenAddr_t) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	nbf, exp := self.ts.Ts()
	if payload, ok, _ := self.verify.Check(GetTokens(r), nbf, exp); ok {
		self.next_ok.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), auth_key_t("AUTH"), payload)))
		return
	}
	if re, ok := self.except.Search(r.URL.Path).(*regexp.Regexp); ok {
		if addr := GetRemoteAddr(r); re.MatchString(addr) {
			self.next_ok.ServeHTTP(w, r)
			return
		}
	}
	self.next_error.ServeHTTP(w, r)
}

func VerifyToken(verify Verifier_t, next_ok http.HandlerFunc, next_error http.HandlerFunc, ts Ts) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		nbf, exp := ts.Ts()
		if payload, ok, _ := verify.Check(GetTokens(r), nbf, exp); ok {
			next_ok.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), auth_key_t("AUTH"), payload)))
		} else {
			next_error.ServeHTTP(w, r)
		}
	}
}

func VerifyAddr(re *regexp.Regexp, next_ok http.HandlerFunc, next_error http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if addr := GetRemoteAddr(r); re.MatchString(addr) {
			next_ok.ServeHTTP(w, r)
		} else {
			next_error.ServeHTTP(w, r)
		}
		return
	}
}
