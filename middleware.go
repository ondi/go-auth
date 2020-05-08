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

type Middleware_t struct {
	verify Verify_t
	except *tst.Tree1_t
	next   http.Handler
}

func (self Middleware_t) WithNext(next http.Handler) http.Handler {
	return Middleware_t{verify: self.verify, except: self.except, next: next}
}

func NewMiddleware(AuthGlob string, except map[string]string, next http.Handler) (res Middleware_t, err error) {
	if res.verify, err = NewVerify(AuthGlob); err != nil {
		return
	}
	res.except = &tst.Tree1_t{}
	var re *regexp.Regexp
	for k, v := range except {
		if re, err = regexp.Compile(v); err != nil {
			return
		}
		res.except.Add(k, re)
	}
	res.next = next
	return
}

func (self Middleware_t) Names(bits int) []string {
	return self.verify.Names(bits)
}

func (self Middleware_t) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if re, ok := self.except.Search(r.URL.Path).(*regexp.Regexp); ok {
		if addr := RemoteAddr(r); re.MatchString(addr) {
			self.next.ServeHTTP(w, r)
		} else {
			http.Error(w, "ACCESS DENIED: "+addr, http.StatusForbidden)
		}
		return
	}
	ts := time.Now().Unix()
	payload, ok, err := self.verify.Check(r.Header["Authorization"], ts+60, ts)
	if ok && err == nil {
		self.next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), auth_key_t("AUTH"), payload)))
	} else {
		http.Error(w, "Authorization required", http.StatusUnauthorized)
	}
	return
}
