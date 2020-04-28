//
//
//

package auth

import (
	"context"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/ondi/go-jwt"
	"github.com/ondi/go-log"
	"github.com/ondi/go-tst"
)

type Auth_t struct {
	verify []jwt.Verifier
	except *tst.Tree1_t
	next   http.Handler
}

func (self Auth_t) Middleware(next http.Handler) http.Handler {
	return Auth_t{verify: self.verify, except: self.except, next: next}
}

func SetupAuth(self *Auth_t, AuthGlob string, except map[string]string, next http.Handler) (err error) {
	var matched []string
	if matched, err = filepath.Glob(AuthGlob); err != nil {
		return
	}
	log.Debug("AUTH MATCHED: %v", matched)
	var buf []byte
	for _, certfile := range matched {
		verify := &jwt.Verify_t{}
		if buf, err = ioutil.ReadFile(certfile); err == nil {
			if strings.HasSuffix(certfile, ".crt") {
				err = verify.LoadCertPem(buf)
			} else {
				err = verify.LoadCertDer(buf)
			}
		}
		if err != nil {
			return
		}
		self.verify = append(self.verify, verify)
	}
	self.except = &tst.Tree1_t{}
	var re *regexp.Regexp
	for k, v := range except {
		if re, err = regexp.Compile(v); err != nil {
			return
		}
		self.except.Add(k, re)
	}
	self.next = next
	return
}

func (self Auth_t) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if re, ok := self.except.Search(r.URL.Path).(*regexp.Regexp); ok {
		if addr := RemoteAddr(r); re.MatchString(addr) {
			self.next.ServeHTTP(w, r)
		} else {
			http.Error(w, "ACCESS DENIED: "+addr, http.StatusForbidden)
		}
		return
	}
	var i int
	var ok bool
	ts := time.Now().Unix()
	for _, token := range r.Header["Authorization"] {
		ix := strings.LastIndexByte(token, ' ')
		if ix == -1 {
			continue
		}
		header, payload, signature, err := jwt.Parse([]byte(token[ix+1:]))
		if err != nil {
			continue
		}
		for i = 0; i < len(self.verify); i++ {
			if header.Alg != self.verify[i].Name(header.HashBits) {
				continue
			}
			if ok, err = jwt.Verify(self.verify[i], header.HashBits, signature, []byte(token[ix+1:])); err == nil && ok {
				if err = jwt.Validate(payload, ts+60, ts); err == nil {
					break
				}
			}
		}
		if i == len(self.verify) {
			log.Debug("AUTH: %v, %v", ok, err)
			continue
		}
		self.next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), auth_key_t("AUTH"), payload)))
		return
	}
	http.Error(w, "Authorization required", http.StatusUnauthorized)
	return
}
