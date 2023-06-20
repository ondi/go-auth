//
//
//

package auth

import (
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Token_t[T any] struct {
	Name    string
	Value   []byte
	Payload T
}

func (self *Token_t[T]) GetName() string {
	return self.Name
}

func (self *Token_t[T]) GetPayload() T {
	return self.Payload
}

func (self *Token_t[T]) Verify(in Verifier) (ok bool) {
	payload, ok := in.Verify(self.Value)
	if ok {
		if json.Unmarshal(payload, &self.Payload) != nil {
			return false
		}
	}
	return
}

func (self *Token_t[T]) Validate(ts time.Time, in []Validator[T]) bool {
	for _, v := range in {
		if !v.Validate(ts, self.Name, self.Payload) {
			return false
		}
	}
	return true
}

func TOKEN(r *http.Request) (out []Token[PAYLOAD_TYPE]) {
	var ix int
	var token string
	for _, token = range r.Header[AUTHORIZATION] {
		ix = strings.IndexByte(token, ' ')
		out = append(out, &Token_t[PAYLOAD_TYPE]{Name: AUTHORIZATION, Value: []byte(token[ix+1:])})
	}
	if c, err := r.Cookie(AUTHORIZATION); err == nil {
		if token, err = url.QueryUnescape(c.Value); err == nil {
			ix = strings.IndexByte(token, ' ')
			out = append(out, &Token_t[PAYLOAD_TYPE]{Name: AUTHORIZATION, Value: []byte(token[ix+1:])})
		}
	}
	return
}

func ADDR(r *http.Request) (out string) {
	if out = r.Header.Get("X-Forwarded-For"); len(out) > 0 {
		return
	}
	if out = r.Header.Get("X-Real-IP"); len(out) > 0 {
		return
	}
	if out, _, _ = net.SplitHostPort(r.RemoteAddr); len(out) > 0 {
		return
	}
	return r.RemoteAddr
}
