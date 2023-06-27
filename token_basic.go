//
//
//

package auth

import (
	"net/http"
	"net/url"
	"strings"
	"time"
)

type BASIC_PAYLOAD = []byte

type BASIC_PAYLOAD_GET interface {
	BasicPayload() BASIC_PAYLOAD
}

type TokenBasic_t struct {
	Name  string
	Value []byte
}

func (self *TokenBasic_t) GetName() string {
	return self.Name
}

func (self *TokenBasic_t) BasicPayload() BASIC_PAYLOAD {
	return self.Value
}

func (self *TokenBasic_t) VerifyAndValidate(in Verifier, ts time.Time) (ok bool) {
	_, ok = in.Verify(self.Value)
	return
}

type GetBasic_t struct {
}

func NewGetBasic() *GetBasic_t {
	return &GetBasic_t{}
}

func (self *GetBasic_t) Tokens(r *http.Request) (out []Token) {
	var ix int
	var token string
	for _, token = range r.Header[AUTHORIZATION] {
		if ix = strings.IndexByte(token, ' '); ix > -1 && token[:ix] == "Basic" {
			out = append(out, &TokenBasic_t{Name: AUTHORIZATION, Value: []byte(token[ix+1:])})
		}
	}
	if c, err := r.Cookie(AUTHORIZATION); err == nil {
		if token, err = url.QueryUnescape(c.Value); err == nil {
			if ix = strings.IndexByte(token, ' '); ix > -1 && token[:ix] == "Basic" {
				out = append(out, &TokenBasic_t{Name: AUTHORIZATION, Value: []byte(token[ix+1:])})
			}
		}
	}
	return
}
