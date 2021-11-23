//
//
//

package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

var TOKEN = Token_t{}
var ADDR = Addr_t{}
var ERROR = Error_t{}
var VALIDATOR = &Validator_t{Nbf: 60, Exp: -60}

type auth_key_t string

func Auth(ctx context.Context) (res map[string]interface{}, ok bool) {
	res, ok = ctx.Value(auth_key_t("AUTH")).(map[string]interface{})
	return
}

type Validator interface {
	Validate(payload []byte) (res map[string]interface{}, err error)
}

type Validator_t struct {
	Nbf int64
	Exp int64
}

func (self *Validator_t) Validate(payload []byte) (res map[string]interface{}, err error) {
	now := time.Now().Unix()
	nbf := now + self.Nbf
	exp := now + self.Exp

	var ts float64
	res = map[string]interface{}{}
	if err = json.Unmarshal(payload, &res); err != nil {
		return
	}
	// not before
	temp, ok := res["nbf"]
	if ok {
		if ts, ok = temp.(float64); !ok {
			return res, fmt.Errorf("nbf format error")
		}
		if int64(ts) > nbf {
			return res, fmt.Errorf("nbf=%v", int64(ts)-nbf)
		}
	}
	// expire
	temp, ok = res["exp"]
	if ok {
		if ts, ok = temp.(float64); !ok {
			return res, fmt.Errorf("exp format error")
		}
		if int64(ts) < exp {
			return res, fmt.Errorf("exp=%v", int64(ts)-exp)
		}
	}
	return
}

type Token interface {
	GetToken(r *http.Request) (res []string)
}

type Token_t struct{}

func (Token_t) GetToken(r *http.Request) (res []string) {
	res = r.Header["Authorization"]
	if c, err := r.Cookie("Authorization"); err == nil {
		if v, err := url.QueryUnescape(c.Value); err == nil {
			res = append(res, v)
		}
	}
	return
}

type Addr interface {
	GetAddr(r *http.Request) (addr string)
}

type Addr_t struct{}

func (Addr_t) GetAddr(r *http.Request) (addr string) {
	if addr = r.Header.Get("X-Forwarded-For"); len(addr) > 0 {
		return
	}
	if addr = r.Header.Get("X-Real-IP"); len(addr) > 0 {
		return
	}
	if addr, _, _ = net.SplitHostPort(r.RemoteAddr); len(addr) > 0 {
		return
	}
	return r.RemoteAddr
}

type Error interface {
	ShowError(w http.ResponseWriter, r *http.Request, err error)
}

type Error_t struct{}

func (Error_t) ShowError(w http.ResponseWriter, r *http.Request, err error) {
	if err != nil {
		http.Error(w, "AUTHORIZATION REQUIRED: "+err.Error(), http.StatusUnauthorized)
	} else {
		http.Error(w, "AUTHORIZATION REQUIRED ", http.StatusUnauthorized)
	}
}
