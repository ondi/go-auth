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

var TOKEN = GetToken
var ADDR = GetAddr
var ERROR = ShowError
var VALIDATOR = (&Validate_t{Nbf: 60, Exp: -60}).Validate

type auth_t string

var ctx_auth auth_t = "AUTH"

func Auth(ctx context.Context) (res map[string]interface{}) {
	res, _ = ctx.Value(ctx_auth).(map[string]interface{})
	return
}

type Validator_t func(payload []byte) (res map[string]interface{}, err error)
type Token_t func(r *http.Request) (res []string)
type Addr_t func(r *http.Request) (addr string)
type Error_t func(w http.ResponseWriter, r *http.Request, err error)

type Validate_t struct {
	Nbf int64
	Exp int64
}

func (self *Validate_t) Validate(payload []byte) (res map[string]interface{}, err error) {
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

func GetToken(r *http.Request) (res []string) {
	res = r.Header["Authorization"]
	if c, err := r.Cookie("Authorization"); err == nil {
		if v, err := url.QueryUnescape(c.Value); err == nil {
			res = append(res, v)
		}
	}
	return
}

func GetAddr(r *http.Request) (addr string) {
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

func ShowError(w http.ResponseWriter, r *http.Request, err error) {
	if err != nil {
		http.Error(w, "AUTHORIZATION REQUIRED: "+err.Error(), http.StatusUnauthorized)
	} else {
		http.Error(w, "AUTHORIZATION REQUIRED", http.StatusUnauthorized)
	}
}
