//
//
//

package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var (
	VALIDATOR   = &Validator_t{Nbf: 60, Exp: -60}
	ERROR_MATCH = errors.New("NO MATCHING ELEMENTS")
)

type auth_t string

var ctx_auth auth_t = "AUTH"

func Auth(ctx context.Context) (res map[string]interface{}) {
	res, _ = ctx.Value(ctx_auth).(map[string]interface{})
	return
}

func ERROR(w http.ResponseWriter, r *http.Request, err error) {
	w.WriteHeader(http.StatusUnauthorized)
	io.WriteString(w, "AUTHORIZATION REQUIRED")
	if err != nil {
		io.WriteString(w, " ")
		io.WriteString(w, err.Error())
	}
}

func TOKEN(r *http.Request) (out []string) {
	var ix int
	var token string
	for _, token = range r.Header["Authorization"] {
		if ix = strings.IndexByte(token, ' '); ix > -1 {
			out = append(out, token[ix+1:])
		}
	}
	if c, err := r.Cookie("Authorization"); err == nil {
		if token, err = url.QueryUnescape(c.Value); err == nil {
			if ix = strings.IndexByte(token, ' '); ix > -1 {
				out = append(out, token[ix+1:])
			}
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

type Validator_t struct {
	Nbf        int64
	Exp        int64
	ExtraCheck func(ctx context.Context, route string, ts time.Time, in map[string]interface{}) error
}

func (self *Validator_t) Validate(ctx context.Context, route string, ts time.Time, payload []byte) (out context.Context, err error) {
	var test float64
	var res map[string]interface{}

	if err = json.Unmarshal(payload, &res); err != nil {
		return
	}

	// not before
	temp, ok := res["nbf"]
	if ok {
		if test, ok = temp.(float64); !ok {
			return ctx, fmt.Errorf("nbf format error")
		}
		if int64(test) > ts.Unix()+self.Nbf {
			return ctx, fmt.Errorf("nbf=%v", int64(test))
		}
	}
	// expire
	temp, ok = res["exp"]
	if ok {
		if test, ok = temp.(float64); !ok {
			return ctx, fmt.Errorf("exp format error")
		}
		if int64(test) < ts.Unix()+self.Exp {
			return ctx, fmt.Errorf("exp=%v", int64(test))
		}
	}

	if self.ExtraCheck != nil {
		if err = self.ExtraCheck(ctx, route, ts, res); err != nil {
			return
		}
	}

	out = context.WithValue(ctx, ctx_auth, res)
	return
}
