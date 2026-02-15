//
//
//

package auth

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/ondi/go-tst"
)

var (
	// &auth used for context.Value key
	auth                      = 1
	ERROR_VERIFY_FAILED       = errors.New("verify failed")
	ERROR_VALIDATE_FORMAT_NBF = errors.New("validate format nbf")
	ERROR_VALIDATE_FORMAT_EXP = errors.New("validate format exp")
	ERROR_VALIDATE_NBF        = errors.New("validate nbf")
	ERROR_VALIDATE_EXP        = errors.New("validate exp")
	KEY_BEARER                = TokenArgs_t{Name: "bearer", Type: "Bearer", HeaderKey: "Authorization", HeaderPrefix: []string{"Bearer"}, QueryKey: "bearer"}
	KEY_BASIC                 = TokenArgs_t{Name: "basic", Type: "Basic", HeaderKey: "Authorization", HeaderPrefix: []string{"Basic"}, QueryKey: "basic"}
)

type Token interface {
	GetKeyId() string
	GetName() string
	GetType() string
	GetValue() []byte
	GetError() error
	SetError(error)
	Validate(ts time.Time, route string, key_id string, payload []byte) error
}

type ErrorVerify_t struct {
	error
}

type ErrorValidate_t struct {
	error
}

type TokenCreator interface {
	TokenCreate(Name string, Type string, Value []byte) Token
}

type TokenFinder interface {
	TokenFind(r *http.Request) (keys_found int, out []Token)
}

type Verifier interface {
	TokenFinder
	Verify(token []byte) (payload []byte, key_id string, err error)
	Approve(passed []Token) (ok bool)
}

type Found_t struct {
	Passed    []Token
	Failed    []Token
	KeysFound int
}

func Found(ctx context.Context) (found Found_t) {
	if temp, _ := ctx.Value(&auth).(*Found_t); temp != nil {
		found = *temp
	}
	return
}

func AppendCtx(ctx context.Context, found Found_t) context.Context {
	temp, _ := ctx.Value(&auth).(*Found_t)
	if temp == nil {
		temp = &Found_t{}
		ctx = context.WithValue(ctx, &auth, temp)
	}
	temp.KeysFound += found.KeysFound
	temp.Passed = append(temp.Passed, found.Passed...)
	temp.Failed = append(temp.Failed, found.Failed...)
	return ctx
}

type Auth_t struct {
	next_passed http.Handler
	next_failed http.Handler
	routes      *tst.Tree3_t[Verifier]
}

func NewAuth(next_passed http.Handler, next_failed http.Handler) (self *Auth_t) {
	self = &Auth_t{
		next_passed: next_passed,
		next_failed: next_failed,
		routes:      tst.NewTree3[Verifier](),
	}
	return
}

func (self *Auth_t) AddVerifier(route string, verifier Verifier) (ok bool) {
	_, ok = self.routes.Add(route, verifier)
	return
}

func (self *Auth_t) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var err error
	var found Found_t
	var key_id string
	var payload []byte
	ts := time.Now()
	verifier, _, count := self.routes.Search(r.URL.Path)
	if count > 0 {
		keys_found, tokens := verifier.TokenFind(r)
		found.KeysFound += keys_found
		for _, v2 := range tokens {
			if payload, key_id, err = verifier.Verify(v2.GetValue()); err != nil {
				v2.SetError(ErrorVerify_t{err})
			}
			if err = v2.Validate(ts, r.URL.Path, key_id, payload); err != nil {
				v2.SetError(ErrorValidate_t{err})
			}
			if v2.GetError() != nil {
				found.Failed = append(found.Failed, v2)
			} else {
				found.Passed = append(found.Passed, v2)
			}
		}
		if verifier.Approve(found.Passed) {
			self.next_passed.ServeHTTP(w, r.WithContext(AppendCtx(r.Context(), found)))
			return
		}
	}
	self.next_failed.ServeHTTP(w, r.WithContext(AppendCtx(r.Context(), found)))
}

type Status_t struct {
	status_code int
}

func NewStatus(status_code int) *Status_t {
	return &Status_t{
		status_code: status_code,
	}
}

func NewStatus401() *Status_t {
	return NewStatus(http.StatusUnauthorized)
}

func (self *Status_t) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(self.status_code)
}

type EmptyAuth_t struct {
	Next http.Handler
}

func (self *EmptyAuth_t) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	self.Next.ServeHTTP(w, r.WithContext(AppendCtx(r.Context(), Found_t{})))
}
