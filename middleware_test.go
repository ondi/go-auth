//
//
//

package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"gotest.tools/assert"
)

var router = http.DefaultServeMux

func Test001(t *testing.T) {
	find_bearer := NewTokenFind(
		NewTokenBearer(
			NewExp(-60, 60),
		),
		KEY_BEARER,
	)

	find_basic := NewTokenFind(
		NewTokenBasic(),
		KEY_BASIC,
	)

	verify_bearer, err := NewVerifyBearer(nil, "", find_bearer)
	assert.NilError(t, err)

	verify_basic, err := NewVerifyBasic(nil, "", find_basic)
	assert.NilError(t, err)

	verifiy_noauth, err := NewVerifyNoAuth()
	assert.NilError(t, err)

	noauth := NewAuth(router, NewStatus401(false))
	noauth.AddVerifier("/noath", verifiy_noauth)

	basic := NewAuth(router, noauth)
	basic.AddVerifier("/basic", verify_basic)

	bearer := NewAuth(router, basic)
	bearer.AddVerifier("/bearer", verify_bearer)

	r1 := httptest.NewRequest("GET", "http://localhost", nil)
	w1 := httptest.NewRecorder()
	bearer.ServeHTTP(w1, r1)
}
