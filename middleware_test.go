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
	parse_bearer, err := NewVerifiersBearer(map[string]KeysBearer_t{"/": {Keys: nil, Approve: ""}})
	assert.NilError(t, err)

	parse_basic, err := NewVerifiersBasic(map[string]KeysBasic_t{"/": {Keys: nil}})
	assert.NilError(t, err)

	parse_noauth, err := NewVerifiersNoAuth(map[string]struct{}{"/": {}})
	assert.NilError(t, err)

	noauth := NewAuth(
		router,
		NewStatus401(),
		parse_noauth,
	)

	basic := NewAuth(
		router,
		noauth,
		parse_basic,
		NewTokenFind(
			NewTokenBasic(),
			KEY_BASIC,
		),
	)

	bearer := NewAuth(
		router,
		basic,
		parse_bearer,
		NewTokenFind(
			NewTokenBearer(
				NewExp(-60, 60),
			),
			KEY_BEARER,
		),
	)

	r := httptest.NewRequest("GET", "http://localhost", nil)
	w := httptest.NewRecorder()
	bearer.ServeHTTP(w, r)
}
