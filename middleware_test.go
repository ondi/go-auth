//
//
//

package auth

import (
	"testing"

	"gotest.tools/assert"
)

func Test001(t *testing.T) {
	bearer := NewTokenBearer(NewExp())
	find := NewFindBearer(bearer)
	parser, err := NewParseBearer(1, nil)
	assert.Assert(t, err == nil)
	auth := NewAuth(nil, nil, parser, find)
	_ = auth
	// auth.ServeHTTP(nil, nil)
}
