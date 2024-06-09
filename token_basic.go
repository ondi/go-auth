//
//
//

package auth

import (
	"bytes"
	"time"
)

type TokenBasic_t struct {
	Name       string
	Value      []byte
	Body       []byte
	Error      error
	validators []Validator
}

func NewTokenBasic(validators ...Validator) *TokenBasic_t {
	return &TokenBasic_t{
		validators: validators,
	}
}

func (self *TokenBasic_t) Create(name string, value []byte) Token {
	return &TokenBasic_t{
		Name:       name,
		Value:      value,
		validators: self.validators,
	}
}

func (self *TokenBasic_t) GetName() string {
	return self.Name
}

func (self *TokenBasic_t) GetValue() []byte {
	return self.Value
}

func (self *TokenBasic_t) GetError() error {
	return self.Error
}

func (self *TokenBasic_t) Validate(ts time.Time, payload []byte, verify_error error) error {
	if self.Error = verify_error; self.Error != nil {
		return self.Error
	}
	if ix := bytes.IndexByte(payload, ':'); ix > -1 {
		self.Body = payload[:ix]
	} else {
		self.Body = payload
	}
	return nil
}
