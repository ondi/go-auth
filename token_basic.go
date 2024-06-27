//
//
//

package auth

import (
	"bytes"
	"time"
)

type BasicValidator interface {
	ValidateBasic(ts time.Time, token *TokenBasic_t) error
}

type TokenBasic_t struct {
	Name       string
	Value      []byte
	Body       []byte
	Error      error
	validators []BasicValidator
}

func NewTokenBasic(validators ...BasicValidator) *TokenBasic_t {
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

func (self *TokenBasic_t) SetError(in error) {
	self.Error = in
}

func (self *TokenBasic_t) Validate(ts time.Time, payload []byte) (err error) {
	if self.Error != nil {
		return
	}
	if ix := bytes.IndexByte(payload, ':'); ix > -1 {
		self.Body = payload[:ix]
	} else {
		self.Body = payload
	}
	for _, v := range self.validators {
		if err = v.ValidateBasic(ts, self); err != nil {
			return
		}
	}
	return
}
