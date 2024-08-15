//
//
//

package auth

import (
	"bytes"
	"fmt"
	"time"
)

type BasicValidator interface {
	ValidateBasic(ts time.Time, token *TokenBasic_t) error
	Suspend(bool)
}

type TokenBasic_t struct {
	Name       string
	Type       string
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

func (self *TokenBasic_t) TokenCreate(Name string, Type string, Value []byte) Token {
	return &TokenBasic_t{
		Name:       Name,
		Type:       Type,
		Value:      Value,
		validators: self.validators,
	}
}

func (self *TokenBasic_t) GetName() string {
	return self.Name
}

func (self *TokenBasic_t) GetType() string {
	return self.Type
}

func (self *TokenBasic_t) GetValue() []byte {
	return self.Value
}

func (self *TokenBasic_t) GetError() error {
	return self.Error
}

func (self *TokenBasic_t) SetError(in error) {
	if self.Error == nil {
		self.Error = in
	} else {
		self.Error = fmt.Errorf("%w, %w", self.Error, in)
	}
}

func (self *TokenBasic_t) Validate(ts time.Time, payload []byte) (err error) {
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
