//
//
//

package auth

import (
	"time"
)

type BasicValidator interface {
	ValidateBasic(ts time.Time, route string, token *TokenBasic_t) error
}

type TokenBasic_t struct {
	KeyId      string
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

func (self *TokenBasic_t) GetKeyId() string {
	return self.KeyId
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
	}
}

func (self *TokenBasic_t) Validate(ts time.Time, route string, key_id string, payload []byte) (err error) {
	self.KeyId = key_id
	for _, v := range self.validators {
		if err = v.ValidateBasic(ts, route, self); err != nil {
			return
		}
	}
	return
}
