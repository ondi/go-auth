//
//
//

package auth

import (
	"encoding/json"
	"time"
)

type BearerValidator interface {
	ValidateBearer(ts time.Time, token *TokenBearer_t) error
}

type TokenBearer_t struct {
	Name       string
	Value      []byte
	Body       map[string]interface{}
	Error      error
	validators []BearerValidator
}

func NewTokenBearer(validators ...BearerValidator) *TokenBearer_t {
	return &TokenBearer_t{
		validators: validators,
	}
}

func (self *TokenBearer_t) TokenCreate(name string, value []byte) Token {
	return &TokenBearer_t{
		Name:       name,
		Value:      value,
		validators: self.validators,
	}
}

func (self *TokenBearer_t) GetName() string {
	return self.Name
}

func (self *TokenBearer_t) GetValue() []byte {
	return self.Value
}

func (self *TokenBearer_t) GetError() error {
	return self.Error
}

func (self *TokenBearer_t) SetError(in error) {
	self.Error = in
}

func (self *TokenBearer_t) Validate(ts time.Time, payload []byte) (err error) {
	if self.Error != nil {
		return
	}
	if err = json.Unmarshal(payload, &self.Body); err != nil {
		return
	}
	for _, v := range self.validators {
		if err = v.ValidateBearer(ts, self); err != nil {
			return
		}
	}
	return
}

type Exp_t struct {
	Nbf int64
	Exp int64
}

// nbf = -60
// exp = 60
func NewExp(nbf int64, exp int64) *Exp_t {
	return &Exp_t{Nbf: nbf, Exp: exp}
}

func (self *Exp_t) ValidateBearer(ts time.Time, token *TokenBearer_t) error {
	var test float64
	// not before
	temp, ok := token.Body["nbf"]
	if ok {
		if test, ok = temp.(float64); !ok {
			return ERROR_FORMAT_NBF
		}
		if ok = ts.Unix() >= int64(test)+self.Nbf; !ok {
			return ERROR_NBF
		}
	}
	// expire
	temp, ok = token.Body["exp"]
	if ok {
		if test, ok = temp.(float64); !ok {
			return ERROR_FORMAT_EXP
		}
		if ok = ts.Unix() < int64(test)+self.Exp; !ok {
			return ERROR_EXP
		}
	}
	return nil
}
