//
//
//

package auth

import (
	"encoding/json"
	"time"
)

type BearerValidator interface {
	ValidateBearer(ts time.Time, route string, token *TokenBearer_t) error
}

type TokenBearer_t struct {
	KeyId      string
	Name       string
	Type       string
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

func (self *TokenBearer_t) TokenCreate(Name string, Type string, Value []byte) Token {
	return &TokenBearer_t{
		Name:       Name,
		Type:       Type,
		Value:      Value,
		validators: self.validators,
	}
}

func (self *TokenBearer_t) GetKeyId() string {
	return self.KeyId
}

func (self *TokenBearer_t) GetName() string {
	return self.Name
}

func (self *TokenBearer_t) GetType() string {
	return self.Type
}

func (self *TokenBearer_t) GetValue() []byte {
	return self.Value
}

func (self *TokenBearer_t) GetError() error {
	return self.Error
}

func (self *TokenBearer_t) SetError(in error) {
	if self.Error == nil {
		self.Error = in
	}
}

func (self *TokenBearer_t) Validate(ts time.Time, route string, key_id string, payload []byte) (err error) {
	self.KeyId = key_id
	if err = json.Unmarshal(payload, &self.Body); err != nil {
		return
	}
	for _, v := range self.validators {
		if err = v.ValidateBearer(ts, route, self); err != nil {
			return
		}
	}
	return
}

type Exp_t struct {
	nbf int64
	exp int64
}

// nbf = -60
// exp = 60
func NewExp(nbf int64, exp int64) *Exp_t {
	return &Exp_t{nbf: nbf, exp: exp}
}

func (self *Exp_t) ValidateBearer(ts time.Time, route string, token *TokenBearer_t) error {
	var test float64
	// not before
	temp, ok := token.Body["nbf"]
	if ok {
		if test, ok = temp.(float64); !ok {
			return ERROR_VALIDATE_FORMAT_NBF
		}
		if ok = ts.Unix() >= int64(test)+self.nbf; !ok {
			return ERROR_VALIDATE_NBF
		}
	}
	// expire
	temp, ok = token.Body["exp"]
	if ok {
		if test, ok = temp.(float64); !ok {
			return ERROR_VALIDATE_FORMAT_EXP
		}
		if ok = ts.Unix() < int64(test)+self.exp; !ok {
			return ERROR_VALIDATE_EXP
		}
	}
	return nil
}
