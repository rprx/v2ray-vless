// +build !confonly

package vless

import (
	"strings"
	"sync"

	"v2ray.com/core/common/protocol"
	"v2ray.com/core/common/uuid"
)

// UserValidator is a user Validator.
type UserValidator struct {
	sync.RWMutex
	users map[uuid.UUID]*protocol.MemoryUser
}

// NewUserValidator creates a new UserValidator.
func NewUserValidator() *UserValidator {
	return &UserValidator{
		users: make(map[uuid.UUID]*protocol.MemoryUser), // need more
	}
}

func (v *UserValidator) Add(u *protocol.MemoryUser) error {
	v.Lock()
	defer v.Unlock()

	v.users[u.Account.(*MemoryAccount).ID.UUID()] = u
	return nil
}

func (v *UserValidator) Get(id uuid.UUID) (*protocol.MemoryUser, bool) {
	defer v.RUnlock()
	v.RLock()

	u, found := v.users[id]
	if found {
		return u, true
	}
	return nil, false
}

func (v *UserValidator) Remove(email string) bool {
	v.Lock()
	defer v.Unlock()

	email = strings.ToLower(email)
	for id, u := range v.users {
		if strings.EqualFold(u.Email, email) {
			delete(v.users, id)
			return true
		}
	}
	return false
}
