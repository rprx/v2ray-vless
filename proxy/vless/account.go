// +build !confonly

package vless

import (
	"v2ray.com/core/common/protocol"
	"v2ray.com/core/common/uuid"
)

// MemoryAccount is an in-memory from of VLess account.
type MemoryAccount struct {
	// ID is the main ID of the account.
	ID *protocol.ID
	// Mess type of the account. Used for client connections for now.
	Mess string
	// Security type of the account. Used for client connections.
	Security protocol.SecurityType
}

// Equals implements protocol.Account.
func (a *MemoryAccount) Equals(account protocol.Account) bool {
	vlessAccount, ok := account.(*MemoryAccount)
	if !ok {
		return false
	}
	return a.ID.Equals(vlessAccount.ID)
}

// AsAccount implements protocol.Account.
func (a *Account) AsAccount() (protocol.Account, error) {
	id, err := uuid.ParseString(a.Id)
	if err != nil {
		return nil, newError("failed to parse ID").Base(err).AtError()
	}
	protoID := protocol.NewID(id)
	return &MemoryAccount{
		ID:       protoID,
		Mess:     a.Mess,
		Security: a.SecuritySettings.GetSecurityType(),
	}, nil
}
