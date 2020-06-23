package conf

import (
	"encoding/json"
	"strings"

	"github.com/golang/protobuf/proto"

	"v2ray.com/core/common/protocol"
	"v2ray.com/core/common/serial"
	"v2ray.com/core/proxy/vless"
	"v2ray.com/core/proxy/vless/inbound"
	"v2ray.com/core/proxy/vless/outbound"
)

type VLessAccount struct {
	ID       string `json:"id"`
	Mess     string `json:"mess"`
	Security string `json:"security"`
}

// Build implements Buildable
func (a *VLessAccount) Build() *vless.Account {
	var st protocol.SecurityType
	switch strings.ToLower(a.Security) {
	case "aes-128-gcm":
		st = protocol.SecurityType_AES128_GCM
	case "chacha20-poly1305":
		st = protocol.SecurityType_CHACHA20_POLY1305
	case "auto":
		st = protocol.SecurityType_AUTO
	case "none":
		st = protocol.SecurityType_NONE
	default:
		st = protocol.SecurityType_AUTO
	}
	return &vless.Account{
		Id:   a.ID,
		Mess: a.Mess,
		SecuritySettings: &protocol.SecurityConfig{
			Type: st,
		},
	}
}

type VLessDefaultConfig struct {
	Level byte `json:"level"`
}

// Build implements Buildable
func (c *VLessDefaultConfig) Build() *inbound.DefaultConfig {
	config := new(inbound.DefaultConfig)
	config.Level = uint32(c.Level)
	return config
}

type VLessInboundConfig struct {
	Users    []json.RawMessage   `json:"clients"`
	Defaults *VLessDefaultConfig `json:"default"`
}

// Build implements Buildable
func (c *VLessInboundConfig) Build() (proto.Message, error) {
	config := &inbound.Config{}

	if c.Defaults != nil {
		config.Default = c.Defaults.Build()
	}

	config.User = make([]*protocol.User, len(c.Users))
	for idx, rawData := range c.Users {
		user := new(protocol.User)
		if err := json.Unmarshal(rawData, user); err != nil {
			return nil, newError("invalid VLess user").Base(err)
		}
		account := new(VLessAccount)
		if err := json.Unmarshal(rawData, account); err != nil {
			return nil, newError("invalid VLess user").Base(err)
		}
		user.Account = serial.ToTypedMessage(account.Build())
		config.User[idx] = user
	}

	return config, nil
}

type VLessOutboundTarget struct {
	Address *Address          `json:"address"`
	Port    uint16            `json:"port"`
	Users   []json.RawMessage `json:"users"`
}

type VLessOutboundConfig struct {
	Receivers []*VLessOutboundTarget `json:"vnext"`
}

// Build implements Buildable
func (c *VLessOutboundConfig) Build() (proto.Message, error) {
	config := new(outbound.Config)

	if len(c.Receivers) == 0 {
		return nil, newError("0 VLess receiver configured")
	}
	serverSpecs := make([]*protocol.ServerEndpoint, len(c.Receivers))
	for idx, rec := range c.Receivers {
		if len(rec.Users) == 0 {
			return nil, newError("0 user configured for VLess outbound")
		}
		if rec.Address == nil {
			return nil, newError("address is not set in VLess outbound config")
		}
		spec := &protocol.ServerEndpoint{
			Address: rec.Address.Build(),
			Port:    uint32(rec.Port),
		}
		for _, rawUser := range rec.Users {
			user := new(protocol.User)
			if err := json.Unmarshal(rawUser, user); err != nil {
				return nil, newError("invalid VLess user").Base(err)
			}
			account := new(VLessAccount)
			if err := json.Unmarshal(rawUser, account); err != nil {
				return nil, newError("invalid VLess user").Base(err)
			}
			user.Account = serial.ToTypedMessage(account.Build())
			spec.User = append(spec.User, user)
		}
		serverSpecs[idx] = spec
	}
	config.Receiver = serverSpecs
	return config, nil
}
