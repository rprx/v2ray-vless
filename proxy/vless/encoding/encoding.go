package encoding

import (
	"io"

	"v2ray.com/core/common"
	"v2ray.com/core/common/buf"
	"v2ray.com/core/common/net"
	"v2ray.com/core/common/protocol"
	"v2ray.com/core/proxy/vless"
)

//go:generate errorgen

const (
	Version = byte(0)
)

var addrParser = protocol.NewAddressParser(
	protocol.AddressFamilyByte(byte(protocol.AddressTypeIPv4), net.AddressFamilyIPv4),
	protocol.AddressFamilyByte(byte(protocol.AddressTypeDomain), net.AddressFamilyDomain),
	protocol.AddressFamilyByte(byte(protocol.AddressTypeIPv6), net.AddressFamilyIPv6),
	protocol.PortThenAddress(),
)

// EncodeRequestHeader writes encoded request header into the given writer.
func EncodeRequestHeader(request *protocol.RequestHeader, addons *Addons, writer io.Writer) error {

	buffer := buf.StackNew()
	defer buffer.Release()

	common.Must(buffer.WriteByte(request.Version))
	common.Must2(buffer.Write(request.User.Account.(*vless.MemoryAccount).ID.Bytes()))

	EncodeAddonsHeader(addons, &buffer)

	common.Must(buffer.WriteByte(byte(request.Command)))
	if request.Command != protocol.RequestCommandMux {
		if err := addrParser.WriteAddressPort(&buffer, request.Address, request.Port); err != nil {
			return newError("failed to write address and port").Base(err)
		}
	}

	common.Must2(writer.Write(buffer.Bytes()))
	return nil
}

// DecodeRequestHeader decodes and returns (if successful) a RequestHeader from an input stream.
func DecodeRequestHeader(validator *vless.UserValidator, reader io.Reader) (*protocol.RequestHeader, *Addons, error) {

	buffer := buf.StackNew()
	defer buffer.Release()

	if _, err := buffer.ReadFullFrom(reader, 1); err != nil {
		return nil, nil, newError("failed to read request version").Base(err).AtWarning()
	}

	request := &protocol.RequestHeader{
		Version: buffer.Byte(0),
	}

	switch request.Version {
	case 0:

		buffer.Clear()
		if _, err := buffer.ReadFullFrom(reader, protocol.IDBytesLen); err != nil {
			return nil, nil, newError("failed to read request user").Base(err)
		}

		var id [16]byte
		copy(id[:], buffer.Bytes())
		user, valid := validator.Get(id)
		if !valid {
			return nil, nil, newError("invalid request user")
		}
		request.User = user

		addons, err := DecodeAddonsHeader(reader, &buffer)
		if err != nil {
			return nil, nil, err
		}

		buffer.Clear()
		if _, err := buffer.ReadFullFrom(reader, 1); err != nil {
			return nil, nil, newError("failed to read request command").Base(err)
		}

		request.Command = protocol.RequestCommand(buffer.Byte(0))

		switch request.Command {
		case protocol.RequestCommandMux:
			request.Address = net.DomainAddress("v1.mux.cool")
			request.Port = 0
		case protocol.RequestCommandTCP, protocol.RequestCommandUDP:
			if addr, port, err := addrParser.ReadAddressPort(&buffer, reader); err == nil {
				request.Address = addr
				request.Port = port
			}
		}

		if request.Address == nil {
			return nil, nil, newError("invalid request address")
		}

		return request, addons, nil

	default:

		return nil, nil, newError("unexpected request version")

	}

}

// EncodeResponseHeader writes encoded response header into the given writer.
func EncodeResponseHeader(request *protocol.RequestHeader, response *Addons, writer io.Writer) error {

	buffer := buf.StackNew()
	defer buffer.Release()

	common.Must(buffer.WriteByte(request.Version))

	EncodeAddonsHeader(response, &buffer)

	common.Must2(writer.Write(buffer.Bytes()))
	return nil
}

// DecodeResponseHeader decodes and returns (if successful) a ResponseHeader from an input stream.
func DecodeResponseHeader(request *protocol.RequestHeader, reader io.Reader) (*Addons, error) {

	buffer := buf.StackNew()
	defer buffer.Release()

	if _, err := buffer.ReadFullFrom(reader, 1); err != nil {
		return nil, newError("failed to read response version").Base(err).AtWarning()
	}

	if buffer.Byte(0) != request.Version {
		return nil, newError("unexpected response version. Expecting ", int(request.Version), " but actually ", int(buffer.Byte(0)))
	}

	response, err := DecodeAddonsHeader(reader, &buffer)
	if err != nil {
		return nil, err
	}

	return response, nil
}
