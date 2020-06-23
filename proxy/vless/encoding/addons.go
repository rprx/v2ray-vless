// +build !confonly

package encoding

import (
	"crypto/rand"
	"io"

	"github.com/golang/protobuf/proto"

	"v2ray.com/core/common"
	"v2ray.com/core/common/buf"
	"v2ray.com/core/common/crypto"
	"v2ray.com/core/common/protocol"
)

func EncodeAddonsHeader(addons *Addons, buffer *buf.Buffer) {

	switch addons.MessName {
	case "shake":

		addons.MessSeed = make([]byte, 16)
		rand.Read(addons.MessSeed)

		bytes := common.Must2(proto.Marshal(addons)).([]byte)

		common.Must(buffer.WriteByte(byte(len(bytes))))
		common.Must2(buffer.Write(bytes))

	default:

		common.Must(buffer.WriteByte(0))

	}

}

func DecodeAddonsHeader(reader io.Reader, buffer *buf.Buffer) (*Addons, error) {

	addons := &Addons{}

	buffer.Clear()
	if _, err := buffer.ReadFullFrom(reader, 1); err != nil {
		return nil, newError("failed to read addons length").Base(err)
	}

	length := int32(buffer.Byte(0))
	if length != 0 {

		buffer.Clear()
		if _, err := buffer.ReadFullFrom(reader, length); err != nil {
			return nil, newError("failed to read addons bytes").Base(err)
		}

		common.Must(proto.Unmarshal(buffer.Bytes(), addons))

		// Verification
		switch addons.MessName {
		case "shake":
			if len(addons.MessSeed) != 16 {
				return nil, newError("mess: shake's seed length is not 16")
			}
		}

	}

	return addons, nil

}

// EncodeAddonsBody returns a Writer that auto-encrypt content written by caller.
func EncodeAddonsBody(request *protocol.RequestHeader, addons *Addons, writer io.Writer) buf.Writer {

	switch addons.MessName {
	case "shake":

		var sizeParser crypto.ChunkSizeEncoder = crypto.PlainChunkSizeParser{}
		sizeParser = NewShakeSizeParser(addons.MessSeed)
		var padding crypto.PaddingLengthGenerator
		//padding = sizeParser.(crypto.PaddingLengthGenerator)

		if request.Command.TransferType() == protocol.TransferTypeStream {
			return crypto.NewChunkStreamWriter(sizeParser, writer)
		}
		auth := &crypto.AEADAuthenticator{
			AEAD:                    new(NoOpAuthenticator),
			NonceGenerator:          crypto.GenerateEmptyBytes(),
			AdditionalDataGenerator: crypto.GenerateEmptyBytes(),
		}
		return crypto.NewAuthenticationWriter(auth, sizeParser, writer, protocol.TransferTypePacket, padding)

	default:

		return buf.NewWriter(writer)

	}

}

// DecodeAddonsBody returns a Reader from which caller can fetch decrypted body.
func DecodeAddonsBody(request *protocol.RequestHeader, addons *Addons, reader io.Reader) buf.Reader {

	switch addons.MessName {
	case "shake":

		var sizeParser crypto.ChunkSizeDecoder = crypto.PlainChunkSizeParser{}
		sizeParser = NewShakeSizeParser(addons.MessSeed)
		var padding crypto.PaddingLengthGenerator
		//padding = sizeParser.(crypto.PaddingLengthGenerator)

		if request.Command.TransferType() == protocol.TransferTypeStream {
			return crypto.NewChunkStreamReader(sizeParser, reader)
		}
		auth := &crypto.AEADAuthenticator{
			AEAD:                    new(NoOpAuthenticator),
			NonceGenerator:          crypto.GenerateEmptyBytes(),
			AdditionalDataGenerator: crypto.GenerateEmptyBytes(),
		}
		return crypto.NewAuthenticationReader(auth, sizeParser, reader, protocol.TransferTypePacket, padding)

	default:

		return buf.NewReader(reader)

	}

}
