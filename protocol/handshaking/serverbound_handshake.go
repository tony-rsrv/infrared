package handshaking

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/haveachin/infrared/protocol"
)

const (
	ServerBoundHandshakePacketID byte = 0x00

	ServerBoundHandshakeStatusState = protocol.Byte(1)
	ServerBoundHandshakeLoginState  = protocol.Byte(2)

	ForgeSeparator  = "\x00"
	RealIPSeparator = "///"
)

type ServerBoundHandshake struct {
	ProtocolVersion protocol.VarInt
	ServerAddress   protocol.String
	ServerPort      protocol.UnsignedShort
	NextState       protocol.Byte
}

func (pk ServerBoundHandshake) Marshal() protocol.Packet {
	return protocol.MarshalPacket(
		ServerBoundHandshakePacketID,
		pk.ProtocolVersion,
		pk.ServerAddress,
		pk.ServerPort,
		pk.NextState,
	)
}

func UnmarshalServerBoundHandshake(packet protocol.Packet) (ServerBoundHandshake, error) {
	var pk ServerBoundHandshake

	if packet.ID != ServerBoundHandshakePacketID {
		return pk, protocol.ErrInvalidPacketID
	}

	if err := packet.Scan(
		&pk.ProtocolVersion,
		&pk.ServerAddress,
		&pk.ServerPort,
		&pk.NextState,
	); err != nil {
		return pk, err
	}

	return pk, nil
}

func (pk ServerBoundHandshake) IsStatusRequest() bool {
	return pk.NextState == ServerBoundHandshakeStatusState
}

func (pk ServerBoundHandshake) IsLoginRequest() bool {
	return pk.NextState == ServerBoundHandshakeLoginState
}

func (pk ServerBoundHandshake) IsForgeAddress() bool {
	addr := string(pk.ServerAddress)
	return len(strings.Split(addr, ForgeSeparator)) > 1
}

func (pk ServerBoundHandshake) IsRealIPAddress() bool {
	addr := string(pk.ServerAddress)
	return len(strings.Split(addr, RealIPSeparator)) > 1
}

func (pk ServerBoundHandshake) ParseServerAddress() string {
	addr := string(pk.ServerAddress)
	addr = strings.Split(addr, ForgeSeparator)[0]
	addr = strings.Split(addr, RealIPSeparator)[0]
	// Resolves an issue with some proxies
	addr = strings.Trim(addr, ".")
	return addr
}

func (pk *ServerBoundHandshake) UpgradeToRealIP(clientAddr string, timestamp time.Time) {
	if pk.IsRealIPAddress() {
		return
	}

	addr := string(pk.ServerAddress)
	addrWithForge := strings.SplitN(addr, ForgeSeparator, 3)

	addr = fmt.Sprintf("%s///%s///%d", addrWithForge[0], clientAddr, timestamp.Unix())

	if len(addrWithForge) > 1 {
		addr = fmt.Sprintf("%s\x00%s\x00", addr, addrWithForge[1])
	}

	pk.ServerAddress = protocol.String(addr)
}

func (hs *ServerBoundHandshake) UpgradeToNewRealIP(clientAddr string, key *ecdsa.PrivateKey) error {
	hs.UpgradeToRealIP(clientAddr, time.Now())
	text := hs.ServerAddress
	hash := sha512.Sum512([]byte(text))
	bytes, err := ecdsa.SignASN1(rand.Reader, key, hash[:])
	if err != nil {
		return err
	}
	encoded := base64.StdEncoding.EncodeToString(bytes)
	addr := fmt.Sprintf("%s///%s", hs.ServerAddress, encoded)
	hs.ServerAddress = protocol.String(addr)
	return nil
}
