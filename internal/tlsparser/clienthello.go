package tlsparser

import (
	"bytes"
	"encoding/binary"
	"errors"
)

type ClientHello struct {
	Version      uint16
	Random       []byte
	SessionID    []byte
	CipherSuites []uint16
	Extensions   map[uint16][]byte
	ServerName   string
}

const (
	ExtensionSNI     = 0x00
	ExtensionPadding = 0x15
)

// Main entry point for streaming proxy:
func TryParseClientHello(data []byte) (*ClientHello, error) {
	if len(data) < 5 {
		return nil, errors.New("incomplete TLS record")
	}
	if data[0] != 0x16 {
		return nil, errors.New("not TLS Handshake record")
	}

	recordLength := int(binary.BigEndian.Uint16(data[3:5]))
	if len(data) < 5+recordLength {
		return nil, errors.New("incomplete TLS record payload")
	}

	payload := data[5 : 5+recordLength]
	if len(payload) < 4 || payload[0] != 0x01 {
		return nil, errors.New("not ClientHello handshake")
	}

	handshakeLength := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	if len(payload[4:]) < handshakeLength {
		return nil, errors.New("incomplete ClientHello body")
	}

	reader := bytes.NewReader(payload[4:])

	ch := &ClientHello{}
	binary.Read(reader, binary.BigEndian, &ch.Version)

	ch.Random = make([]byte, 32)
	reader.Read(ch.Random)

	var sidLen uint8
	binary.Read(reader, binary.BigEndian, &sidLen)
	ch.SessionID = make([]byte, sidLen)
	reader.Read(ch.SessionID)

	var csLen uint16
	binary.Read(reader, binary.BigEndian, &csLen)
	ch.CipherSuites = make([]uint16, csLen/2)
	for i := range ch.CipherSuites {
		binary.Read(reader, binary.BigEndian, &ch.CipherSuites[i])
	}

	var compLen uint8
	binary.Read(reader, binary.BigEndian, &compLen)
	reader.Seek(int64(compLen), 1)

	ch.Extensions = make(map[uint16][]byte)

	var extLen uint16
	if err := binary.Read(reader, binary.BigEndian, &extLen); err != nil {
		return ch, nil
	}

	for pos := 0; pos < int(extLen); {
		var extType uint16
		var extDataLen uint16
		binary.Read(reader, binary.BigEndian, &extType)
		binary.Read(reader, binary.BigEndian, &extDataLen)

		extData := make([]byte, extDataLen)
		reader.Read(extData)

		ch.Extensions[extType] = extData
		pos += 4 + int(extDataLen)

		if extType == ExtensionSNI {
			if len(extData) >= 5 {
				sniReader := bytes.NewReader(extData[2:])
				var nameType uint8
				binary.Read(sniReader, binary.BigEndian, &nameType)
				if nameType == 0x00 {
					var nameLen uint16
					binary.Read(sniReader, binary.BigEndian, &nameLen)
					serverName := make([]byte, nameLen)
					sniReader.Read(serverName)
					ch.ServerName = string(serverName)
				}
			}
		}
	}

	return ch, nil
}

func (ch *ClientHello) RemoveSNI() {
	delete(ch.Extensions, ExtensionSNI)
	ch.ServerName = ""
}

func (ch *ClientHello) AddPadding(padSize int) {
	padding := make([]byte, padSize)
	ch.Extensions[ExtensionPadding] = padding
}

func (ch *ClientHello) Serialize() ([]byte, error) {
	buf := &bytes.Buffer{}

	// Version
	binary.Write(buf, binary.BigEndian, ch.Version)

	// Random
	buf.Write(ch.Random)

	// Session ID
	binary.Write(buf, binary.BigEndian, uint8(len(ch.SessionID)))
	buf.Write(ch.SessionID)

	// Cipher Suites
	binary.Write(buf, binary.BigEndian, uint16(len(ch.CipherSuites)*2))
	for _, cs := range ch.CipherSuites {
		binary.Write(buf, binary.BigEndian, cs)
	}

	// Compression methods
	buf.WriteByte(1) // Length
	buf.WriteByte(0) // null compression

	// Extensions
	extBuf := &bytes.Buffer{}
	for extType, extData := range ch.Extensions {
		binary.Write(extBuf, binary.BigEndian, extType)
		binary.Write(extBuf, binary.BigEndian, uint16(len(extData)))
		extBuf.Write(extData)
	}

	binary.Write(buf, binary.BigEndian, uint16(extBuf.Len()))
	buf.Write(extBuf.Bytes())

	handshakePayload := buf.Bytes()

	// Build Handshake layer
	handshake := &bytes.Buffer{}
	handshake.WriteByte(0x01) // ClientHello
	writeUint24(handshake, len(handshakePayload))
	handshake.Write(handshakePayload)

	handshakeBytes := handshake.Bytes()

	// Build TLS Record Layer
	record := &bytes.Buffer{}
	record.WriteByte(0x16)           // Handshake ContentType
	record.Write([]byte{0x03, 0x03}) // TLS version 1.2 (мы фиксируем тут TLS 1.2)
	binary.Write(record, binary.BigEndian, uint16(len(handshakeBytes)))
	record.Write(handshakeBytes)

	return record.Bytes(), nil
}

func writeUint24(buf *bytes.Buffer, val int) {
	buf.WriteByte(byte(val >> 16))
	buf.WriteByte(byte(val >> 8))
	buf.WriteByte(byte(val))
}
