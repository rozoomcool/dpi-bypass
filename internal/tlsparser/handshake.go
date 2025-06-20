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
	ServerName   string // кешируем SNI для удобства
}

const (
	ExtensionSNI     = 0x00
	ExtensionPadding = 0x15
)

func ParseClientHello(data []byte) (*ClientHello, error) {
	if len(data) < 5 || data[0] != 0x16 {
		return nil, errors.New("invalid TLS record")
	}

	payload := data[5:]
	if payload[0] != 0x01 {
		return nil, errors.New("not ClientHello")
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
		var extLen uint16
		binary.Read(reader, binary.BigEndian, &extType)
		binary.Read(reader, binary.BigEndian, &extLen)

		extData := make([]byte, extLen)
		reader.Read(extData)

		ch.Extensions[extType] = extData
		pos += 4 + int(extLen)

		if extType == ExtensionSNI {
			// парсим SNI
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

// Удалить SNI extension
func (ch *ClientHello) RemoveSNI() {
	delete(ch.Extensions, ExtensionSNI)
	ch.ServerName = ""
}

// Добавить Padding extension
func (ch *ClientHello) AddPadding(padSize int) {
	padding := make([]byte, padSize)
	ch.Extensions[ExtensionPadding] = padding
}

func (ch *ClientHello) Serialize() ([]byte, error) {
	buf := &bytes.Buffer{}

	// Handshake Layer Payload
	body := &bytes.Buffer{}

	// Version
	binary.Write(body, binary.BigEndian, ch.Version)

	// Random
	body.Write(ch.Random)

	// Session ID
	body.WriteByte(uint8(len(ch.SessionID)))
	body.Write(ch.SessionID)

	// Cipher Suites
	binary.Write(body, binary.BigEndian, uint16(len(ch.CipherSuites)*2))
	for _, cs := range ch.CipherSuites {
		binary.Write(body, binary.BigEndian, cs)
	}

	// Compression (null compression)
	body.WriteByte(1)
	body.WriteByte(0)

	// Extensions
	extBuf := &bytes.Buffer{}
	for extType, extData := range ch.Extensions {
		binary.Write(extBuf, binary.BigEndian, extType)
		binary.Write(extBuf, binary.BigEndian, uint16(len(extData)))
		extBuf.Write(extData)
	}

	if extBuf.Len() > 0 {
		binary.Write(body, binary.BigEndian, uint16(extBuf.Len()))
		body.Write(extBuf.Bytes())
	} else {
		binary.Write(body, binary.BigEndian, uint16(0))
	}

	handshakePayload := body.Bytes()

	// Handshake Header
	buf.WriteByte(0x01) // HandshakeType: ClientHello
	writeUint24(buf, len(handshakePayload))
	buf.Write(handshakePayload)

	handshakeRecord := buf.Bytes()

	// TLS Record Layer
	record := &bytes.Buffer{}
	record.WriteByte(0x16)           // ContentType: Handshake
	record.Write([]byte{0x03, 0x03}) // TLS version 1.2 (фиксируем пока для большинства DPI)
	binary.Write(record, binary.BigEndian, uint16(len(handshakeRecord)))
	record.Write(handshakeRecord)

	return record.Bytes(), nil
}

func writeUint24(buf *bytes.Buffer, val int) {
	buf.WriteByte(byte(val >> 16))
	buf.WriteByte(byte(val >> 8))
	buf.WriteByte(byte(val))
}
