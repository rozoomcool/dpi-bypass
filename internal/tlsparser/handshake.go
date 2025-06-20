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
