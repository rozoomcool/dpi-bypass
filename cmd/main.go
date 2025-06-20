package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"

	"github.com/rozoomcool/dpi-bypass/internal/strategy"
	"github.com/rozoomcool/dpi-bypass/internal/tlsparser"
)

func main() {
	listenAddr := ":8001"
	log.Printf("Starting DPI Bypass Proxy on %s", listenAddr)

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatal(err)
	}

	for {
		clientConn, err := ln.Accept()
		if err != nil {
			log.Println("Accept error:", err)
			continue
		}
		go handleConnection(clientConn)
	}
}

func handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	reader := bufio.NewReaderSize(clientConn, 32*1024)

	// Шаг 1 — читаем заголовок TLS Record (первые 5 байт)
	header := make([]byte, 5)
	_, err := io.ReadFull(reader, header)
	if err != nil {
		if err == io.EOF {
			log.Println("Client closed connection before sending any data")
		} else {
			log.Println("Failed to read TLS header:", err)
		}
		return
	}

	if header[0] != 0x16 {
		log.Println("Not a TLS Handshake record")
		forwardRaw(clientConn, reader, append([]byte{}, header...))
		return
	}

	recordLength := int(binary.BigEndian.Uint16(header[3:5]))

	if recordLength > 64*1024 {
		log.Println("TLS record too large, probably not ClientHello")
		forwardRaw(clientConn, reader, append([]byte{}, header...))
		return
	}

	// Шаг 2 — читаем остальную часть TLS Record
	body := make([]byte, recordLength)
	_, err = io.ReadFull(reader, body)
	if err != nil {
		log.Println("Failed to read TLS record body:", err)
		return
	}

	fullRecord := append(header, body...)

	// Шаг 3 — пробуем распарсить ClientHello
	ch, err := tlsparser.TryParseClientHello(fullRecord)
	if err != nil {
		log.Println("Not a TLS ClientHello, forwarding as-is")
		forwardRaw(clientConn, reader, fullRecord)
		return
	}

	log.Println("Intercepted ClientHello! SNI:", ch.ServerName)

	// Применяем обфускацию
	strategy.ApplyBasicObfuscation(ch)
	modifiedData, err := ch.Serialize()
	if err != nil {
		log.Println("Serialization failed:", err)
		return
	}

	// Подключаемся к целевому серверу
	targetConn, err := net.Dial("tcp", fmt.Sprintf("%s:443", ch.ServerName))
	if err != nil {
		log.Println("Connection to server failed:", err)
		return
	}
	defer targetConn.Close()

	// Отправляем модифицированный ClientHello
	_, err = targetConn.Write(modifiedData)
	if err != nil {
		log.Println("Write to server failed:", err)
		return
	}

	// Дальше обычный стриминг
	go io.Copy(targetConn, reader)
	io.Copy(clientConn, targetConn)
}

// Если это не TLS — пока закрываем соединение (расширим позже)
func forwardRaw(clientConn net.Conn, reader *bufio.Reader, firstData []byte) {
	log.Println("Non-TLS connection — dropped (for now)")
	clientConn.Close()
}
