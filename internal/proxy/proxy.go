package proxy

import (
	"io"
	"log"
	"net"
	"time"

	"github.com/rozoomcool/dpi-bypass/internal/strategy"
	"github.com/rozoomcool/dpi-bypass/internal/tlsparser"
)

func Start(listenAddr string) error {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}
	log.Printf("Listening on %s\n", listenAddr)

	for {
		client, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go handle(client)
	}
}

func handle(client net.Conn) {
	defer client.Close()

	client.SetReadDeadline(time.Now().Add(10 * time.Second))

	buf := make([]byte, 8192)
	n, err := client.Read(buf)
	if err != nil {
		log.Println("Error reading ClientHello:", err)
		return
	}

	ch, err := tlsparser.ParseClientHello(buf[:n])
	if err != nil {
		log.Println("Failed parsing TLS:", err)
		return
	}

	log.Printf("Intercepted TLS for host: %s", ch.ServerName)

	// Применяем стратегию обхода
	strategy.ApplyBasicObfuscation(ch)

	modifiedData, err := ch.Serialize()
	if err != nil {
		log.Println("Failed serialize:", err)
		return
	}

	// Подключаемся к оригинальному хосту
	remote, err := net.Dial("tcp", ch.ServerName+":443")
	if err != nil {
		log.Println("Remote connect failed:", err)
		return
	}
	defer remote.Close()

	remote.Write(modifiedData)

	// Дальше двунаправленный стриминг
	go io.Copy(remote, client)
	io.Copy(client, remote)
}
