package proxy

import (
	"errors"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/rozoomcool/dpi-bypass/internal/strategy"
	"github.com/rozoomcool/dpi-bypass/internal/tlsparser"
	"github.com/songgao/water"
)

type ConnectionKey struct {
	SrcIP, DstIP     string
	SrcPort, DstPort uint16
}

type TCPConnection struct {
	Key           ConnectionKey
	Buffer        []byte
	NextSeq       uint32
	Modified      bool
	EstablishedAt time.Time
}

var connections = make(map[ConnectionKey]*TCPConnection)

func Start(dev *water.Interface) {
	buf := make([]byte, 65535)

	for {
		n, err := dev.Read(buf)
		if err != nil {
			log.Fatal(err)
		}

		packet := gopacket.NewPacket(buf[:n], layers.LayerTypeIPv4, gopacket.Default)
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			continue
		}
		ip, _ := ipLayer.(*layers.IPv4)

		if ip.Protocol != layers.IPProtocolTCP {
			continue
		}

		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue
		}
		tcp, _ := tcpLayer.(*layers.TCP)

		key := ConnectionKey{
			SrcIP:   ip.SrcIP.String(),
			DstIP:   ip.DstIP.String(),
			SrcPort: uint16(tcp.SrcPort),
			DstPort: uint16(tcp.DstPort),
		}

		conn, exists := connections[key]
		if !exists {
			conn = &TCPConnection{
				Key:           key,
				Buffer:        []byte{},
				NextSeq:       uint32(tcp.Seq) + uint32(len(tcp.Payload)),
				Modified:      false,
				EstablishedAt: time.Now(),
			}
			connections[key] = conn
		} else {
			if uint32(tcp.Seq) != conn.NextSeq {
				log.Printf("Out of order packet: got %d expected %d", tcp.Seq, conn.NextSeq)
				continue
			}
			conn.NextSeq += uint32(len(tcp.Payload))
		}

		// Пропускаем служебные пакеты (SYN, FIN, RST)
		if tcp.SYN || tcp.FIN || tcp.RST {
			dev.Write(buf[:n])
			continue
		}

		if len(tcp.Payload) == 0 {
			dev.Write(buf[:n])
			continue
		}

		// Добавляем в stream
		conn.Buffer = append(conn.Buffer, tcp.Payload...)

		// Пробуем парсить ClientHello
		if !conn.Modified {
			ch, err := tryParseTLSClientHello(conn.Buffer)
			if err == nil {
				log.Println("Intercepted ClientHello! SNI:", ch.ServerName)
				strategy.ApplyBasicObfuscation(ch)

				modifiedData, err := ch.Serialize()
				if err == nil {
					conn.Buffer = modifiedData
					conn.Modified = true
					log.Println("ClientHello modified!")
				}
			}
		}

		// Отправляем модифицированный пакет
		err = InjectModifiedPacket(dev, ip, tcp, conn.Buffer)
		if err != nil {
			log.Println("Injection failed:", err)
		}
	}
}

func tryParseTLSClientHello(data []byte) (*tlsparser.ClientHello, error) {
	if len(data) < 5 {
		return nil, errors.New("not enough data")
	}
	if data[0] != 0x16 || data[5] != 0x01 {
		return nil, errors.New("not TLS ClientHello")
	}
	return tlsparser.TryParseClientHello(data)
}
