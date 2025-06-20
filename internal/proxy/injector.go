package proxy

import (
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/songgao/water"
)

func InjectModifiedPacket(dev *water.Interface, ip *layers.IPv4, tcp *layers.TCP, modifiedPayload []byte) error {
	// Создаем новые слои

	ipNew := *ip // копируем IP заголовок
	ipNew.Length = uint16(20 + int(tcp.DataOffset)*4 + len(modifiedPayload))

	tcpNew := *tcp // копируем TCP заголовок
	tcpNew.Payload = modifiedPayload

	// Пересчитываем TCP checksum (важнейший момент)
	err := tcpNew.SetNetworkLayerForChecksum(&ipNew)
	if err != nil {
		return err
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err = gopacket.SerializeLayers(buf, opts, &ipNew, &tcpNew)
	if err != nil {
		return err
	}

	outPacket := buf.Bytes()

	// Записываем модифицированный пакет обратно в TUN интерфейс (система сама отправит в интернет)
	n, err := dev.Write(outPacket)
	if err != nil {
		return err
	}
	log.Printf("Injected modified packet (%d bytes)", n)
	return nil
}
