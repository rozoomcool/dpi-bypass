package strategy

import (
	"log"

	"github.com/yourname/dpi-bypass/tlsparser"
)

func ApplyBasicObfuscation(ch *tlsparser.ClientHello) {
	log.Println("[Strategy] Applying basic DPI bypass: Remove SNI + Add Padding")

	// Удаляем SNI
	ch.RemoveSNI()

	// Добавляем Padding (например, 256 байт)
	ch.AddPadding(256)
}
