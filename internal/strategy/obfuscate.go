package strategy

import (
	"log"

	"github.com/rozoomcool/dpi-bypass/internal/tlsparser"
)

func ApplyBasicObfuscation(ch *tlsparser.ClientHello) {
	log.Println("[Strategy] Applying DPI bypass: Remove SNI + Add Padding")

	// Удаляем SNI extension
	ch.RemoveSNI()

	// Добавляем Padding (например, 256 байт)
	ch.AddPadding(256)
}
