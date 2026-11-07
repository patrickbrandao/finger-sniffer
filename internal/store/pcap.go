package store

import "encoding/binary"

// pcapHeader é o cabeçalho global libpcap com tempos em nanossegundos (magic 0xa1b23c4d), Ethernet.
func pcapHeader(snaplen uint32) []byte {
	h := make([]byte, 24)
	binary.LittleEndian.PutUint32(h[0:4], 0xa1b23c4d)
	binary.LittleEndian.PutUint16(h[4:6], 2)
	binary.LittleEndian.PutUint16(h[6:8], 4)
	binary.LittleEndian.PutUint32(h[16:20], snaplen)
	binary.LittleEndian.PutUint32(h[20:24], 1) // LINKTYPE_ETHERNET
	return h
}

// appendPcapRecord acrescenta um pacote ao pcap.
func appendPcapRecord(buf []byte, tsNs int64, wireLen int, frame []byte) []byte {
	var h [16]byte
	binary.LittleEndian.PutUint32(h[0:4], uint32(tsNs/1e9))          //nolint:gosec // segundos desde 1970 cabem em 32 bits até 2106
	binary.LittleEndian.PutUint32(h[4:8], uint32(tsNs%1e9))          //nolint:gosec // < 1e9
	binary.LittleEndian.PutUint32(h[8:12], uint32(len(frame)))       //nolint:gosec // frame < 64 KiB
	binary.LittleEndian.PutUint32(h[12:16], uint32(max(wireLen, 0))) //nolint:gosec // frame < 64 KiB
	return append(append(buf, h[:]...), frame...)
}
