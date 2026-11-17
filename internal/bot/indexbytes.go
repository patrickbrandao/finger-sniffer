package bot

import (
	"container/list"
	"sort"
	"unsafe"

	"github.com/patrickbrandao/finger-sniffer/pkg/h2passive"
)

// Contabilidade aproximada dos bytes do índice (spec 018 RF-02, ADR 0057 item 2). Cada entrada soma o custo fixo
// das estruturas que ela aloca (tamanhos por unsafe.Sizeof, arredondados à classe de tamanho do alocador do Go)
// mais o tamanho dos textos e fatias que guarda. Texto compartilhado pelo interner conta uma vez por geração: na
// entrada que o criou (ver interner). Erro aceito: ±25% contra o heap medido (BenchmarkIndexFullMemory).

// sizeClasses são as classes de tamanho do alocador do Go até 32 KiB (runtime/sizeclasses.go); acima disso a
// alocação é arredondada à página de 8 KiB.
var sizeClasses = []int{
	8, 16, 24, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240, 256, 288, 320, 352, 384, 416, 448,
	480, 512, 576, 640, 704, 768, 896, 1024, 1152, 1280, 1408, 1536, 1792, 2048, 2304, 2688, 3072, 3200, 3456, 4096,
	4864, 5376, 6144, 6528, 6784, 6912, 8192, 9472, 9728, 10240, 10880, 12288, 13568, 14336, 16384, 18432, 19072,
	20480, 21760, 24576, 27264, 28672, 32768,
}

// allocBytes é quanto o alocador reserva para n bytes.
func allocBytes[T ~int | ~uintptr](v T) int64 {
	n := int(v)
	if n <= 0 {
		return 0
	}
	if n > 32768 {
		return int64((n + 8191) &^ 8191)
	}
	return int64(sizeClasses[sort.SearchInts(sizeClasses, n)])
}

// strBytes é o custo de um texto alocado à parte: abaixo de 16 bytes ele vai para o alocador "tiny", que junta
// vários num bloco (conta o próprio tamanho).
func strBytes(n int) int64 {
	if n < 16 {
		return int64(n)
	}
	return allocBytes(n)
}

// mapHeaderBytes é o cabeçalho de um mapa (internal/runtime/maps.Map, 48 bytes no amd64 e no arm64).
const mapHeaderBytes = 48

// mapSlotBytes é o custo médio de uma entrada num mapa grande: a casa (chave + valor) e o byte de controle,
// divididos pela ocupação média das tabelas swiss (até 7/8, metade depois de crescer: ≈ 2/3, medido no
// BenchmarkIndexFullMemory).
func mapSlotBytes(slot uintptr) int64 { return int64(slot+1) * 3 / 2 } //nolint:gosec // tamanhos de struct, pequenos

// mapBytes é o custo de um mapa pequeno com k entradas de casas de slot bytes (os mapas de campos do fork): até 8
// entradas, um grupo só; acima, a tabela com capacidade em potência de 2 e ocupação máxima de 7/8.
func mapBytes(k int, slot uintptr) int64 {
	if k == 0 {
		return 0
	}
	group := func(groups int) int64 { return allocBytes(uintptr(groups) * (8 + 8*slot)) }
	if k <= 8 {
		return allocBytes(mapHeaderBytes) + group(1)
	}
	slots := 8
	for slots*7/8 < k {
		slots *= 2
	}
	return allocBytes(mapHeaderBytes) + allocBytes(48) + allocBytes(8) + group(slots/8) // tabela e diretório
}

// Custos fixos por estrutura (unsafe.Sizeof, arredondado à classe do alocador).
var (
	strHeader = unsafe.Sizeof("")
	ptrSize   = unsafe.Sizeof(uintptr(0))
	// entrada de uma tabela: elemento da lista, ttlEntry e as casas em byID (string → ponteiro) e bySrc.
	tableEntryBytes = allocBytes(unsafe.Sizeof(list.Element{})) + mapSlotBytes(strHeader+ptrSize) +
		mapSlotBytes(unsafe.Sizeof(srcKey{})+ptrSize)
	storeEntryBytes = tableEntryBytes + allocBytes(unsafe.Sizeof(ttlEntry[*StoreConn]{})) + allocBytes(unsafe.Sizeof(StoreConn{}))
	forkEntryBytes  = tableEntryBytes + allocBytes(unsafe.Sizeof(ttlEntry[*ForkConn]{})) + allocBytes(unsafe.Sizeof(ForkConn{}))
	// probeLinkBytes: casa do conn_id no conjunto do probe (byProbe) e a parte do conjunto.
	probeLinkBytes = mapSlotBytes(strHeader) + 32
	reqItemBytes   = allocBytes(unsafe.Sizeof(reqItem{}))
	forkTLSBytes   = allocBytes(unsafe.Sizeof(ForkTLS{}))
	forkH2Bytes    = allocBytes(unsafe.Sizeof(ForkH2{}))
	forkReqSize    = unsafe.Sizeof(ForkRequest{})
	priorityBytes  = unsafe.Sizeof(h2passive.Priority{})
	fieldSlot      = 2 * strHeader // map[string]string
	// indexEmptyBytes é o índice vazio: a estrutura, as duas tabelas (lista e dois mapas cada), byProbe e o canal.
	indexEmptyBytes = allocBytes(unsafe.Sizeof(Index{})) +
		allocBytes(unsafe.Sizeof(ttlTable[*StoreConn]{})) + allocBytes(unsafe.Sizeof(ttlTable[*ForkConn]{})) +
		2*allocBytes(unsafe.Sizeof(list.List{})) + 5*allocBytes(mapHeaderBytes) + allocBytes(96)
)

// listBytes é o custo de uma lista de textos (só o vetor; os textos contam à parte).
func listBytes(n int) int64 { return allocBytes(uintptr(n) * strHeader) }

// storeBytes é o custo de uma conexão do store no índice; os resumos de requisição compartilhados contam em
// reqCharge (só na conexão que os criou).
func storeBytes(c *StoreConn) int64 {
	n := storeEntryBytes + strBytes(len(c.ConnID)) + strBytes(len(c.ProbeID)) + strBytes(len(c.Stage)) +
		strBytes(len(c.L4)) + strBytes(len(c.Proto)) + allocBytes(cap(c.Record)) +
		allocBytes(uintptr(cap(c.Requests))*ptrSize) + c.reqCharge
	if c.ProbeID != "" {
		n += probeLinkBytes
	}
	return n
}

// forkBytes é o custo de uma conexão do fork no índice: a estrutura, o vetor de requisições e o que cada parte
// (registro de conexão, TLS, h2, requisições) somou ao ser montada.
func forkBytes(c *ForkConn) int64 {
	// LastClass é uma das constantes de classe (sem alocação); o JSON do veredito conta pela capacidade.
	n := forkEntryBytes + strBytes(len(c.FsConnID)) + c.connCost + allocBytes(uintptr(len(c.Requests))*forkReqSize) +
		allocBytes(cap(c.LastVerdict))
	if c.TLS != nil {
		n += c.TLS.cost
	}
	if c.H2 != nil {
		n += c.H2.cost
	}
	for i := range c.Requests {
		n += c.Requests[i].cost
	}
	return n
}
