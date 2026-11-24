//go:build linux

package web

// fionread é o SIOCINQ/FIONREAD do Linux (include/uapi/asm-generic/ioctls.h); o pacote syscall não o exporta.
const fionread = 0x541B
