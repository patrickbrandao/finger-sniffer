//go:build darwin

package web

// fionread é o FIONREAD do macOS (_IOR('f', 127, int), sys/filio.h), só para o ambiente de desenvolvimento.
const fionread = 0x4004667F
