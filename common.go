package main

import "log"

const (
	PromNamespace = "opnsense"
	LoggerFlags   = log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile | log.Lmsgprefix
)

func WrapUint64(ui uint64) float64 {
	return float64(ui & ((1 << 53) - 1))
}
