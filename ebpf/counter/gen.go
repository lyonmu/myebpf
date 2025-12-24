package counter

//go:generate go tool bpf2go -tags linux -go-package counter Counter counter.c
