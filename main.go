package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// FlowEvent 对应 eBPF 中的 flow_event 结构体
type FlowEvent struct {
	SrcIP    uint32
	DstIP    uint32
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
	Pad      [3]byte
}

// uint32 转 net.IP
func intToIP(i uint32) net.IP {
	return net.IPv4(byte(i), byte(i>>8), byte(i>>16), byte(i>>24))
}

// 网络字节序转主机字节序
func ntohs(n uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], n)
	return binary.LittleEndian.Uint16(b[:])
}

func main() {
	ifaceName := flag.String("interface", "", "Network interface to attach to")
	flag.Parse()

	if *ifaceName == "" {
		fmt.Println("Usage: sudo ./myebpf -interface <interface_name>")
		os.Exit(1)
	}

	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs flowObjects
	if err := loadFlowObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	// Open Ring Buffer for reading flow events.
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatal("Creating ringbuf reader:", err)
	}
	defer rd.Close()

	// Attach XDP program to network interface.
	iface, err := net.InterfaceByName(*ifaceName)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", *ifaceName, err)
	}

	link, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.ProcessPacket,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatal("Attaching XDP:", err)
	}
	defer link.Close()

	log.Printf("Listening for flow events on %s...", iface.Name)

	// Signal handling for graceful shutdown.
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	// Event processing loop.
	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					return
				}
				log.Printf("Reading from ringbuf: %v", err)
				continue
			}

			var event FlowEvent
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("Parsing event: %v", err)
				continue
			}

			protocol := "UNK"
			if event.Protocol == 6 {
				protocol = "TCP"
			} else if event.Protocol == 17 {
				protocol = "UDP"
			}

			fmt.Printf("%s %s:%d -> %s:%d\n",
				protocol,
				intToIP(event.SrcIP), ntohs(event.SrcPort),
				intToIP(event.DstIP), ntohs(event.DstPort))
		}
	}()

	<-stop
	log.Println("Exiting...")
}
