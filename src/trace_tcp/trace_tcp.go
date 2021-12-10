package main

import "C"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"strconv"

	"golang.org/x/sys/unix"

	bpf "github.com/aquasecurity/tracee/libbpfgo"
)

type Event struct {
	PID   uint32
	TID   uint32
	SAddr uint32
	DAddr uint32
	Sport uint16
	Dport uint16
	Comm  [80]byte
}

func Uint2IP4(ipInt uint32) string {
	b0 := strconv.FormatInt((int64)(ipInt>>24)&0xff, 10)
	b1 := strconv.FormatInt((int64)(ipInt>>16)&0xff, 10)
	b2 := strconv.FormatInt((int64)(ipInt>>8)&0xff, 10)
	b3 := strconv.FormatInt((int64)(ipInt&0xff), 10)
	return b3 + "." + b2 + "." + b1 + "." + b0
}

func main() {

	bpfModule, err := bpf.NewModuleFromFile("trace_tcp_bpf.o")
	if err != nil {
		os.Exit(-1)
	}
	defer bpfModule.Close()

	bpfModule.BPFLoadObject()
	prog, err := bpfModule.GetProgram("kprobe__tcp_sendmsg")
	if err != nil {
		os.Exit(-1)
	}

	_, err = prog.AttachKprobe("tcp_sendmsg")
	if err != nil {
		os.Exit(-1)
	}

	eventsChannel := make(chan []byte)
	rb, err := bpfModule.InitRingBuf("events", eventsChannel)
	if err != nil {
		os.Exit(-1)
	}

	rb.Start()

	for {
		record := <-eventsChannel
		var event Event
		if err := binary.Read(bytes.NewBuffer(record), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing ringbuf event: %s", err)
			continue
		}

		comment := unix.ByteSliceToString(event.Comm[:])

		fmt.Printf("PID: %d\tTID: %d\tComm: %s\t Edge: %s:%d->%s:%d\n",
			event.PID, event.TID, comment,
			Uint2IP4(event.SAddr), event.Sport, Uint2IP4(event.DAddr), event.Dport)
	}

	rb.Stop()
	rb.Close()
}
