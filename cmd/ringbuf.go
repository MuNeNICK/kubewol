package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"

	bpf "github.com/munenick/kubewol/internal/ebpf"
)

type ringbufReader struct {
	rd *ringbuf.Reader
}

type synEventLog struct {
	SrcAddr string
	SrcPort uint16
	DstAddr string
	DstPort uint16
}

func newRingbufReader(m *ebpf.Map) (*ringbufReader, error) {
	rd, err := ringbuf.NewReader(m)
	if err != nil {
		return nil, fmt.Errorf("ringbuf: %w", err)
	}
	return &ringbufReader{rd: rd}, nil
}

func (r *ringbufReader) ReadEvent() (synEventLog, error) {
	record, err := r.rd.Read()
	if err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return synEventLog{}, err
		}
		return synEventLog{}, err
	}
	if len(record.RawSample) < int(unsafe.Sizeof(bpf.SynEvent{})) {
		return synEventLog{}, fmt.Errorf("short sample")
	}
	var evt bpf.SynEvent
	if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &evt); err != nil {
		return synEventLog{}, err
	}
	return synEventLog{
		SrcAddr: bpf.Uint32ToIP(evt.SrcAddr).String(),
		SrcPort: bpf.Ntohs(evt.SrcPort),
		DstAddr: bpf.Uint32ToIP(evt.DstAddr).String(),
		DstPort: bpf.Ntohs(evt.DstPort),
	}, nil
}

func (r *ringbufReader) Close() { _ = r.rd.Close() }
