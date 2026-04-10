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

func newRingbufReader(m *ebpf.Map) (*ringbufReader, error) {
	rd, err := ringbuf.NewReader(m)
	if err != nil {
		return nil, fmt.Errorf("ringbuf: %w", err)
	}
	return &ringbufReader{rd: rd}, nil
}

// ReadEvent returns the raw BPF SYN event (fields in network byte order).
func (r *ringbufReader) ReadEvent() (bpf.SynEvent, error) {
	record, err := r.rd.Read()
	if err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return bpf.SynEvent{}, err
		}
		return bpf.SynEvent{}, err
	}
	if len(record.RawSample) < int(unsafe.Sizeof(bpf.SynEvent{})) {
		return bpf.SynEvent{}, fmt.Errorf("short sample")
	}
	var evt bpf.SynEvent
	if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &evt); err != nil {
		return bpf.SynEvent{}, err
	}
	return evt, nil
}

func (r *ringbufReader) Close() { _ = r.rd.Close() }
