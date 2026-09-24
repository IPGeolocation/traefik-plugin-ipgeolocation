// Package ipgeolocation implements a Traefik middleware that enriches and
// filters HTTP traffic using IPGeolocation.io data.
//
// This file contains a self-contained reader for the MaxMind DB (MMDB) binary
// format. It exists because Traefik plugins are executed by the Yaegi
// interpreter, which cannot run the reflection- and mmap-heavy official
// readers, and because plugin dependencies must be vendored. Everything here
// uses only the Go standard library.
//
// Format reference: MaxMind DB File Format Specification v2.0.
package ipgeolocation

import (
	"encoding/binary"
	"fmt"
	"math"
	"os"
)

// MMDB data section type markers.
const (
	typePointer   = 1
	typeString    = 2
	typeDouble    = 3
	typeBytes     = 4
	typeUint16    = 5
	typeUint32    = 6
	typeMap       = 7
	typeInt32     = 8
	typeUint64    = 9
	typeUint128   = 10
	typeArray     = 11
	typeContainer = 12
	typeEndMarker = 13
	typeBool      = 14
	typeFloat     = 15
)

const (
	// maxDecodeDepth guards against malformed or hostile files that contain
	// pointer loops or absurd nesting.
	maxDecodeDepth = 64
	// maxValueSize caps a single string/bytes value at 32 MiB.
	maxValueSize = 32 << 20
)

// source abstracts "give me n bytes at offset". It has two implementations:
// an in-memory byte slice and a file handle that keeps only the search tree
// resident. Both avoid mmap and unsafe, which Yaegi does not allow.
type source interface {
	at(off int64, n int) ([]byte, error)
	size() int64
	close() error
}

// memSource keeps the whole database in RAM. Fastest, but needs as much
// memory as the file is large.
type memSource struct {
	b []byte
}

func newMemSource(path string) (*memSource, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return &memSource{b: b}, nil
}

func (m *memSource) at(off int64, n int) ([]byte, error) {
	if off < 0 || n < 0 || off+int64(n) > int64(len(m.b)) {
		return nil, fmt.Errorf("read of %d bytes at offset %d is out of range (size %d)", n, off, len(m.b))
	}
	return m.b[off : off+int64(n)], nil
}

func (m *memSource) size() int64 { return int64(len(m.b)) }

func (m *memSource) close() error {
	m.b = nil
	return nil
}

// fileSource keeps the search tree in memory (that is what every lookup walks)
// and reads data records from disk on demand. Use it for multi-gigabyte
// databases where loading the whole file is not an option. The operating
// system page cache absorbs most of the cost of the small reads.
type fileSource struct {
	f       *os.File
	head    []byte // search tree + separator, resident
	headLen int64
	total   int64
}

func newFileSource(path string) (*fileSource, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return &fileSource{f: f, total: st.Size()}, nil
}

// loadHead pins the first n bytes (the search tree) in memory.
func (s *fileSource) loadHead(n int64) error {
	if n < 0 || n > s.total {
		return fmt.Errorf("invalid search tree size %d for file of %d bytes", n, s.total)
	}
	buf := make([]byte, n)
	if _, err := s.f.ReadAt(buf, 0); err != nil {
		return err
	}
	s.head = buf
	s.headLen = n
	return nil
}

func (s *fileSource) at(off int64, n int) ([]byte, error) {
	if off < 0 || n < 0 || off+int64(n) > s.total {
		return nil, fmt.Errorf("read of %d bytes at offset %d is out of range (size %d)", n, off, s.total)
	}
	if s.head != nil && off+int64(n) <= s.headLen {
		return s.head[off : off+int64(n)], nil
	}
	buf := make([]byte, n)
	if _, err := s.f.ReadAt(buf, off); err != nil {
		return nil, err
	}
	return buf, nil
}

func (s *fileSource) size() int64 { return s.total }

func (s *fileSource) close() error {
	s.head = nil
	return s.f.Close()
}

// windowSource serves reads from a block that was fetched in one call and
// falls back to the underlying source for anything outside it.
//
// Decoding or seeking a record touches many small, mostly contiguous pieces
// of the data section. Against a file that means hundreds of one byte reads,
// each a syscall. Reading one window up front turns them into a single read,
// which is what makes the file backed mode usable for the multi-gigabyte
// databases. Pointers can still jump outside the window; those fall through.
type windowSource struct {
	base     int64
	buf      []byte
	fallback source
}

func (w *windowSource) at(off int64, n int) ([]byte, error) {
	start := off - w.base
	if start >= 0 && n >= 0 && start+int64(n) <= int64(len(w.buf)) {
		return w.buf[start : start+int64(n)], nil
	}
	return w.fallback.at(off, n)
}

func (w *windowSource) size() int64 { return w.fallback.size() }

func (w *windowSource) close() error { return nil }

// decoder decodes MMDB values. base is the offset of the section that
// pointers are relative to: the start of the data section for record data,
// the start of the metadata block for metadata.
type decoder struct {
	src  source
	base int64
}

// decode reads one value at off and returns it together with the offset of
// the next value.
func (d *decoder) decode(off int64, depth int) (interface{}, int64, error) {
	if depth > maxDecodeDepth {
		return nil, 0, fmt.Errorf("maximum decode depth %d exceeded at offset %d", maxDecodeDepth, off)
	}

	ctrlBuf, err := d.src.at(off, 1)
	if err != nil {
		return nil, 0, err
	}
	ctrl := ctrlBuf[0]
	off++

	valueType := int(ctrl >> 5)

	if valueType == typePointer {
		target, next, err := d.decodePointer(ctrl, off)
		if err != nil {
			return nil, 0, err
		}
		value, _, err := d.decode(target, depth+1)
		if err != nil {
			return nil, 0, err
		}
		return value, next, nil
	}

	if valueType == 0 {
		extBuf, err := d.src.at(off, 1)
		if err != nil {
			return nil, 0, err
		}
		valueType = int(extBuf[0]) + 7
		off++
	}

	size := int(ctrl & 0x1f)
	size, off, err = d.decodeSize(size, off)
	if err != nil {
		return nil, 0, err
	}

	switch valueType {
	case typeString:
		if size > maxValueSize {
			return nil, 0, fmt.Errorf("string of %d bytes exceeds the limit", size)
		}
		b, err := d.src.at(off, size)
		if err != nil {
			return nil, 0, err
		}
		return string(b), off + int64(size), nil

	case typeBytes:
		if size > maxValueSize {
			return nil, 0, fmt.Errorf("byte field of %d bytes exceeds the limit", size)
		}
		b, err := d.src.at(off, size)
		if err != nil {
			return nil, 0, err
		}
		out := make([]byte, size)
		copy(out, b)
		return out, off + int64(size), nil

	case typeDouble:
		if size != 8 {
			return nil, 0, fmt.Errorf("double must be 8 bytes, got %d", size)
		}
		b, err := d.src.at(off, 8)
		if err != nil {
			return nil, 0, err
		}
		return math.Float64frombits(binary.BigEndian.Uint64(b)), off + 8, nil

	case typeFloat:
		if size != 4 {
			return nil, 0, fmt.Errorf("float must be 4 bytes, got %d", size)
		}
		b, err := d.src.at(off, 4)
		if err != nil {
			return nil, 0, err
		}
		return float64(math.Float32frombits(binary.BigEndian.Uint32(b))), off + 4, nil

	case typeUint16, typeUint32, typeUint64:
		v, err := d.readUint(off, size)
		if err != nil {
			return nil, 0, err
		}
		return v, off + int64(size), nil

	case typeInt32:
		v, err := d.readUint(off, size)
		if err != nil {
			return nil, 0, err
		}
		return int64(int32(v)), off + int64(size), nil

	case typeUint128:
		b, err := d.src.at(off, size)
		if err != nil {
			return nil, 0, err
		}
		out := make([]byte, size)
		copy(out, b)
		return out, off + int64(size), nil

	case typeBool:
		return size != 0, off, nil

	case typeMap:
		out := make(map[string]interface{}, size)
		cur := off
		for i := 0; i < size; i++ {
			rawKey, next, err := d.decode(cur, depth+1)
			if err != nil {
				return nil, 0, err
			}
			key, ok := rawKey.(string)
			if !ok {
				return nil, 0, fmt.Errorf("map key at offset %d is not a string", cur)
			}
			value, next2, err := d.decode(next, depth+1)
			if err != nil {
				return nil, 0, err
			}
			out[key] = value
			cur = next2
		}
		return out, cur, nil

	case typeArray:
		out := make([]interface{}, 0, size)
		cur := off
		for i := 0; i < size; i++ {
			value, next, err := d.decode(cur, depth+1)
			if err != nil {
				return nil, 0, err
			}
			out = append(out, value)
			cur = next
		}
		return out, cur, nil

	case typeContainer, typeEndMarker:
		return nil, off, nil
	}

	return nil, 0, fmt.Errorf("unknown MMDB type %d at offset %d", valueType, off)
}

// decodeSize expands the 5-bit size field of the control byte.
func (d *decoder) decodeSize(size int, off int64) (int, int64, error) {
	switch {
	case size < 29:
		return size, off, nil
	case size == 29:
		b, err := d.src.at(off, 1)
		if err != nil {
			return 0, 0, err
		}
		return 29 + int(b[0]), off + 1, nil
	case size == 30:
		b, err := d.src.at(off, 2)
		if err != nil {
			return 0, 0, err
		}
		return 285 + int(binary.BigEndian.Uint16(b)), off + 2, nil
	default:
		b, err := d.src.at(off, 3)
		if err != nil {
			return 0, 0, err
		}
		return 65821 + (int(b[0])<<16 | int(b[1])<<8 | int(b[2])), off + 3, nil
	}
}

// decodePointer returns the absolute offset the pointer refers to and the
// offset immediately after the pointer.
func (d *decoder) decodePointer(ctrl byte, off int64) (int64, int64, error) {
	pointerSize := int((ctrl>>3)&0x3) + 1
	b, err := d.src.at(off, pointerSize)
	if err != nil {
		return 0, 0, err
	}
	prefix := int64(ctrl & 0x7)

	var pointer int64
	switch pointerSize {
	case 1:
		pointer = prefix<<8 | int64(b[0])
	case 2:
		pointer = prefix<<16 | int64(b[0])<<8 | int64(b[1])
		pointer += 2048
	case 3:
		pointer = prefix<<24 | int64(b[0])<<16 | int64(b[1])<<8 | int64(b[2])
		pointer += 526336
	default:
		pointer = int64(binary.BigEndian.Uint32(b))
	}
	return d.base + pointer, off + int64(pointerSize), nil
}

func (d *decoder) readUint(off int64, size int) (uint64, error) {
	if size > 8 {
		return 0, fmt.Errorf("unsigned integer of %d bytes is too large", size)
	}
	if size == 0 {
		return 0, nil
	}
	b, err := d.src.at(off, size)
	if err != nil {
		return 0, err
	}
	var v uint64
	for i := 0; i < size; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, nil
}

// ---------------------------------------------------------------------------
// Targeted access
// ---------------------------------------------------------------------------
//
// Decoding a whole record to read two fields is wasteful: an IPGeolocation.io
// location record carries a dozen localized name maps, and materializing them
// all costs hundreds of allocations per request. seek walks the encoded bytes
// to the value at a path and skips everything else, so only the subtree that
// is actually used gets decoded.

// seek returns the offset of the value at path, relative to the record at off.
func (d *decoder) seek(off int64, path []string, depth int) (int64, bool, error) {
	if depth > maxDecodeDepth {
		return 0, false, fmt.Errorf("maximum depth %d exceeded while seeking", maxDecodeDepth)
	}
	if len(path) == 0 {
		return off, true, nil
	}

	ctrlBuf, err := d.src.at(off, 1)
	if err != nil {
		return 0, false, err
	}
	ctrl := ctrlBuf[0]
	off++
	valueType := int(ctrl >> 5)

	if valueType == typePointer {
		target, _, err := d.decodePointer(ctrl, off)
		if err != nil {
			return 0, false, err
		}
		return d.seek(target, path, depth+1)
	}

	if valueType == 0 {
		extBuf, err := d.src.at(off, 1)
		if err != nil {
			return 0, false, err
		}
		valueType = int(extBuf[0]) + 7
		off++
	}

	size, off, err := d.decodeSize(int(ctrl&0x1f), off)
	if err != nil {
		return 0, false, err
	}
	if valueType != typeMap {
		// The path continues but this value is not a map.
		return 0, false, nil
	}

	cur := off
	for i := 0; i < size; i++ {
		rawKey, next, err := d.decode(cur, depth+1)
		if err != nil {
			return 0, false, err
		}
		key, ok := rawKey.(string)
		if !ok {
			return 0, false, fmt.Errorf("map key at offset %d is not a string", cur)
		}
		if key == path[0] {
			return d.seek(next, path[1:], depth+1)
		}
		cur, err = d.skip(next, depth+1)
		if err != nil {
			return 0, false, err
		}
	}

	return 0, false, nil
}

// skip returns the offset just past the value at off without decoding it.
func (d *decoder) skip(off int64, depth int) (int64, error) {
	if depth > maxDecodeDepth {
		return 0, fmt.Errorf("maximum depth %d exceeded while skipping", maxDecodeDepth)
	}

	ctrlBuf, err := d.src.at(off, 1)
	if err != nil {
		return 0, err
	}
	ctrl := ctrlBuf[0]
	off++
	valueType := int(ctrl >> 5)

	if valueType == typePointer {
		// A pointer is a fixed number of bytes; there is no need to follow it.
		return off + int64((ctrl>>3)&0x3) + 1, nil
	}

	if valueType == 0 {
		extBuf, err := d.src.at(off, 1)
		if err != nil {
			return 0, err
		}
		valueType = int(extBuf[0]) + 7
		off++
	}

	size, off, err := d.decodeSize(int(ctrl&0x1f), off)
	if err != nil {
		return 0, err
	}

	switch valueType {
	case typeMap:
		cur := off
		for i := 0; i < size; i++ {
			if cur, err = d.skip(cur, depth+1); err != nil {
				return 0, err
			}
			if cur, err = d.skip(cur, depth+1); err != nil {
				return 0, err
			}
		}
		return cur, nil

	case typeArray:
		cur := off
		for i := 0; i < size; i++ {
			if cur, err = d.skip(cur, depth+1); err != nil {
				return 0, err
			}
		}
		return cur, nil

	case typeBool, typeContainer, typeEndMarker:
		return off, nil

	default:
		return off + int64(size), nil
	}
}
