package ipgeolocation

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"sort"
	"testing"
)

// This file builds MMDB files byte by byte so the reader can be tested
// against the real binary format instead of a mock.

type dbEntry struct {
	network string
	data    map[string]interface{}
}

type record struct {
	kind  int // 0 empty, 1 node, 2 data
	value uint32
}

type treeNode struct {
	records [2]record
}

// buildMMDB returns a complete MMDB file for the given entries.
func buildMMDB(t *testing.T, recordSize, ipVersion int, databaseType string, entries []dbEntry) []byte {
	t.Helper()

	// 1. Encode the data section and remember each entry's offset.
	var data bytes.Buffer
	offsets := make([]uint32, len(entries))
	for i, entry := range entries {
		offsets[i] = uint32(data.Len())
		encodeValue(t, &data, entry.data)
	}

	// 2. Build the search tree.
	nodes := []treeNode{{}}
	for i, entry := range entries {
		insertNetwork(t, &nodes, entry.network, ipVersion, offsets[i])
	}
	nodeCount := uint32(len(nodes))

	// 3. Serialize the tree.
	var tree bytes.Buffer
	for _, node := range nodes {
		left := resolveRecord(node.records[0], nodeCount)
		right := resolveRecord(node.records[1], nodeCount)
		writeNode(t, &tree, recordSize, left, right)
	}

	// 4. Assemble: tree, 16 byte separator, data section, marker, metadata.
	var out bytes.Buffer
	out.Write(tree.Bytes())
	out.Write(make([]byte, 16))
	out.Write(data.Bytes())
	out.Write(metadataMarker)

	metadata := map[string]interface{}{
		"node_count":                  uint32Value(nodeCount),
		"record_size":                 uint16Value(uint16(recordSize)),
		"ip_version":                  uint16Value(uint16(ipVersion)),
		"database_type":               databaseType,
		"languages":                   []interface{}{"en"},
		"binary_format_major_version": uint16Value(2),
		"binary_format_minor_version": uint16Value(0),
		"build_epoch":                 uint64Value(1750000000),
		"description":                 map[string]interface{}{"en": "test fixture"},
	}
	encodeValue(t, &out, metadata)

	return out.Bytes()
}

// Typed wrappers so the encoder emits the exact MMDB integer types.
type uint16Value uint16
type uint32Value uint32
type uint64Value uint64
type int32Value int32

func resolveRecord(r record, nodeCount uint32) uint32 {
	switch r.kind {
	case 1:
		return r.value
	case 2:
		return nodeCount + 16 + r.value
	default:
		return nodeCount
	}
}

func insertNetwork(t *testing.T, nodes *[]treeNode, cidr string, ipVersion int, dataOffset uint32) {
	t.Helper()

	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("invalid fixture network %q: %v", cidr, err)
	}
	ones, _ := network.Mask.Size()

	var bits []byte
	if v4 := ip.To4(); v4 != nil {
		if ipVersion == 6 {
			// IPv4 lives under ::/96 in an IPv6 database.
			bits = append(bits, make([]byte, 12)...)
			bits = append(bits, v4...)
			ones += 96
		} else {
			bits = v4
		}
	} else {
		if ipVersion == 4 {
			t.Fatalf("cannot insert IPv6 network %q into an IPv4 database", cidr)
		}
		bits = ip.To16()
	}

	current := 0
	for i := 0; i < ones; i++ {
		bit := (bits[i>>3] >> (7 - uint(i&7))) & 1
		if i == ones-1 {
			(*nodes)[current].records[bit] = record{kind: 2, value: dataOffset}
			return
		}
		existing := (*nodes)[current].records[bit]
		if existing.kind != 1 {
			*nodes = append(*nodes, treeNode{})
			next := uint32(len(*nodes) - 1)
			(*nodes)[current].records[bit] = record{kind: 1, value: next}
			current = int(next)
			continue
		}
		current = int(existing.value)
	}
}

func writeNode(t *testing.T, buf *bytes.Buffer, recordSize int, left, right uint32) {
	t.Helper()

	switch recordSize {
	case 24:
		buf.Write([]byte{byte(left >> 16), byte(left >> 8), byte(left)})
		buf.Write([]byte{byte(right >> 16), byte(right >> 8), byte(right)})
	case 28:
		middle := byte((left>>24)&0x0F)<<4 | byte((right>>24)&0x0F)
		buf.Write([]byte{byte(left >> 16), byte(left >> 8), byte(left)})
		buf.WriteByte(middle)
		buf.Write([]byte{byte(right >> 16), byte(right >> 8), byte(right)})
	case 32:
		var b [8]byte
		binary.BigEndian.PutUint32(b[0:4], left)
		binary.BigEndian.PutUint32(b[4:8], right)
		buf.Write(b[:])
	default:
		t.Fatalf("unsupported record size %d", recordSize)
	}
}

// ---------------------------------------------------------------------------
// Minimal MMDB value encoder
// ---------------------------------------------------------------------------

func encodeValue(t *testing.T, buf *bytes.Buffer, value interface{}) {
	t.Helper()

	switch v := value.(type) {
	case string:
		writeControl(t, buf, typeString, len(v))
		buf.WriteString(v)

	case bool:
		size := 0
		if v {
			size = 1
		}
		writeControl(t, buf, typeBool, size)

	case float64:
		writeControl(t, buf, typeDouble, 8)
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], math.Float64bits(v))
		buf.Write(b[:])

	case float32:
		writeControl(t, buf, typeFloat, 4)
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], math.Float32bits(v))
		buf.Write(b[:])

	case uint16Value:
		writeUint(t, buf, typeUint16, uint64(v))

	case uint32Value:
		writeUint(t, buf, typeUint32, uint64(v))

	case uint64Value:
		writeUint(t, buf, typeUint64, uint64(v))

	case uint64:
		writeUint(t, buf, typeUint64, v)

	case int:
		writeUint(t, buf, typeUint32, uint64(v))

	case int32Value:
		writeControl(t, buf, typeInt32, 4)
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(v))
		buf.Write(b[:])

	case []interface{}:
		writeControl(t, buf, typeArray, len(v))
		for _, item := range v {
			encodeValue(t, buf, item)
		}

	case map[string]interface{}:
		writeControl(t, buf, typeMap, len(v))
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			encodeValue(t, buf, k)
			encodeValue(t, buf, v[k])
		}

	default:
		t.Fatalf("fixture encoder cannot handle %T", value)
	}
}

func writeUint(t *testing.T, buf *bytes.Buffer, typ int, v uint64) {
	t.Helper()

	var raw []byte
	for i := 7; i >= 0; i-- {
		b := byte(v >> (uint(i) * 8))
		if len(raw) == 0 && b == 0 {
			continue
		}
		raw = append(raw, b)
	}
	writeControl(t, buf, typ, len(raw))
	buf.Write(raw)
}

func writeControl(t *testing.T, buf *bytes.Buffer, typ, size int) {
	t.Helper()

	var sizeBits int
	var extra []byte
	switch {
	case size < 29:
		sizeBits = size
	case size < 285:
		sizeBits = 29
		extra = []byte{byte(size - 29)}
	case size < 65821:
		sizeBits = 30
		extra = []byte{byte((size - 285) >> 8), byte(size - 285)}
	default:
		t.Fatalf("fixture encoder does not support values of %d bytes", size)
	}

	if typ <= 7 {
		buf.WriteByte(byte(typ)<<5 | byte(sizeBits))
	} else {
		buf.WriteByte(byte(sizeBits))
		buf.WriteByte(byte(typ - 7))
	}
	buf.Write(extra)
}

func writeFixture(t *testing.T, dir, name string, content []byte) string {
	t.Helper()
	path := fmt.Sprintf("%s/%s", dir, name)
	if err := writeFile(path, content); err != nil {
		t.Fatalf("cannot write fixture %s: %v", path, err)
	}
	return path
}
