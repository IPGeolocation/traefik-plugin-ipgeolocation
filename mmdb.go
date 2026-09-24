package ipgeolocation

import (
	"fmt"
	"net"
	"os"
	"time"
)

// metadataMarker separates the data section from the metadata block.
var metadataMarker = []byte{0xAB, 0xCD, 0xEF, 'M', 'a', 'x', 'M', 'i', 'n', 'd', '.', 'c', 'o', 'm'}

// metadataMaxSize is the largest region at the end of the file that the
// specification allows the metadata block to occupy.
const metadataMaxSize = 128 * 1024

// Metadata describes an opened database.
type Metadata struct {
	DatabaseType string
	Description  map[string]string
	Languages    []string
	BuildEpoch   int64
	IPVersion    int
	NodeCount    uint32
	RecordSize   uint
	MajorVersion int
	MinorVersion int
}

// BuildTime returns the build timestamp of the database.
func (m Metadata) BuildTime() time.Time { return time.Unix(m.BuildEpoch, 0).UTC() }

// Reader looks up IP addresses in a single MMDB file.
type Reader struct {
	path     string
	src      source
	meta     Metadata
	nodeSize int64 // bytes per node
	treeSize int64
	dataBase int64 // start of the data section; also the pointer base

	ipv4Start    uint32
	ipv4StartSet bool
	fileSize     int64
	fileModTime  time.Time
	inMemory     bool
}

// OpenReader opens an MMDB file. When inMemory is true the whole file is read
// into RAM; otherwise only the search tree is kept resident and data records
// are read from disk as needed.
func OpenReader(path string, inMemory bool) (*Reader, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("cannot stat %q: %v", path, err)
	}
	if st.IsDir() {
		return nil, fmt.Errorf("%q is a directory, not an MMDB file", path)
	}

	// Note for maintainers: assign the concrete type to a local first and
	// then to the interface. Yaegi, the interpreter Traefik runs plugins
	// with, cannot convert a concrete type to an interface as part of a
	// multi-value assignment from a call.
	var src source
	if inMemory {
		memory, memErr := newMemSource(path)
		if memErr != nil {
			return nil, fmt.Errorf("cannot open %q: %v", path, memErr)
		}
		src = memory
	} else {
		file, fileErr := newFileSource(path)
		if fileErr != nil {
			return nil, fmt.Errorf("cannot open %q: %v", path, fileErr)
		}
		src = file
	}

	r := &Reader{
		path:        path,
		src:         src,
		inMemory:    inMemory,
		fileSize:    st.Size(),
		fileModTime: st.ModTime(),
	}

	if err := r.readMetadata(); err != nil {
		_ = src.close()
		return nil, fmt.Errorf("cannot read metadata of %q: %v", path, err)
	}

	if fs, ok := src.(*fileSource); ok {
		// Pin the search tree plus the 16 byte separator.
		if err := fs.loadHead(r.dataBase); err != nil {
			_ = src.close()
			return nil, fmt.Errorf("cannot load search tree of %q: %v", path, err)
		}
	}

	if r.meta.IPVersion == 6 {
		start, err := r.findIPv4Start()
		if err != nil {
			_ = src.close()
			return nil, fmt.Errorf("cannot locate the IPv4 subtree of %q: %v", path, err)
		}
		r.ipv4Start = start
		r.ipv4StartSet = true
	}

	return r, nil
}

// Close releases the file handle or memory held by the reader.
func (r *Reader) Close() error {
	if r.src == nil {
		return nil
	}
	return r.src.close()
}

// Metadata returns the database metadata.
func (r *Reader) Metadata() Metadata { return r.meta }

// Path returns the file the reader was opened from.
func (r *Reader) Path() string { return r.path }

// Changed reports whether the file on disk differs from the one that was
// opened, which is how the background refresher detects a new release.
func (r *Reader) Changed() bool {
	st, err := os.Stat(r.path)
	if err != nil {
		return false
	}
	return st.Size() != r.fileSize || !st.ModTime().Equal(r.fileModTime)
}

func (r *Reader) readMetadata() error {
	total := r.src.size()
	if total < int64(len(metadataMarker)) {
		return fmt.Errorf("file is too small (%d bytes) to be an MMDB database", total)
	}

	window := int64(metadataMaxSize)
	if window > total {
		window = total
	}
	start := total - window
	buf, err := r.src.at(start, int(window))
	if err != nil {
		return err
	}

	idx := lastIndexOfBytes(buf, metadataMarker)
	if idx < 0 {
		return fmt.Errorf("metadata marker not found; the file does not look like an MMDB database")
	}
	metaStart := start + int64(idx) + int64(len(metadataMarker))

	d := &decoder{src: r.src, base: metaStart}
	raw, _, err := d.decode(metaStart, 0)
	if err != nil {
		return err
	}
	m, ok := raw.(map[string]interface{})
	if !ok {
		return fmt.Errorf("metadata block is not a map")
	}

	r.meta = Metadata{
		DatabaseType: asString(m["database_type"]),
		Description:  asStringMap(m["description"]),
		Languages:    asStringSlice(m["languages"]),
		BuildEpoch:   int64(asUint(m["build_epoch"])),
		IPVersion:    int(asUint(m["ip_version"])),
		NodeCount:    uint32(asUint(m["node_count"])),
		RecordSize:   uint(asUint(m["record_size"])),
		MajorVersion: int(asUint(m["binary_format_major_version"])),
		MinorVersion: int(asUint(m["binary_format_minor_version"])),
	}

	switch r.meta.RecordSize {
	case 24, 28, 32:
	default:
		return fmt.Errorf("unsupported record size %d", r.meta.RecordSize)
	}
	if r.meta.NodeCount == 0 {
		return fmt.Errorf("database declares zero nodes")
	}
	if r.meta.IPVersion != 4 && r.meta.IPVersion != 6 {
		return fmt.Errorf("unsupported IP version %d", r.meta.IPVersion)
	}
	if r.meta.MajorVersion != 2 {
		return fmt.Errorf("unsupported binary format version %d.%d", r.meta.MajorVersion, r.meta.MinorVersion)
	}

	r.nodeSize = int64(r.meta.RecordSize) * 2 / 8
	r.treeSize = int64(r.meta.NodeCount) * r.nodeSize
	r.dataBase = r.treeSize + 16
	if r.dataBase > total {
		return fmt.Errorf("search tree of %d bytes does not fit in a file of %d bytes", r.treeSize, total)
	}
	return nil
}

// readNode returns the left and right records of a node.
func (r *Reader) readNode(node uint32) (uint32, uint32, error) {
	base := int64(node) * r.nodeSize
	b, err := r.src.at(base, int(r.nodeSize))
	if err != nil {
		return 0, 0, err
	}

	switch r.meta.RecordSize {
	case 24:
		left := uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
		right := uint32(b[3])<<16 | uint32(b[4])<<8 | uint32(b[5])
		return left, right, nil
	case 28:
		left := uint32(b[3]&0xF0)<<20 | uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
		right := uint32(b[3]&0x0F)<<24 | uint32(b[4])<<16 | uint32(b[5])<<8 | uint32(b[6])
		return left, right, nil
	default:
		left := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
		right := uint32(b[4])<<24 | uint32(b[5])<<16 | uint32(b[6])<<8 | uint32(b[7])
		return left, right, nil
	}
}

// findIPv4Start walks 96 zero bits from the root, which is where the IPv4
// subtree of an IPv6 database begins.
func (r *Reader) findIPv4Start() (uint32, error) {
	node := uint32(0)
	for i := 0; i < 96 && node < r.meta.NodeCount; i++ {
		left, _, err := r.readNode(node)
		if err != nil {
			return 0, err
		}
		node = left
	}
	return node, nil
}

// Lookup resolves an IP address and decodes its whole record. Prefer
// LookupOffset with Value when only a few fields are needed.
func (r *Reader) Lookup(ip net.IP) (interface{}, bool, error) {
	offset, found, err := r.LookupOffset(ip)
	if err != nil || !found {
		return nil, found, err
	}
	return r.lookupRecordAt(offset)
}

// recordWindow is how much of the data section is read in one call before
// decoding a record from a file backed database. Large enough to hold most
// records whole, small enough that the read stays cheap.
const recordWindow = 4096

// readerSource returns the source to decode a record at offset with, reading
// a window up front when the database is not resident in memory.
func (r *Reader) readerSource(offset int64) source {
	if r.inMemory {
		return r.src
	}
	size := int64(recordWindow)
	if remaining := r.src.size() - offset; remaining < size {
		size = remaining
	}
	if size <= 0 {
		return r.src
	}
	buf, err := r.src.at(offset, int(size))
	if err != nil {
		return r.src
	}
	window := make([]byte, size)
	copy(window, buf)
	return &windowSource{base: offset, buf: window, fallback: r.src}
}

// lookupRecordAt decodes the whole record at offset.
func (r *Reader) lookupRecordAt(offset int64) (interface{}, bool, error) {
	d := &decoder{src: r.readerSource(offset), base: r.dataBase}
	value, _, err := d.decode(offset, 0)
	if err != nil {
		return nil, false, err
	}
	return value, true, nil
}

// Value returns the value at a dot separated path inside the record at
// offset, decoding only that subtree.
func (r *Reader) Value(offset int64, path []string) (interface{}, bool, error) {
	d := &decoder{src: r.readerSource(offset), base: r.dataBase}
	target, found, err := d.seek(offset, path, 0)
	if err != nil || !found {
		return nil, false, err
	}
	value, _, err := d.decode(target, 0)
	if err != nil {
		return nil, false, err
	}
	return value, true, nil
}

// LookupOffset resolves an IP address to the offset of its record without
// decoding anything.
func (r *Reader) LookupOffset(ip net.IP) (int64, bool, error) {
	if ip == nil {
		return 0, false, fmt.Errorf("nil IP address")
	}

	var addr []byte
	node := uint32(0)

	if v4 := ip.To4(); v4 != nil {
		addr = v4
		if r.meta.IPVersion == 6 {
			if !r.ipv4StartSet {
				return 0, false, fmt.Errorf("IPv4 subtree offset is unknown")
			}
			node = r.ipv4Start
		}
	} else {
		if r.meta.IPVersion == 4 {
			// An IPv6-only address cannot be present in an IPv4 database.
			return 0, false, nil
		}
		addr = ip.To16()
		if addr == nil {
			return 0, false, fmt.Errorf("unusable IP address %q", ip.String())
		}
	}

	bits := len(addr) * 8
	for i := 0; i < bits; i++ {
		if node >= r.meta.NodeCount {
			break
		}
		bit := (addr[i>>3] >> (7 - uint(i&7))) & 1
		left, right, err := r.readNode(node)
		if err != nil {
			return 0, false, err
		}
		if bit == 0 {
			node = left
		} else {
			node = right
		}
	}

	switch {
	case node == r.meta.NodeCount:
		// The reserved "no data" record.
		return 0, false, nil
	case node > r.meta.NodeCount:
		return r.dataBase + int64(node) - int64(r.meta.NodeCount) - 16, true, nil
	}

	return 0, false, fmt.Errorf("search tree is corrupt: terminated inside the tree at node %d", node)
}

func lastIndexOfBytes(haystack, needle []byte) int {
	if len(needle) == 0 || len(haystack) < len(needle) {
		return -1
	}
	for i := len(haystack) - len(needle); i >= 0; i-- {
		match := true
		for j := 0; j < len(needle); j++ {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}
