package passwordium

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/dmi3midd/passwordium/internal/crypto"
)

func TestHeaderMarshalParseLayout(t *testing.T) {
	t.Parallel()

	var salt [crypto.SaltSize]byte
	for i := range salt {
		salt[i] = byte(i + 1)
	}

	orig := header{
		Version: currentVersion,
		Salt:    salt,
		Params: Argon2Params{
			Time:    3,
			Memory:  64 * 1024,
			Threads: 2,
		},
	}

	raw := orig.marshal()
	if len(raw) != headerSize {
		t.Fatalf("len(marshal) = %d, want %d", len(raw), headerSize)
	}

	// Verify exact binary layout byte-by-byte:
	// [0:4] Magic "PSDM", [4:6] Version BE, [6:38] Salt, [38:42] Time BE, [42:46] Memory BE, [46:50] Threads BE.
	if string(raw[0:4]) != "PSDM" {
		t.Fatalf("magic = %q, want PSDM", raw[0:4])
	}
	if got := binary.BigEndian.Uint16(raw[4:6]); got != 1 {
		t.Fatalf("version = %d, want 1", got)
	}
	if !bytes.Equal(raw[6:38], salt[:]) {
		t.Fatal("salt bytes mismatch")
	}
	if got := binary.BigEndian.Uint32(raw[38:42]); got != 3 {
		t.Fatalf("argonTime = %d, want 3", got)
	}
	if got := binary.BigEndian.Uint32(raw[42:46]); got != 64*1024 {
		t.Fatalf("argonMemory = %d, want %d", got, 64*1024)
	}
	if got := binary.BigEndian.Uint32(raw[46:50]); got != 2 {
		t.Fatalf("argonThreads = %d, want 2", got)
	}

	parsed, err := parseHeader(raw)
	if err != nil {
		t.Fatalf("parseHeader: %v", err)
	}
	if parsed != orig {
		t.Fatalf("parsed header = %+v, want %+v", parsed, orig)
	}
}

func TestHeaderAndEnvelopeValidationErrors(t *testing.T) {
	t.Parallel()

	valid := header{
		Version: currentVersion,
		Params:  DefaultArgon2Params(),
	}.marshal()

	// Truncated header
	if _, err := parseHeader(valid[:headerSize-1]); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("truncated header err = %v, want ErrInvalidHeader", err)
	}

	// Wrong magic
	badMagic := bytes.Clone(valid)
	badMagic[0] = 'X'
	if _, err := parseHeader(badMagic); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("bad magic err = %v, want ErrInvalidHeader", err)
	}

	// Unsupported version
	badVer := bytes.Clone(valid)
	binary.BigEndian.PutUint16(badVer[4:6], 2)
	if _, err := parseHeader(badVer); !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("bad version err = %v, want ErrUnsupportedVersion", err)
	}

	// Out-of-bounds Argon2 params
	badThreads := bytes.Clone(valid)
	binary.BigEndian.PutUint32(badThreads[46:50], 0)
	if _, err := parseHeader(badThreads); !errors.Is(err, ErrInvalidArgon2Params) {
		t.Fatalf("zero threads err = %v, want ErrInvalidArgon2Params", err)
	}

	badMem := bytes.Clone(valid)
	binary.BigEndian.PutUint32(badMem[42:46], 10*1024*1024)
	if _, err := parseHeader(badMem); !errors.Is(err, ErrInvalidArgon2Params) {
		t.Fatalf("huge memory err = %v, want ErrInvalidArgon2Params", err)
	}

	// Valid header but envelope shorter than minEnvelopeSize (90 bytes)
	shortEnv := make([]byte, minEnvelopeSize-1)
	copy(shortEnv, valid)
	if _, _, _, _, err := unpackEnvelope(shortEnv); !errors.Is(err, ErrCorruptedVault) {
		t.Fatalf("short envelope err = %v, want ErrCorruptedVault", err)
	}
}
