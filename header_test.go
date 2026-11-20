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
		Params:  Argon2Params{Time: 3, MemoryKiB: 64 * 1024, Threads: 2},
	}

	raw := orig.marshal()
	if len(raw) != headerSize {
		t.Fatalf("len(marshal) = %d, want %d", len(raw), headerSize)
	}

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

	parsed, err := parseHeader(raw, crypto.DefaultArgon2Limits())
	if err != nil {
		t.Fatalf("parseHeader: %v", err)
	}
	if parsed != orig {
		t.Fatalf("parsed header = %+v, want %+v", parsed, orig)
	}
}

func TestHeaderAndEnvelopeValidationErrors(t *testing.T) {
	t.Parallel()

	limits := crypto.DefaultArgon2Limits()
	valid := header{Version: currentVersion, Params: DefaultArgon2Params()}.marshal()

	if _, err := parseHeader(valid[:headerSize-1], limits); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("truncated header err = %v, want ErrInvalidHeader", err)
	}

	badMagic := bytes.Clone(valid)
	badMagic[0] = 'X'
	if _, err := parseHeader(badMagic, limits); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("bad magic err = %v, want ErrInvalidHeader", err)
	}

	badVer := bytes.Clone(valid)
	binary.BigEndian.PutUint16(badVer[4:6], 2)
	if _, err := parseHeader(badVer, limits); !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("bad version err = %v, want ErrUnsupportedVersion", err)
	}

	badThreads := bytes.Clone(valid)
	binary.BigEndian.PutUint32(badThreads[46:50], 0)
	if _, err := parseHeader(badThreads, limits); !errors.Is(err, ErrInvalidArgon2Params) {
		t.Fatalf("zero threads err = %v, want ErrInvalidArgon2Params", err)
	}

	badMem := bytes.Clone(valid)
	binary.BigEndian.PutUint32(badMem[42:46], 10*1024*1024)
	if _, err := parseHeader(badMem, limits); !errors.Is(err, ErrInvalidArgon2Params) {
		t.Fatalf("huge memory err = %v, want ErrInvalidArgon2Params", err)
	}

	shortEnv := make([]byte, minEnvelopeSize-1)
	copy(shortEnv, valid)
	if _, _, _, _, err := unpackEnvelope(shortEnv, limits); !errors.Is(err, ErrCorruptedVault) {
		t.Fatalf("short envelope err = %v, want ErrCorruptedVault", err)
	}
}

// FINDING-01: headers whose KDF cost exceeds default open limits are rejected during parsing.
func TestParseHeaderEnforcesDoSLimits(t *testing.T) {
	t.Parallel()

	limits := crypto.DefaultArgon2Limits()
	cases := map[string]Argon2Params{
		"hard_max_everything":  {Time: 100, MemoryKiB: 4 * 1024 * 1024, Threads: 255},
		"time_over_default":    {Time: crypto.DefaultMaxArgonTime + 1, MemoryKiB: 64, Threads: 1},
		"memory_over_default":  {Time: 1, MemoryKiB: crypto.DefaultMaxArgonMemoryKiB + 1, Threads: 1},
		"threads_over_default": {Time: 1, MemoryKiB: 64, Threads: crypto.DefaultMaxArgonThreads + 1},
		"work_over_default":    {Time: 8, MemoryKiB: crypto.DefaultMaxArgonMemoryKiB, Threads: 1},
	}
	for name, p := range cases {
		raw := header{Version: currentVersion, Params: p}.marshal()
		if _, err := parseHeader(raw, limits); !errors.Is(err, ErrInvalidArgon2Params) {
			t.Errorf("%s: parseHeader err = %v, want ErrInvalidArgon2Params", name, err)
		}
	}

	// Raised limits accept a header that defaults reject.
	raised := crypto.Argon2Limits{MaxTime: 32, MaxMemoryKiB: 64, MaxThreads: 1, MaxWork: 32 * 64}
	raw := header{Version: currentVersion, Params: Argon2Params{Time: 20, MemoryKiB: 64, Threads: 1}}.marshal()
	if _, err := parseHeader(raw, limits); !errors.Is(err, ErrInvalidArgon2Params) {
		t.Fatalf("Time=20 under default limits err = %v, want ErrInvalidArgon2Params", err)
	}
	if _, err := parseHeader(raw, raised); err != nil {
		t.Fatalf("Time=20 under raised limits err = %v, want nil", err)
	}
}
