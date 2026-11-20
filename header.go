package passwordium

import (
	"encoding/binary"
	"fmt"

	"github.com/dmi3midd/passwordium/internal/crypto"
)

const (
	headerMagic           = "PSDM"
	currentVersion uint16 = 1

	// headerSize is the fixed 50-byte plaintext envelope header length:
	// Magic (4) + Version (2) + Salt (32) + ArgonTime (4) + ArgonMemory (4) + ArgonThreads (4).
	headerSize = 50

	// minEnvelopeSize is Header (50) + Nonce (24) + Poly1305 Tag (16).
	minEnvelopeSize = headerSize + crypto.NonceSize + crypto.Overhead
)

type header struct {
	Version uint16
	Salt    [crypto.SaltSize]byte
	Params  Argon2Params
}

func (h header) marshal() []byte {
	buf := make([]byte, headerSize)
	copy(buf[0:4], headerMagic)
	binary.BigEndian.PutUint16(buf[4:6], h.Version)
	copy(buf[6:38], h.Salt[:])
	binary.BigEndian.PutUint32(buf[38:42], h.Params.Time)
	binary.BigEndian.PutUint32(buf[42:46], h.Params.Memory)
	binary.BigEndian.PutUint32(buf[46:50], h.Params.Threads)
	return buf
}

func parseHeader(data []byte) (header, error) {
	if len(data) < headerSize {
		return header{}, fmt.Errorf("%w: expected at least %d bytes, got %d", ErrInvalidHeader, headerSize, len(data))
	}
	if string(data[0:4]) != headerMagic {
		return header{}, fmt.Errorf("%w: unexpected magic bytes", ErrInvalidHeader)
	}

	version := binary.BigEndian.Uint16(data[4:6])
	if version != currentVersion {
		return header{}, fmt.Errorf("%w: %d", ErrUnsupportedVersion, version)
	}

	var h header
	h.Version = version
	copy(h.Salt[:], data[6:38])
	h.Params = Argon2Params{
		Time:    binary.BigEndian.Uint32(data[38:42]),
		Memory:  binary.BigEndian.Uint32(data[42:46]),
		Threads: binary.BigEndian.Uint32(data[46:50]),
	}
	if err := h.Params.validate(); err != nil {
		return header{}, err
	}
	return h, nil
}

func packEnvelope(headerBytes, nonce, ciphertext []byte) []byte {
	out := make([]byte, 0, len(headerBytes)+len(nonce)+len(ciphertext))
	out = append(out, headerBytes...)
	out = append(out, nonce...)
	out = append(out, ciphertext...)
	return out
}

func unpackEnvelope(data []byte) (hdr header, headerBytes, nonce, ciphertext []byte, err error) {
	hdr, err = parseHeader(data)
	if err != nil {
		return header{}, nil, nil, nil, err
	}
	if len(data) < minEnvelopeSize {
		return header{}, nil, nil, nil, fmt.Errorf("%w: envelope too short (%d bytes)", ErrCorruptedVault, len(data))
	}
	headerBytes = data[:headerSize]
	nonce = data[headerSize : headerSize+crypto.NonceSize]
	ciphertext = data[headerSize+crypto.NonceSize:]
	return hdr, headerBytes, nonce, ciphertext, nil
}
