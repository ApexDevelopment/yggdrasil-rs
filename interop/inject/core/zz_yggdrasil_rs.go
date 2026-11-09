package core

// Exports internals for yggdrasil-rs's interop tests.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
)

type ExportedMetadata struct {
	Major    uint16
	Minor    uint16
	Key      []byte
	Priority uint8
}

func ExportEncodeMetadata(major, minor uint16, priority uint8, secret ed25519.PrivateKey, password []byte) ([]byte, error) {
	m := version_metadata{
		majorVer:  major,
		minorVer:  minor,
		publicKey: secret.Public().(ed25519.PublicKey),
		priority:  priority,
	}
	return m.encode(secret, password)
}

func ExportDecodeMetadata(data []byte, password []byte) (ExportedMetadata, error) {
	var m version_metadata
	err := m.decode(bytes.NewReader(data), password)
	return ExportedMetadata{m.majorVer, m.minorVer, m.publicKey, m.priority}, err
}

func ExportNodeInfo(given map[string]any, privacy bool) (json.RawMessage, error) {
	var n nodeinfo
	if err := n._setNodeInfo(given, privacy); err != nil {
		return nil, err
	}
	return n.myNodeInfo, nil
}
