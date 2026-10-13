package transport_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/bsv8/go-bitfs/transport"
	"github.com/bsv8/go-bitfs/wire"
)

type fixtureIndex struct {
	WireManifest     string `json:"wire_manifest"`
	TransportProfile string `json:"transport_profile"`
}

type wireFixture struct {
	Entries []struct {
		Kind     uint16 `json:"kind"`
		ExactHex string `json:"exact_hex"`
	} `json:"entries"`
}

func TestFramerRoundTripUsesSharedTruth(t *testing.T) {
	root := filepath.Join("..")
	indexRaw, err := os.ReadFile(filepath.Join(root, "fixtures", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var index fixtureIndex
	if err := json.Unmarshal(indexRaw, &index); err != nil {
		t.Fatal(err)
	}
	manifestRaw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(index.WireManifest)))
	if err != nil {
		t.Fatal(err)
	}
	var manifest wireFixture
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		t.Fatal(err)
	}

	var stream bytes.Buffer
	writer, err := transport.NewFramer(&stream)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range manifest.Entries {
		raw, err := hex.DecodeString(entry.ExactHex)
		if err != nil {
			t.Fatal(err)
		}
		artifact, err := wire.ParseAs(wire.Kind(entry.Kind), raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := writer.WriteArtifact(artifact); err != nil {
			t.Fatal(err)
		}
	}

	reader, err := transport.NewFramer(&stream)
	if err != nil {
		t.Fatal(err)
	}
	for index, expected := range manifest.Entries {
		artifact, err := reader.ReadArtifact()
		if err != nil {
			t.Fatalf("entry %d: %v", index, err)
		}
		if artifact.Kind() != wire.Kind(expected.Kind) {
			t.Fatalf("entry %d kind = %d, want %d", index, artifact.Kind(), expected.Kind)
		}
	}
}

func TestProtocolIDIsSharedProfile(t *testing.T) {
	indexRaw, err := os.ReadFile(filepath.Join("..", "fixtures", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var index fixtureIndex
	if err := json.Unmarshal(indexRaw, &index); err != nil {
		t.Fatal(err)
	}
	var profile struct {
		ProtocolID        string `json:"protocol_id"`
		MaxWireFrameBytes int    `json:"max_wire_frame_bytes"`
	}
	raw, err := os.ReadFile(filepath.Join("..", filepath.FromSlash(index.TransportProfile)))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &profile); err != nil {
		t.Fatal(err)
	}
	if transport.ProtocolID != profile.ProtocolID {
		t.Fatalf("ProtocolID = %q, want shared %q", transport.ProtocolID, profile.ProtocolID)
	}
	if wire.MaxWireParseBytes != profile.MaxWireFrameBytes {
		t.Fatalf("MaxWireParseBytes = %d, want shared %d", wire.MaxWireParseBytes, profile.MaxWireFrameBytes)
	}
}
