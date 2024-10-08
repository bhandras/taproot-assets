package proof

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightningnetwork/lnd/tlv"
	"github.com/stretchr/testify/require"
)

var (
	// proofInvalidJsonHexFileName is the name of the file that contains the
	// hex proof data for a proof where the meta type is declared as JSON
	// but the data is not valid JSON.
	proofInvalidJsonHexFileName = filepath.Join(
		testDataFileName, "proof-invalid-json-meta-reveal.hex",
	)
)

func TestValidateMetaReveal(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		reveal      *MetaReveal
		expectedErr error
	}{
		{
			name:        "nil reveal",
			reveal:      nil,
			expectedErr: nil,
		},
		{
			name: "valid reveal",
			reveal: &MetaReveal{
				Type: MetaOpaque,
				Data: []byte("data"),
			},
			expectedErr: nil,
		},
		{
			name: "missing data",
			reveal: &MetaReveal{
				Type: MetaOpaque,
				Data: nil,
			},
			expectedErr: ErrMetaDataMissing,
		},
		{
			name: "too much data",
			reveal: &MetaReveal{
				Type: MetaOpaque,
				Data: make([]byte, MetaDataMaxSizeBytes+1),
			},
			expectedErr: ErrMetaDataTooLarge,
		},
		{
			name: "invalid JSON",
			reveal: &MetaReveal{
				Type: MetaJson,
				Data: []byte("invalid"),
			},
			expectedErr: ErrInvalidJSON,
		},
		{
			name: "valid JSON",
			reveal: &MetaReveal{
				Type: MetaJson,
				Data: []byte(`{"key": "value"}`),
			},
			expectedErr: nil,
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(tt *testing.T) {
			tt.Parallel()

			err := tc.reveal.Validate()
			if tc.expectedErr == nil {
				require.NoError(tt, err)
				return
			}

			require.Error(tt, err)
			require.ErrorIs(tt, err, tc.expectedErr)
		})
	}
}

// TestProofInvalidJsonMetaReveal tests that a proof with a meta reveal that
// is declared as JSON but is not valid JSON will return the correct error when
// trying to decode the decimal display.
func TestProofInvalidJsonMetaReveal(t *testing.T) {
	proofHex, err := os.ReadFile(proofInvalidJsonHexFileName)
	require.NoError(t, err)

	proofBytes, err := hex.DecodeString(
		strings.Trim(string(proofHex), "\n"),
	)
	require.NoError(t, err)

	p := &Proof{}
	err = p.Decode(bytes.NewReader(proofBytes))
	require.NoError(t, err)

	require.NotNil(t, p.MetaReveal)

	_, decDisplay, err := p.MetaReveal.GetDecDisplay()
	require.ErrorIs(t, err, ErrInvalidJSON)
	require.Zero(t, decDisplay)
}

// TestMetaRevealUnknownOddType tests that an unknown odd type is allowed in a
// meta reveal and that we can still arrive at the correct meta hash with it.
func TestMetaRevealUnknownOddType(t *testing.T) {
	knownMeta := &MetaReveal{
		Type: 123,
		Data: []byte("probably some JPEG or something"),
	}
	knownMetaHash := knownMeta.MetaHash()

	test.RunUnknownOddTypeTest(
		t, knownMeta, &asset.ErrUnknownType{},
		func(buf *bytes.Buffer, meta *MetaReveal) error {
			return meta.Encode(buf)
		},
		func(buf *bytes.Buffer) (*MetaReveal, error) {
			var parsedMeta MetaReveal
			return &parsedMeta, parsedMeta.Decode(buf)
		},
		func(parsedMeta *MetaReveal, unknownTypes tlv.TypeMap) {
			require.Equal(
				t, unknownTypes, parsedMeta.UnknownOddTypes,
			)

			// The meta should've changed, to make sure the unknown
			// value was taken into account when creating the
			// serialized meta.
			parsedMetaHash := parsedMeta.MetaHash()

			require.NotEqual(t, knownMetaHash, parsedMetaHash)

			parsedMeta.UnknownOddTypes = nil
			require.Equal(t, knownMeta, parsedMeta)
		},
	)
}
