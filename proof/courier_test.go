package proof

import (
	"bytes"
	"context"
	"testing"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/stretchr/testify/require"
)

// TestUniverseRpcCourierLocalArchiveShortCut tests that the local archive is
// used as a shortcut to fetch a proof if it's available.
func TestUniverseRpcCourierLocalArchiveShortCut(t *testing.T) {
	localArchive := NewMockProofArchive()

	testBlocks := readTestData(t)
	oddTxBlock := testBlocks[0]

	genesis := asset.RandGenesis(t, asset.Collectible)
	scriptKey := test.RandPubKey(t)
	proof := RandProof(t, genesis, scriptKey, oddTxBlock, 0, 1)

	file, err := NewFile(V0, proof, proof)
	require.NoError(t, err)
	proof.AdditionalInputs = []File{*file, *file}

	var fileBuf bytes.Buffer
	require.NoError(t, file.Encode(&fileBuf))
	proofBlob := Blob(fileBuf.Bytes())

	locator := Locator{
		AssetID:   fn.Ptr(genesis.ID()),
		ScriptKey: *proof.Asset.ScriptKey.PubKey,
		OutPoint:  fn.Ptr(proof.OutPoint()),
	}
	locHash, err := locator.Hash()
	require.NoError(t, err)

	localArchive.proofs.Store(locHash, proofBlob)

	recipient := Recipient{}
	courier := &UniverseRpcCourier{
		client:        nil,
		cfg:           &UniverseRpcCourierCfg{},
		localArchive:  localArchive,
		rawConn:       nil,
		backoffHandle: nil,
		subscribers:   nil,
	}

	ctx := context.Background()
	ctxt, cancel := context.WithTimeout(ctx, testTimeout)
	defer cancel()

	// If we attempt to receive a proof that the local archive has, we
	// expect to get it back.
	annotatedProof, err := courier.ReceiveProof(ctxt, recipient, locator)
	require.NoError(t, err)

	require.Equal(t, proofBlob, annotatedProof.Blob)

	// If we query for a proof that the local archive doesn't have, we
	// should end up in the code path that attempts to fetch the proof from
	// the universe. Since we don't want to set up a full universe server
	// in the test, we just make sure we get an error from that code path.
	_, err = courier.ReceiveProof(ctxt, recipient, Locator{
		AssetID:   fn.Ptr(genesis.ID()),
		ScriptKey: *proof.Asset.ScriptKey.PubKey,
	})
	require.ErrorContains(t, err, "is missing outpoint")
}
