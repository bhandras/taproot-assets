package itest

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/cmd/commands"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/rpcutils"
	"github.com/lightninglabs/taproot-assets/tapfreighter"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/taprpc"
	wrpc "github.com/lightninglabs/taproot-assets/taprpc/assetwalletrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/tapdevrpc"
	unirpc "github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightningnetwork/lnd/lnrpc/chainrpc"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"
	"google.golang.org/protobuf/proto"
)

var (
	statusDetected  = taprpc.AddrEventStatus_ADDR_EVENT_STATUS_TRANSACTION_DETECTED
	statusConfirmed = taprpc.AddrEventStatus_ADDR_EVENT_STATUS_TRANSACTION_CONFIRMED
	proofReceived   = taprpc.AddrEventStatus_ADDR_EVENT_STATUS_PROOF_RECEIVED
	statusCompleted = taprpc.AddrEventStatus_ADDR_EVENT_STATUS_COMPLETED

	batchFrozen    = mintrpc.BatchState_BATCH_STATE_FROZEN
	batchFinalized = mintrpc.BatchState_BATCH_STATE_FINALIZED

	allScriptKeysQuery = &taprpc.ScriptKeyTypeQuery{
		Type: &taprpc.ScriptKeyTypeQuery_AllTypes{
			AllTypes: true,
		},
	}

	groupBalancesByAssetID = &taprpc.ListBalancesRequest_AssetId{
		AssetId: true,
	}

	groupBalancesByGroupKey = &taprpc.ListBalancesRequest_GroupKey{
		GroupKey: true,
	}
)

// tapClient is an interface that covers all currently available RPC interfaces
// a client should implement.
type tapClient interface {
	taprpc.TaprootAssetsClient
	wrpc.AssetWalletClient
	tapdevrpc.TapDevClient
	mintrpc.MintClient
	unirpc.UniverseClient
}

// AssetCheck is a function type that checks an RPC asset's property.
type AssetCheck func(a *taprpc.Asset) error

// AssetAmountCheck returns a check function that tests an asset's amount.
func AssetAmountCheck(amt uint64) AssetCheck {
	return func(a *taprpc.Asset) error {
		if a.Amount != amt {
			return fmt.Errorf("unexpected asset amount, got %d "+
				"wanted %d", a.Amount, amt)
		}

		return nil
	}
}

// AssetTypeCheck returns a check function that tests an asset's type.
func AssetTypeCheck(assetType taprpc.AssetType) AssetCheck {
	return func(a *taprpc.Asset) error {
		if a.AssetGenesis.AssetType != assetType {
			return fmt.Errorf("unexpected asset type, got %v "+
				"wanted %v", a.AssetGenesis.AssetType,
				assetType)
		}

		return nil
	}
}

// AssetAnchorCheck returns a check function that tests an asset's anchor.
func AssetAnchorCheck(txid, blockHash chainhash.Hash) AssetCheck {
	return func(a *taprpc.Asset) error {
		if a.ChainAnchor == nil {
			return fmt.Errorf("asset is missing chain anchor field")
		}

		out, err :=
			wire.NewOutPointFromString(a.ChainAnchor.AnchorOutpoint)
		if err != nil {
			return fmt.Errorf("unable to parse outpoint: %w", err)
		}

		anchorTxid := out.Hash.String()

		if anchorTxid != txid.String() {
			return fmt.Errorf("unexpected asset anchor TXID, got "+
				"%v wanted %x", anchorTxid, txid[:])
		}

		if a.ChainAnchor.AnchorBlockHash != blockHash.String() {
			return fmt.Errorf("unexpected asset anchor block "+
				"hash, got %v wanted %x",
				a.ChainAnchor.AnchorBlockHash, blockHash[:])
		}

		return nil
	}
}

// AssetScriptKeyIsLocalCheck returns a check function that tests an asset's
// script key for being a local key.
func AssetScriptKeyIsLocalCheck(isLocal bool) AssetCheck {
	return func(a *taprpc.Asset) error {
		if a.ScriptKeyIsLocal != isLocal {
			return fmt.Errorf("unexpected script key, wanted "+
				"local=%v but is local=%v", isLocal,
				a.ScriptKeyIsLocal)
		}

		return nil
	}
}

// AssetScriptKeyIsBurnCheck returns a check function that tests an asset's
// script key for being a burn key.
func AssetScriptKeyIsBurnCheck(isBurn bool) AssetCheck {
	return func(a *taprpc.Asset) error {
		if a.IsBurn != isBurn {
			return fmt.Errorf("unexpected script key, wanted "+
				"is_burn=%v but is is_burn=%v", isBurn,
				a.IsBurn)
		}

		return nil
	}
}

func AssetScriptKeyCheck(scriptKey *taprpc.ScriptKey) AssetCheck {
	return func(a *taprpc.Asset) error {
		if scriptKey == nil {
			return nil
		}

		if !bytes.Equal(scriptKey.PubKey, a.ScriptKey[1:]) {
			return fmt.Errorf("unexpected script key, "+
				"wanted %x, got %x ", scriptKey.PubKey,
				a.ScriptKey[1:])
		}

		return nil
	}
}

func AssetIsGroupedCheck(newGrouped, grouped bool) AssetCheck {
	return func(a *taprpc.Asset) error {
		needsGroup := newGrouped || grouped
		if !needsGroup {
			return nil
		}

		if needsGroup && a.AssetGroup == nil {
			return fmt.Errorf("unexpected missing asset group")
		}

		return nil
	}
}

func AssetGroupInternalKeyCheck(key *taprpc.KeyDescriptor) AssetCheck {
	return func(a *taprpc.Asset) error {
		if key == nil {
			return nil
		}

		if a.AssetGroup == nil {
			return fmt.Errorf("unexpected missing asset group")
		}

		expectedKey := key.RawKeyBytes
		groupInternal := a.AssetGroup.RawGroupKey
		if !bytes.Equal(expectedKey, groupInternal) {
			return fmt.Errorf("mistmatched group internal "+
				"key, wanted %x, got %x ", expectedKey,
				groupInternal)
		}

		return nil
	}
}

func AssetGroupTapscriptRootCheck(root []byte) AssetCheck {
	return func(a *taprpc.Asset) error {
		if len(root) == 0 {
			return nil
		}

		switch {
		case a.AssetGroup == nil:
			return fmt.Errorf("unexpected missing asset group")

		case !bytes.Equal(root, a.AssetGroup.TapscriptRoot):
			return fmt.Errorf("mistmatched group tapscript roots, "+
				"wanted %x, got %x",
				root, a.AssetGroup.TapscriptRoot)
		}

		return nil
	}
}

// AssetVersionCheck returns a check function that tests an asset's version.
func AssetVersionCheck(version taprpc.AssetVersion) AssetCheck {
	return func(a *taprpc.Asset) error {
		if a.Version != version {
			return fmt.Errorf("unexpected asset version, got %v "+
				"wanted %v", a.Version, version)
		}

		return nil
	}
}

// AssetDecimalDisplayCheck returns a check function that tests an asset's
// decimal display value. The check function requires that the rpc Asset has a
// non-nil decimal display value.
func AssetDecimalDisplayCheck(decDisplay uint32) AssetCheck {
	return func(a *taprpc.Asset) error {
		// If we didn't set a decimal display in the mint request, we
		// don't expect one to be set.
		if decDisplay == 0 &&
			(a.DecimalDisplay == nil ||
				a.DecimalDisplay.DecimalDisplay == 0) {

			return nil
		}

		if a.DecimalDisplay == nil {
			return fmt.Errorf("asset decimal display is nil")
		}

		if a.DecimalDisplay.DecimalDisplay != decDisplay {
			return fmt.Errorf("unexpected asset decimal display, "+
				"got %v wanted %v", a.DecimalDisplay,
				decDisplay)
		}

		return nil
	}
}

// GroupAssetsByName converts an unordered list of assets to a map of lists of
// assets, where all assets in a list have the same name.
func GroupAssetsByName(assets []*taprpc.Asset) map[string][]*taprpc.Asset {
	assetLists := make(map[string][]*taprpc.Asset)
	for idx := range assets {
		a := assets[idx]
		assetLists[a.AssetGenesis.Name] = append(
			assetLists[a.AssetGenesis.Name], a,
		)
	}

	return assetLists
}

// AssertAssetState makes sure that an asset with the given (possibly
// non-unique!) name exists in the list of assets and then performs the given
// additional checks on that asset.
func AssertAssetState(t *testing.T, assets map[string][]*taprpc.Asset,
	name string, metaHash []byte, assetChecks ...AssetCheck) *taprpc.Asset {

	// Sanity check that the asset name is in the asset map.
	require.Contains(t, assets, name)

	// Find matching asset given asset name and metadata hash.
	var foundAsset *taprpc.Asset
	for _, rpcAsset := range assets[name] {
		rpcGen := rpcAsset.AssetGenesis

		switch {
		case len(assets[name]) == 1:
			foundAsset = rpcAsset
		default:
			// If there are more than one asset with the same
			// name, we need to check the metadata hash to find the
			// correct one.
			if bytes.Equal(rpcGen.MetaHash, metaHash[:]) {
				foundAsset = rpcAsset
			}
		}

		// Break out of the loop if we found a matching asset.
		if foundAsset != nil {
			break
		}
	}

	require.NotNil(t, foundAsset, fmt.Errorf("asset with matching "+
		"name/metadata not found in asset list"))

	// If we have a found asset, we can now run the additional checks
	// against it.
	for _, check := range assetChecks {
		err := check(foundAsset)
		require.NoError(t, err)
	}

	return foundAsset
}

// AssertAssetStateByScriptKey makes sure that an asset with the given (possibly
// non-unique!) name exists in the list of assets and then performs the given
// additional checks on that asset.
func AssertAssetStateByScriptKey(t *testing.T, assets []*taprpc.Asset,
	scriptKey []byte, assetChecks ...AssetCheck) *taprpc.Asset {

	var a *taprpc.Asset
	for _, rpcAsset := range assets {
		if bytes.Equal(rpcAsset.ScriptKey, scriptKey) {
			a = rpcAsset

			for _, check := range assetChecks {
				err := check(rpcAsset)
				require.NoError(t, err)
			}

			break
		}
	}

	require.NotNil(t, a, fmt.Errorf("asset with matching metadata not"+
		"found in asset list"))

	return a
}

// AssertTxInBlock checks that a given transaction can be found in the block's
// transaction list.
func AssertTxInBlock(t *testing.T, block *wire.MsgBlock,
	txid *chainhash.Hash) *wire.MsgTx {

	for _, tx := range block.Transactions {
		sha := tx.TxHash()
		if bytes.Equal(txid[:], sha[:]) {
			return tx
		}
	}

	require.Fail(t, "tx was not included in block")

	return nil
}

// AssertTransferFeeRate checks that fee paid for the TX anchoring an asset
// transfer is close to the expected fee for that TX, at a given fee rate.
func AssertTransferFeeRate(t *testing.T, minerClient *rpcclient.Client,
	transferResp *taprpc.SendAssetResponse, inputAmt int64,
	feeRate chainfee.SatPerKWeight) {

	txid, err := chainhash.NewHash(transferResp.Transfer.AnchorTxHash)
	require.NoError(t, err)

	AssertFeeRate(t, minerClient, inputAmt, txid, feeRate)
}

// AssertFeeRate checks that the fee paid for a given TX is close to the
// expected fee for the same TX, at a given fee rate.
func AssertFeeRate(t *testing.T, minerClient *rpcclient.Client, inputAmt int64,
	txid *chainhash.Hash, feeRate chainfee.SatPerKWeight) {

	var (
		outputValue                 float64
		expectedFee, maxOverpayment btcutil.Amount
		maxVsizeDifference          = lntypes.VByte(2)
	)

	verboseTx, err := minerClient.GetRawTransactionVerbose(txid)
	require.NoError(t, err)

	vsize := verboseTx.Vsize
	weight := verboseTx.Weight

	for _, vout := range verboseTx.Vout {
		outputValue += vout.Value
	}

	t.Logf("TX vsize of %d bytes", vsize)

	btcOutputValue, err := btcutil.NewAmount(outputValue)
	require.NoError(t, err)

	actualFee := inputAmt - int64(btcOutputValue)

	expectedFee = feeRate.FeeForWeight(lntypes.WeightUnit(weight))
	maxOverpayment = feeRate.FeePerKVByte().FeeForVSize(maxVsizeDifference)

	// The actual fee may be higher than the expected fee after
	// confirmation, as the freighter makes a worst-case estimate of the TX
	// vsize. The gap between these two fees should still be small.
	require.GreaterOrEqual(t, actualFee, int64(expectedFee))

	overpaidFee := actualFee - int64(expectedFee)
	require.LessOrEqual(t, overpaidFee, int64(maxOverpayment))

	t.Logf("Correct fee of %d sats", actualFee)
}

// WaitForBatchState polls until the planter has reached the desired state with
// the given batch.
func WaitForBatchState(t *testing.T, ctx context.Context,
	client mintrpc.MintClient, timeout time.Duration, batchKey []byte,
	targetState mintrpc.BatchState) {

	err := wait.NoError(func() error {
		batchResp, err := client.ListBatches(
			ctx, &mintrpc.ListBatchRequest{
				Filter: &mintrpc.ListBatchRequest_BatchKey{
					BatchKey: batchKey,
				},
			},
		)
		require.NoError(t, err)

		if len(batchResp.Batches) != 1 {
			return fmt.Errorf("expected one batch, got %d",
				len(batchResp.Batches))
		}

		if batchResp.Batches[0].Batch.State != targetState {
			return fmt.Errorf("expected batch state %v, got %v",
				targetState, batchResp.Batches[0].Batch.State)
		}

		return nil
	}, timeout)
	require.NoError(t, err)
}

// CommitmentKey returns the asset's commitment key given an RPC asset
// representation.
func CommitmentKey(t *testing.T, rpcAsset *taprpc.Asset) [32]byte {
	t.Helper()

	var assetID asset.ID
	copy(assetID[:], rpcAsset.AssetGenesis.AssetId)

	scriptKey, err := btcec.ParsePubKey(rpcAsset.ScriptKey)
	require.NoError(t, err)

	var groupKey *btcec.PublicKey
	if rpcAsset.AssetGroup != nil &&
		len(rpcAsset.AssetGroup.TweakedGroupKey) > 0 {

		groupKey, err = btcec.ParsePubKey(
			rpcAsset.AssetGroup.TweakedGroupKey,
		)
		require.NoError(t, err)
	}

	return asset.AssetCommitmentKey(assetID, scriptKey, groupKey == nil)
}

// WaitForProofUpdate polls until the proof for the given asset has been
// updated, which is detected by checking the block height of the last proof.
func WaitForProofUpdate(t *testing.T, client taprpc.TaprootAssetsClient,
	a *taprpc.Asset, blockHeight int32) {

	t.Helper()

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout*2)
	defer cancel()

	require.Eventually(t, func() bool {
		// Export the proof, then decode it.
		exportResp, err := client.ExportProof(
			ctxt, &taprpc.ExportProofRequest{
				AssetId:   a.AssetGenesis.AssetId,
				ScriptKey: a.ScriptKey,
			},
		)
		require.NoError(t, err)

		f := &proof.File{}
		require.NoError(
			t, f.Decode(bytes.NewReader(exportResp.RawProofFile)),
		)
		lastProof, err := f.LastProof()
		require.NoError(t, err)

		// Check the block height of the proof.
		return lastProof.BlockHeight == uint32(blockHeight)
	}, defaultWaitTimeout, 200*time.Millisecond)
}

// AssertAssetProofs makes sure the proofs for the given asset can be retrieved
// from the given daemon and can be fully validated.
func AssertAssetProofs(t *testing.T, tapClient taprpc.TaprootAssetsClient,
	chainClient chainrpc.ChainKitClient, a *taprpc.Asset) []byte {

	t.Helper()

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	exportResp, err := tapClient.ExportProof(
		ctxt, &taprpc.ExportProofRequest{
			AssetId:   a.AssetGenesis.AssetId,
			ScriptKey: a.ScriptKey,
		},
	)
	require.NoError(t, err)

	file, snapshot := VerifyProofBlob(
		t, tapClient, chainClient, a, exportResp.RawProofFile,
	)

	assetJSON, err := formatProtoJSON(a)
	require.NoError(t, err)
	t.Logf("Got proof file for asset %x that contains %d proof(s), full "+
		"asset: %s", a.AssetGenesis.AssetId, file.NumProofs(),
		assetJSON)

	require.Equal(
		t, CommitmentKey(t, a), snapshot.Asset.AssetCommitmentKey(),
	)

	return exportResp.RawProofFile
}

// AssertProofAltLeaves makes sure that, for a given asset, the latest proof
// commits to an expected set of altLeaves.
func AssertProofAltLeaves(t *testing.T, tapClient taprpc.TaprootAssetsClient,
	a *taprpc.Asset, leafMap map[string][]*asset.Asset) {

	t.Helper()
	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// Fetch the latest proof for the given asset.
	scriptKey := a.ScriptKey
	proofReq := taprpc.ExportProofRequest{
		AssetId:   a.AssetGenesis.AssetId,
		ScriptKey: scriptKey,
	}
	exportResp, err := tapClient.ExportProof(ctxt, &proofReq)
	require.NoError(t, err)

	decodeReq := taprpc.DecodeProofRequest{
		RawProof: exportResp.RawProofFile,
	}
	decodeResp, err := tapClient.DecodeProof(ctxt, &decodeReq)
	require.NoError(t, err)

	// Check if we expect the asset to be anchored alongside alt leaves or
	// not. E.x. a passive asset created inside the freighter will not be
	// anchored with any alt leaves.
	altLeavesBytes := decodeResp.DecodedProof.AltLeaves
	expectedAltLeaves := leafMap[string(scriptKey)]
	emptyAltLeaves := len(expectedAltLeaves) == 0

	// If we expect no alt leaves, there might be alt leaves in the proof,
	// but that is from an asset that wasn't transferred just now. We don't
	// need to check those alt leaves.
	if emptyAltLeaves {
		return
	}

	// If we have altLeaves, decode them and check that they match the
	// expected leaves.
	var (
		r       = bytes.NewReader(altLeavesBytes)
		l       = uint64(len(altLeavesBytes))
		scratch [8]byte
		val     []asset.AltLeaf[asset.Asset]
	)

	require.NoError(t, asset.AltLeavesDecoder(r, &val, &scratch, l))
	asset.CompareAltLeaves(t, asset.ToAltLeaves(expectedAltLeaves), val)
	t.Logf("matching alt leaves for: %v, %x, %x: %d leaves",
		a.ChainAnchor.AnchorOutpoint, a.AssetGenesis.AssetId,
		a.ScriptKey, len(val))
}

// AssertMintingProofs make sure the asset minting proofs contain all the
// correct reveal information.
func AssertMintingProofs(t *testing.T, tapd *tapdHarness,
	requests []*mintrpc.MintAssetRequest, assets []*taprpc.Asset) {

	t.Helper()

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	for idx, a := range assets {
		exportResp, err := tapd.ExportProof(
			ctxt, &taprpc.ExportProofRequest{
				AssetId:   a.AssetGenesis.AssetId,
				ScriptKey: a.ScriptKey,
			},
		)
		require.NoError(t, err)

		// Also make sure that the RPC can verify the proof as well.
		verifyResp, err := tapd.VerifyProof(ctxt, &taprpc.ProofFile{
			RawProofFile: exportResp.RawProofFile,
		})
		require.NoError(t, err)
		require.True(t, verifyResp.Valid)

		// Also make sure that the RPC can decode the proof as well.
		decodeResp, err := tapd.DecodeProof(
			ctxt, &taprpc.DecodeProofRequest{
				RawProof:       exportResp.RawProofFile,
				WithMetaReveal: true,
			},
		)
		require.NoError(t, err)

		expected := requests[idx].Asset
		actual := decodeResp.DecodedProof

		require.NotNil(t, actual.MetaReveal)
		require.Equal(
			t, expected.AssetMeta.Data, actual.MetaReveal.Data,
		)
		require.Equal(
			t, expected.AssetMeta.Type, actual.MetaReveal.Type,
		)
	}
}

// AssertAssetProofsInvalid makes sure the proofs for the given asset can be
// retrieved from the given daemon but fail to validate.
func AssertAssetProofsInvalid(t *testing.T, tapd *tapdHarness,
	a *taprpc.Asset) {

	t.Helper()

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	exportResp, err := tapd.ExportProof(ctxt, &taprpc.ExportProofRequest{
		AssetId:   a.AssetGenesis.AssetId,
		ScriptKey: a.ScriptKey,
	})
	require.NoError(t, err)

	f := &proof.File{}
	require.NoError(t, f.Decode(bytes.NewReader(exportResp.RawProofFile)))

	// Also make sure that the RPC can verify the proof as well.
	verifyResp, err := tapd.VerifyProof(ctxt, &taprpc.ProofFile{
		RawProofFile: exportResp.RawProofFile,
	})
	require.NoError(t, err)
	require.False(t, verifyResp.Valid)
}

// VerifyProofBlob parses the given proof blob into a file, verifies it and
// returns the resulting last asset snapshot together with the parsed file.
func VerifyProofBlob(t *testing.T, tapClient taprpc.TaprootAssetsClient,
	chainClient chainrpc.ChainKitClient, a *taprpc.Asset,
	blob proof.Blob) (*proof.File, *proof.AssetSnapshot) {

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	f := &proof.File{}
	require.NoError(t, f.Decode(bytes.NewReader(blob)))

	// Also make sure that the RPC can verify the proof as well.
	verifyResp, err := tapClient.VerifyProof(ctxt, &taprpc.ProofFile{
		RawProofFile: blob,
	})
	require.NoError(t, err)
	require.True(t, verifyResp.Valid)

	// Also make sure that the RPC can decode the proof as well.
	decodeResp, err := tapClient.DecodeProof(
		ctxt, &taprpc.DecodeProofRequest{
			RawProof: blob,
		},
	)
	require.NoError(t, err)

	require.NotNil(t, decodeResp.DecodedProof)
	AssertAsset(t, a, decodeResp.DecodedProof.Asset)
	proofAsset := decodeResp.DecodedProof.Asset

	// The decoded asset will not include the genesis or group key reveal,
	// so check those separately.
	assertProofReveals(t, proofAsset, decodeResp.DecodedProof)

	// Ensure anchor block height is set.
	anchorTxBlockHeight := proofAsset.ChainAnchor.BlockHeight
	require.Greater(t, anchorTxBlockHeight, uint32(0))

	headerVerifier := func(header wire.BlockHeader, height uint32) error {
		hash := header.BlockHash()

		// Ensure that the block hash matches the hash of the block
		// found at the given height.
		blockHashReq := &chainrpc.GetBlockHashRequest{
			BlockHeight: int64(height),
		}
		blockHashResp, err := chainClient.GetBlockHash(
			ctxb, blockHashReq,
		)
		if err != nil {
			return err
		}

		var heightHash chainhash.Hash
		copy(heightHash[:], blockHashResp.BlockHash)

		expectedHash := hash
		if heightHash != expectedHash {
			return fmt.Errorf("block hash and block height "+
				"mismatch; (height: %d, hashAtHeight: %s, "+
				"expectedHash: %s)", height, heightHash,
				expectedHash)
		}

		// Ensure that the block header corresponds to a block on-chain.
		req := &chainrpc.GetBlockRequest{
			BlockHash: hash.CloneBytes(),
		}
		_, err = chainClient.GetBlock(ctxb, req)
		return err
	}

	groupVerifier := func(groupKey *btcec.PublicKey) error {
		assetGroupKey := hex.EncodeToString(
			groupKey.SerializeCompressed(),
		)

		// The given group key should be listed as a known group.
		assetGroups, err := tapClient.ListGroups(
			ctxt, &taprpc.ListGroupsRequest{},
		)
		require.NoError(t, err)

		_, ok := assetGroups.Groups[assetGroupKey]
		if !ok {
			return fmt.Errorf("group key %s not known",
				assetGroupKey)
		}

		return nil
	}

	vCtx := proof.VerifierCtx{
		HeaderVerifier: headerVerifier,
		MerkleVerifier: proof.DefaultMerkleVerifier,
		GroupVerifier:  groupVerifier,
		ChainLookupGen: proof.MockChainLookup,
	}

	snapshot, err := f.Verify(ctxt, vCtx)
	require.NoError(t, err)

	return f, snapshot
}

// AssertAddrCreated makes sure an address was created correctly for the given
// asset.
func AssertAddrCreated(t *testing.T, client tapClient,
	expected *taprpc.Asset, actual *taprpc.Addr) {

	// Was the address created correctly?
	AssertAddr(t, expected, actual)

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	decoded, err := client.DecodeAddr(ctxt, &taprpc.DecodeAddrRequest{
		Addr: actual.Encoded,
	})
	require.NoError(t, err)

	decodedJSON, err := formatProtoJSON(decoded)
	require.NoError(t, err)
	t.Logf("Got address %s decoded as %v", actual.Encoded, decodedJSON)

	// Does the decoded address still show everything correctly?
	AssertAddr(t, expected, decoded)

	allAddrs, err := client.QueryAddrs(ctxt, &taprpc.QueryAddrRequest{})
	require.NoError(t, err)
	require.NotEmpty(t, allAddrs.Addrs)

	// Can we find the address in the list of all addresses?
	var rpcAddr *taprpc.Addr
	for idx := range allAddrs.Addrs {
		if allAddrs.Addrs[idx].Encoded == actual.Encoded {
			rpcAddr = allAddrs.Addrs[idx]
			break
		}
	}
	require.NotNil(t, rpcAddr)

	// Does the address in the list contain all information we expect?
	AssertAddr(t, expected, rpcAddr)

	// We also make sure we can query the script and internal keys of the
	// address correctly.
	scriptKeyResp, err := client.QueryScriptKey(
		ctxt, &wrpc.QueryScriptKeyRequest{
			TweakedScriptKey: actual.ScriptKey,
		},
	)
	require.NoError(t, err)
	require.NotNil(t, scriptKeyResp.ScriptKey)
	require.NotNil(t, scriptKeyResp.ScriptKey.KeyDesc)
	require.NotNil(t, scriptKeyResp.ScriptKey.KeyDesc.KeyLoc)
	require.EqualValues(
		t, asset.TaprootAssetsKeyFamily,
		scriptKeyResp.ScriptKey.KeyDesc.KeyLoc.KeyFamily,
	)
	require.NotEqual(
		t, scriptKeyResp.ScriptKey.PubKey,
		scriptKeyResp.ScriptKey.KeyDesc.RawKeyBytes,
	)

	internalKeyResp, err := client.QueryInternalKey(
		ctxt, &wrpc.QueryInternalKeyRequest{
			InternalKey: actual.InternalKey,
		},
	)
	require.NoError(t, err)
	require.NotNil(t, internalKeyResp.InternalKey)
	require.NotNil(t, internalKeyResp.InternalKey.KeyLoc)
	require.EqualValues(
		t, asset.TaprootAssetsKeyFamily,
		internalKeyResp.InternalKey.KeyLoc.KeyFamily,
	)
	require.Equal(
		t, actual.InternalKey,
		internalKeyResp.InternalKey.RawKeyBytes,
	)
}

// AssertAddrEvent makes sure the given address was detected by the given
// daemon.
func AssertAddrEvent(t *testing.T, client taprpc.TaprootAssetsClient,
	addr *taprpc.Addr, numEvents int,
	expectedStatus taprpc.AddrEventStatus) {

	AssertAddrEventCustomTimeout(
		t, client, addr, numEvents, expectedStatus, defaultWaitTimeout,
	)
}

// AssertAddrEventCustomTimeout makes sure the given address was detected by
// the given daemon within the given timeout.
func AssertAddrEventCustomTimeout(t *testing.T,
	client taprpc.TaprootAssetsClient, addr *taprpc.Addr, numEvents int,
	expectedStatus taprpc.AddrEventStatus, timeout time.Duration) {

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, timeout)
	defer cancel()

	err := wait.NoError(func() error {
		resp, err := client.AddrReceives(
			ctxt, &taprpc.AddrReceivesRequest{
				FilterAddr: addr.Encoded,
			},
		)
		if err != nil {
			return err
		}

		if len(resp.Events) != numEvents {
			return fmt.Errorf("got %d events, wanted %d",
				len(resp.Events), numEvents)
		}

		if resp.Events[0].Status != expectedStatus {
			return fmt.Errorf("got status %v, wanted %v",
				resp.Events[0].Status, expectedStatus)
		}

		eventJSON, err := formatProtoJSON(resp.Events[0])
		require.NoError(t, err)
		t.Logf("Got address event %s", eventJSON)

		return nil
	}, timeout)
	require.NoError(t, err)
}

// AssertAddrEventByStatus makes sure the given number of events exist with the
// given status.
func AssertAddrEventByStatus(t *testing.T, client taprpc.TaprootAssetsClient,
	filterStatus taprpc.AddrEventStatus, numEvents int) {

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	err := wait.NoError(func() error {
		resp, err := client.AddrReceives(
			ctxt, &taprpc.AddrReceivesRequest{
				FilterStatus: filterStatus,
			},
		)
		require.NoError(t, err)

		if len(resp.Events) != numEvents {
			return fmt.Errorf("got %d events, wanted %d",
				len(resp.Events), numEvents)
		}

		for _, event := range resp.Events {
			if event.Status != filterStatus {
				return fmt.Errorf("got status %v, wanted %v",
					resp.Events[0].Status, filterStatus)
			}
		}

		return nil
	}, defaultWaitTimeout/2)
	require.NoError(t, err)
}

// AssertReceiveEvents makes sure all events with incremental status are sent
// on the stream for the given address.
func AssertReceiveEvents(t *testing.T, addr *taprpc.Addr,
	stream *EventSubscription[*taprpc.ReceiveEvent]) {

	success := make(chan struct{})
	timeout := time.After(defaultWaitTimeout)
	startStatus := statusDetected

	// To make sure we don't forever hang on receiving on the stream, we'll
	// cancel it after the timeout.
	go func() {
		select {
		case <-timeout:
			stream.Cancel()

		case <-success:
		}
	}()

	for {
		event, err := stream.Recv()
		require.NoError(t, err, "receiving address receive event")

		require.True(t, proto.Equal(event.Address, addr))
		require.Equal(t, startStatus, event.Status)
		require.Empty(t, event.Error)

		if event.Status == statusCompleted {
			close(success)
			stream.Cancel()

			return
		}

		startStatus++
	}
}

// makeFilterSendEventScriptKey returns a filter function that checks if the
// given script key is present in the send event. If it is, the event is
// included in the stream.
func makeFilterSendEventScriptKey(
	scriptKey btcec.PublicKey) func(*taprpc.SendEvent) (bool, error) {

	return func(event *taprpc.SendEvent) (bool, error) {
		for _, vPacketBytes := range event.VirtualPackets {
			vPkt, err := tappsbt.Decode(vPacketBytes)
			if err != nil {
				return false, err
			}

			for _, vOut := range vPkt.Outputs {
				if vOut.ScriptKey.PubKey == nil {
					continue
				}

				// This packet sends to the filtered script key,
				// we want to include this event.
				if vOut.ScriptKey.PubKey.IsEqual(&scriptKey) {
					return true, nil
				}
			}
		}

		return false, nil
	}
}

// AssertSendEventsComplete makes sure the two remaining events for the given
// script key are sent on the stream.
func AssertSendEventsComplete(t *testing.T, scriptKey []byte,
	stream *EventSubscription[*taprpc.SendEvent]) {

	AssertSendEvents(
		t, scriptKey, stream, tapfreighter.SendStateWaitTxConf,
		tapfreighter.SendStateComplete,
	)
}

// AssertSendEvents makes sure all events with incremental status are sent
// on the stream for the given script key.
func AssertSendEvents(t *testing.T, targetScriptKey []byte,
	stream *EventSubscription[*taprpc.SendEvent], from,
	to tapfreighter.SendState) {

	success := make(chan struct{})
	timeout := time.After(defaultWaitTimeout)
	expectedStatus := from

	// By default, if the target script key is not given we will accept all
	// send events.
	sendsToKey := func(*taprpc.SendEvent) (bool, error) {
		return true, nil
	}

	// If a target script key is given, we will only accept send events that
	// relate to that key.
	if targetScriptKey != nil {
		targetScriptKey, err := btcec.ParsePubKey(targetScriptKey)
		require.NoError(t, err)

		sendsToKey = makeFilterSendEventScriptKey(*targetScriptKey)
	}

	// To make sure we don't forever hang on receiving on the stream, we'll
	// cancel it after the timeout.
	go func() {
		select {
		case <-timeout:
			t.Logf("AssertSendEvents: cancelling stream after " +
				"timeout")
			stream.Cancel()

		case <-success:
		}
	}()

	for {
		event, err := stream.Recv()
		require.NoError(t, err, "receiving send event")

		// Ensure that the event complies with the target script key
		// check.
		res, err := sendsToKey(event)
		require.NoError(t, err)
		require.True(t, res)

		// Check the event's error field for unexpected errors. Perform
		// this check before verifying the expected send state, as
		// errors might occur alongside an out-of-order send state.
		require.Emptyf(
			t, event.Error, "send event error: %x", event,
		)
		require.Equal(t, expectedStatus.String(), event.SendState)

		// Fully close the stream once we definitely no longer need the
		// stream.
		if event.SendState == tapfreighter.SendStateComplete.String() {
			stream.Cancel()
		}

		if event.SendState == to.String() {
			close(success)
			return
		}

		expectedStatus++
	}
}

// AssertMintEvents makes sure all events with incremental status are sent
// on the stream for the given minting batch.
func AssertMintEvents(t *testing.T, batchKey []byte,
	stream *EventSubscription[*mintrpc.MintEvent]) {

	success := make(chan struct{})
	timeout := time.After(defaultWaitTimeout)
	startStatus := batchFrozen

	// To make sure we don't forever hang on receiving on the stream, we'll
	// cancel it after the timeout.
	go func() {
		select {
		case <-timeout:
			stream.Cancel()

		case <-success:
		}
	}()

	for {
		event, err := stream.Recv()
		require.NoError(t, err, "receiving mint event")

		require.Equal(t, batchKey, event.Batch.BatchKey)
		require.Equal(t, startStatus, event.BatchState)
		require.Empty(t, event.Error)

		if event.BatchState == batchFinalized {
			close(success)
			stream.Cancel()

			return
		}

		startStatus++
	}
}

// ConfirmAndAssertOutboundTransfer makes sure the given outbound transfer has
// the correct state before confirming it and then asserting the confirmed state
// with the node.
func ConfirmAndAssertOutboundTransfer(t *testing.T,
	minerClient *rpcclient.Client, sender commands.RpcClientsBundle,
	sendResp *taprpc.SendAssetResponse, assetID []byte,
	expectedAmounts []uint64, currentTransferIdx,
	numTransfers int) *wire.MsgBlock {

	return ConfirmAndAssertOutboundTransferWithOutputs(
		t, minerClient, sender, sendResp, assetID, expectedAmounts,
		currentTransferIdx, numTransfers, 2,
	)
}

// ConfirmAndAssertOutboundTransferWithOutputs makes sure the given outbound
// transfer has the correct state and number of outputs before confirming it and
// then asserting the confirmed state with the node.
func ConfirmAndAssertOutboundTransferWithOutputs(t *testing.T,
	minerClient *rpcclient.Client, sender commands.RpcClientsBundle,
	sendResp *taprpc.SendAssetResponse, assetID []byte,
	expectedAmounts []uint64, currentTransferIdx,
	numTransfers, numOutputs int) *wire.MsgBlock {

	return AssertAssetOutboundTransferWithOutputs(
		t, minerClient, sender, sendResp.Transfer, assetID,
		expectedAmounts, currentTransferIdx, numTransfers, numOutputs,
		true,
	)
}

// AssertAssetOutboundTransferWithOutputs makes sure the given outbound transfer
// has the correct state and number of outputs.
func AssertAssetOutboundTransferWithOutputs(t *testing.T,
	minerClient *rpcclient.Client, sender commands.RpcClientsBundle,
	transfer *taprpc.AssetTransfer, assetID []byte,
	expectedAmounts []uint64, currentTransferIdx,
	numTransfers, numOutputs int, confirm bool) *wire.MsgBlock {

	ctxb := context.Background()

	// Check that we now have two new outputs, and that they differ
	// in outpoints and scripts.
	outputs := transfer.Outputs
	require.Len(t, outputs, numOutputs)

	outpoints := make(map[string]struct{})
	scripts := make(map[string]struct{})
	for _, o := range outputs {
		// Ensure that each transfer output script key is unique.
		_, ok := scripts[string(o.ScriptKey)]
		require.False(t, ok)

		outpoints[o.Anchor.Outpoint] = struct{}{}
		scripts[string(o.ScriptKey)] = struct{}{}
	}

	sendRespJSON, err := formatProtoJSON(transfer)
	require.NoError(t, err)
	t.Logf("Got response from sending assets: %v", sendRespJSON)

	// Mine a block to force the send event to complete (confirm on-chain).
	var newBlock *wire.MsgBlock
	if confirm {
		newBlock = MineBlocks(t, minerClient, 1, 1)[0]
	}

	// Confirm that we can externally view the transfer.
	require.Eventually(t, func() bool {
		resp, err := sender.ListTransfers(
			ctxb, &taprpc.ListTransfersRequest{},
		)
		require.NoError(t, err)
		require.Len(t, resp.Transfers, numTransfers)

		// Assert the new outpoint, script and amount is in the
		// list.
		transfer := resp.Transfers[currentTransferIdx]
		require.Len(t, transfer.Outputs, numOutputs)
		require.Len(t, expectedAmounts, numOutputs)
		for idx := range transfer.Outputs {
			out := transfer.Outputs[idx]
			require.Contains(t, outpoints, out.Anchor.Outpoint)
			require.Contains(t, scripts, string(out.ScriptKey))
			require.Equalf(
				t, expectedAmounts[idx], out.Amount,
				"expected amounts: %v, transfer: %v",
				expectedAmounts, toJSON(t, transfer))
		}

		firstIn := transfer.Inputs[0]
		return bytes.Equal(firstIn.AssetId, assetID)
	}, defaultTimeout, wait.PollInterval)
	require.NoError(t, err)

	transferResp, err := sender.ListTransfers(
		ctxb, &taprpc.ListTransfersRequest{},
	)
	require.NoError(t, err)

	transferRespJSON, err := formatProtoJSON(transferResp)
	require.NoError(t, err)
	t.Logf("Got response from list transfers: %v", transferRespJSON)

	return newBlock
}

// AssertNonInteractiveRecvComplete makes sure the given receiver has the
// correct number of completed non-interactive inbound asset transfers in their
// list of events.
func AssertNonInteractiveRecvComplete(t *testing.T,
	receiver taprpc.TaprootAssetsClient, totalInboundTransfers int) {

	// And finally, they should be marked as completed with a proof
	// available.
	err := wait.NoError(func() error {
		ctxb := context.Background()
		ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout/2)
		defer cancel()

		resp, err := receiver.AddrReceives(
			ctxt, &taprpc.AddrReceivesRequest{},
		)
		require.NoError(t, err)
		require.Len(t, resp.Events, totalInboundTransfers)

		for _, event := range resp.Events {
			if event.Status != statusCompleted {
				return fmt.Errorf("got status %v, wanted %v",
					event.Status, statusCompleted)
			}

			if !event.HasProof {
				return fmt.Errorf("wanted proof, but was false")
			}
		}

		return nil
	}, defaultWaitTimeout)
	require.NoError(t, err)
}

// AssertAddr asserts that an address contains the correct information of an
// asset.
func AssertAddr(t *testing.T, expected *taprpc.Asset, actual *taprpc.Addr) {
	require.Equal(t, expected.AssetGenesis.AssetId, actual.AssetId)
	require.Equal(t, expected.AssetGenesis.AssetType, actual.AssetType)

	if expected.AssetGroup == nil {
		require.Nil(t, actual.GroupKey)
	} else {
		require.Equal(
			t, expected.AssetGroup.TweakedGroupKey, actual.GroupKey,
		)
	}

	// The script key must explicitly NOT be the same, as that would lead
	// to a collision with assets that have a group key.
	require.NotEqual(t, expected.ScriptKey, actual.ScriptKey)
}

// AssertAsset asserts that two taprpc.Asset objects are equal, ignoring
// node-specific fields like if script keys are local, if the asset is spent,
// or if the anchor information is populated.
func AssertAsset(t *testing.T, expected, actual *taprpc.Asset) {
	require.Equal(t, expected.Version, actual.Version)
	AssertAssetGenesis(t, expected.AssetGenesis, actual.AssetGenesis)
	require.Equal(
		t, expected.AssetGenesis.AssetType,
		actual.AssetGenesis.AssetType,
	)
	require.Equal(t, expected.Amount, actual.Amount)
	require.Equal(t, expected.LockTime, actual.LockTime)
	require.Equal(t, expected.RelativeLockTime, actual.RelativeLockTime)
	require.Equal(t, expected.ScriptVersion, actual.ScriptVersion)
	require.Equal(t, expected.ScriptKey, actual.ScriptKey)
	require.Equal(t, expected.AssetGroup == nil, actual.AssetGroup == nil)
	require.Equal(t, expected.PrevWitnesses, actual.PrevWitnesses)

	// The raw key isn't always set as that's not contained in proofs for
	// example.
	if expected.AssetGroup != nil {
		require.Equal(
			t, expected.AssetGroup.TweakedGroupKey,
			actual.AssetGroup.TweakedGroupKey,
		)
	}
}

func assertProofReveals(t *testing.T, expected *taprpc.Asset,
	actual *taprpc.DecodedProof) {

	if actual.GenesisReveal != nil {
		require.Equal(
			t, expected.AssetGenesis,
			actual.GenesisReveal.GenesisBaseReveal,
		)
		require.Equal(
			t, expected.AssetGenesis.AssetType,
			actual.GenesisReveal.GenesisBaseReveal.AssetType,
		)
	}
}

// AssertAssetGenesis asserts that two taprpc.GenesisInfo objects are equal.
func AssertAssetGenesis(t *testing.T, expected, actual *taprpc.GenesisInfo) {
	require.Equal(t, expected.GenesisPoint, actual.GenesisPoint)
	require.Equal(t, expected.Name, actual.Name)
	require.Equal(t, expected.MetaHash, actual.MetaHash)
	require.Equal(t, expected.AssetId, actual.AssetId)
	require.Equal(t, expected.OutputIndex, actual.OutputIndex)
}

// AssertBalanceByID asserts that the balance of a single asset,
// specified by ID, on the given daemon is correct.
func AssertBalanceByID(t *testing.T, client taprpc.TaprootAssetsClient,
	id []byte, amt uint64) {

	require.Eventually(t, func() bool {
		ctxb := context.Background()
		balancesResp, err := client.ListBalances(
			ctxb, &taprpc.ListBalancesRequest{
				GroupBy: &taprpc.ListBalancesRequest_AssetId{
					AssetId: true,
				},
				AssetFilter:   id,
				ScriptKeyType: allScriptKeysQuery,
			},
		)
		if err != nil {
			t.Logf("error listing balances: %v", err)
			return false
		}

		// nolint: lll
		balance, ok := balancesResp.AssetBalances[hex.EncodeToString(id)]
		if amt == 0 {
			require.False(t, ok)
			return true
		}

		if !ok {
			t.Logf("balance for asset not found (asset_id=%x)", id)
			return false
		}

		if balance.Balance != amt {
			t.Logf("balance mismatch for asset (asset_id=%x, "+
				"expected=%d, actual=%d)", id, amt,
				balance.Balance)
			return false
		}

		return true
	}, defaultWaitTimeout, time.Second)
}

// AssertBalanceByGroup asserts that the balance of a single asset group
// on the given daemon is correct.
func AssertBalanceByGroup(t *testing.T, client taprpc.TaprootAssetsClient,
	hexGroupKey string, amt uint64) {

	t.Helper()

	groupKey, err := hex.DecodeString(hexGroupKey)
	require.NoError(t, err)

	ctxb := context.Background()
	balancesResp, err := client.ListBalances(
		ctxb, &taprpc.ListBalancesRequest{
			GroupBy: &taprpc.ListBalancesRequest_GroupKey{
				GroupKey: true,
			},
			GroupKeyFilter: groupKey,
		},
	)
	require.NoError(t, err)

	balance, ok := balancesResp.AssetGroupBalances[hexGroupKey]
	require.True(t, ok)
	require.Equal(t, amt, balance.Balance)
}

// AssertTransfer asserts that the value of each transfer initiated on the
// given daemon is correct.
func AssertTransfer(t *testing.T, client taprpc.TaprootAssetsClient,
	transferIdx, numTransfers int, outputAmounts []uint64) {

	ctxb := context.Background()
	transferResp, err := client.ListTransfers(
		ctxb, &taprpc.ListTransfersRequest{},
	)
	require.NoError(t, err)
	require.Len(t, transferResp.Transfers, numTransfers)

	transfer := transferResp.Transfers[transferIdx]
	require.Len(t, transfer.Outputs, len(outputAmounts))
	for i := range transfer.Outputs {
		require.Equal(t, outputAmounts[i], transfer.Outputs[i].Amount)
	}
}

// AssertSplitTombstoneTransfer asserts that there is a transfer for the given
// asset ID that is a split that left over a tombstone output.
func AssertSplitTombstoneTransfer(t *testing.T,
	client taprpc.TaprootAssetsClient, id []byte) {

	ctxb := context.Background()
	transferResp, err := client.ListTransfers(
		ctxb, &taprpc.ListTransfersRequest{},
	)
	require.NoError(t, err)
	require.NotEmpty(t, transferResp.Transfers)

	tombstoneFound := false
	for _, transfer := range transferResp.Transfers {
		if !bytes.Equal(transfer.Inputs[0].AssetId, id) {
			continue
		}

		for _, out := range transfer.Outputs {
			if out.Amount != 0 {
				continue
			}

			// A zero amount output is a tombstone output.
			tombstoneFound = true
			require.Equal(t, asset.NUMSBytes, out.ScriptKey)
			require.False(t, out.ScriptKeyIsLocal)
			require.NotEmpty(t, out.SplitCommitRootHash)
		}
	}

	require.True(t, tombstoneFound, "no tombstone output found")
}

// AssertNumGroups asserts that the number of groups the daemon is aware of
// is correct.
func AssertNumGroups(t *testing.T, client taprpc.TaprootAssetsClient,
	num int) {

	require.Equal(t, num, NumGroups(t, client))
}

// AssertNumBurns makes sure a given number of burns exists, then returns them.
func AssertNumBurns(t *testing.T, client taprpc.TaprootAssetsClient,
	num int, req *taprpc.ListBurnsRequest) []*taprpc.AssetBurn {

	ctxb := context.Background()
	if req == nil {
		req = &taprpc.ListBurnsRequest{}
	}

	var result []*taprpc.AssetBurn
	err := wait.NoError(func() error {
		burns, err := client.ListBurns(ctxb, req)
		if err != nil {
			return err
		}

		if len(burns.Burns) != num {
			return fmt.Errorf("wanted %d burns, got %d", num,
				len(burns.Burns))
		}

		result = burns.Burns

		return nil
	}, defaultTimeout)
	require.NoError(t, err)

	return result
}

// NumGroups returns the current number of asset groups present.
func NumGroups(t *testing.T, client taprpc.TaprootAssetsClient) int {
	ctxb := context.Background()
	groupResp, err := client.ListGroups(
		ctxb, &taprpc.ListGroupsRequest{},
	)
	require.NoError(t, err)
	return len(groupResp.Groups)
}

// AssertGroupSizes asserts that a set of groups the daemon is aware of contain
// the expected number of assets.
func AssertGroupSizes(t *testing.T, client taprpc.TaprootAssetsClient,
	hexGroupKeys []string, sizes []int) {

	ctxb := context.Background()
	groupResp, err := client.ListGroups(
		ctxb, &taprpc.ListGroupsRequest{},
	)
	require.NoError(t, err)

	for i, key := range hexGroupKeys {
		groupAssets, ok := groupResp.Groups[key]
		require.True(t, ok)
		require.Equal(t, sizes[i], len(groupAssets.Assets))
	}
}

// AssertGroup asserts that an asset returned from the ListGroups call matches
// a specific asset and has the same group key.
func AssertGroup(t *testing.T, a *taprpc.Asset, b *taprpc.AssetHumanReadable,
	groupKey []byte) {

	require.Equal(t, a.AssetGenesis.AssetId, b.Id)
	require.Equal(t, a.Amount, b.Amount)
	require.Equal(t, a.LockTime, b.LockTime)
	require.Equal(t, a.RelativeLockTime, b.RelativeLockTime)
	require.Equal(t, a.AssetGenesis.Name, b.Tag)
	require.Equal(t, a.AssetGenesis.MetaHash, b.MetaHash)
	require.Equal(t, a.AssetGenesis.AssetType, b.Type)
	require.Equal(t, a.AssetGroup.TweakedGroupKey, groupKey)
}

// AssertGroupAnchor asserts that a specific asset genesis was used to create
// a tweaked group key.
func AssertGroupAnchor(t *testing.T, anchorGen *asset.Genesis,
	anchorGroup *taprpc.AssetGroup) {

	internalPubKey, err := btcec.ParsePubKey(anchorGroup.RawGroupKey)
	require.NoError(t, err)

	// TODO(jhb): add tapscript root support
	anchorTweak := anchorGen.ID()
	computedGroupPubKey, err := asset.GroupPubKeyV0(
		internalPubKey, anchorTweak[:], nil,
	)
	require.NoError(t, err)

	computedGroupKey := computedGroupPubKey.SerializeCompressed()
	require.Equal(t, anchorGroup.TweakedGroupKey, computedGroupKey)
}

// MatchRpcAsset is a function that returns true if the given RPC asset is a
// match.
type MatchRpcAsset func(asset *taprpc.Asset) bool

// AssertListAssets checks that the assets returned by ListAssets match the
// expected assets.
func AssertListAssets(t *testing.T, ctx context.Context,
	client taprpc.TaprootAssetsClient, matchAssets []MatchRpcAsset) {

	resp := AssertNumAssets(t, ctx, client, len(matchAssets))

	// Match each asset returned by the daemon against the expected assets.
	for _, a := range resp.Assets {
		assetMatched := false
		for _, match := range matchAssets {
			if match(a) {
				assetMatched = true
				break
			}
		}
		require.True(t, assetMatched, "asset not matched: %v", a)
	}
}

// AssertNumAssets check the number of assets returned by ListAssets.
func AssertNumAssets(t *testing.T, ctx context.Context,
	client taprpc.TaprootAssetsClient,
	numAssets int) *taprpc.ListAssetResponse {

	resp, err := client.ListAssets(ctx, &taprpc.ListAssetRequest{})
	require.NoError(t, err)

	// Ensure that the number of assets returned is correct.
	require.Len(t, resp.Assets, numAssets)

	return resp
}

// AssertUniverseRootEquality checks that the universe roots returned by two
// daemons are either equal or not, depending on the expectedEquality parameter.
func AssertUniverseRootEquality(t *testing.T,
	clientA, clientB unirpc.UniverseClient, expectedEquality bool) {

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	rootRequest := &unirpc.AssetRootRequest{}
	universeRootsAlice, err := clientA.AssetRoots(ctxt, rootRequest)
	require.NoError(t, err)
	universeRootsBob, err := clientB.AssetRoots(ctxt, rootRequest)
	require.NoError(t, err)
	require.Equal(t, expectedEquality, AssertUniverseRootsEqual(
		universeRootsAlice, universeRootsBob,
	))
}

// AssertUniverseRootEqualityEventually checks that the universe roots returned
// by two daemons are either equal eventually.
func AssertUniverseRootEqualityEventually(t *testing.T,
	clientA, clientB unirpc.UniverseClient) {

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	err := wait.NoError(func() error {
		rootRequest := &unirpc.AssetRootRequest{}
		universeRootsAlice, err := clientA.AssetRoots(ctxt, rootRequest)
		require.NoError(t, err)
		universeRootsBob, err := clientB.AssetRoots(ctxt, rootRequest)
		require.NoError(t, err)

		if !AssertUniverseRootsEqual(
			universeRootsAlice, universeRootsBob,
		) {

			return fmt.Errorf("roots not equal")
		}

		return nil
	}, defaultWaitTimeout)
	require.NoError(t, err)
}

// AssertUniverseRoot makes sure the given universe root exists with the given
// sum, either identified by the asset ID or group key.
func AssertUniverseRoot(t *testing.T, client unirpc.UniverseClient,
	sum int, assetID []byte, groupKey []byte) {

	bothSet := assetID != nil && groupKey != nil
	neitherSet := assetID == nil && groupKey == nil
	require.False(
		t, bothSet || neitherSet, "only set one of assetID or groupKey",
	)

	// Comparing the asset ID is always safe, even if nil.
	matchingRoot := func(root *unirpc.UniverseRoot) bool {
		sumEqual := root.MssmtRoot.RootSum == int64(sum)
		idEqual := bytes.Equal(root.Id.GetAssetId(), assetID)
		groupKeyEqual := true
		if groupKey != nil {
			parsedGroupKey, err := btcec.ParsePubKey(groupKey)
			require.NoError(t, err)

			rootGroupKey := root.Id.GetGroupKey()
			if rootGroupKey != nil {
				groupKeyEqual = bytes.Equal(
					rootGroupKey, schnorr.SerializePubKey(
						parsedGroupKey,
					),
				)
			}
		}

		return sumEqual && idEqual && groupKeyEqual
	}

	ctx := context.Background()

	uniRoots, err := client.AssetRoots(ctx, &unirpc.AssetRootRequest{})
	require.NoError(t, err)

	correctRoot := fn.Any(maps.Values(uniRoots.UniverseRoots), matchingRoot)
	require.True(t, correctRoot)
}

func AssertUniverseRootEqual(a, b *unirpc.UniverseRoot) bool {
	// Basic RPC form sanity checks.
	if (a.Id != nil && b.Id == nil) || (a.Id == nil && b.Id != nil) {
		return false
	}

	// The ids should batch exactly.
	if !reflect.DeepEqual(a.Id.Id, b.Id.Id) {
		return false
	}

	// The sum and root hash should also match for the SMT root itself.
	if !bytes.Equal(a.MssmtRoot.RootHash, b.MssmtRoot.RootHash) {
		return false
	}
	if a.MssmtRoot.RootSum != b.MssmtRoot.RootSum {
		return false
	}

	return true
}

func AssertUniverseRootsEqual(a, b *unirpc.AssetRootResponse) bool {
	// The set of keys in the maps should match exactly, as this means the
	// same set of asset IDs are being tracked.
	uniKeys := maps.Keys(a.UniverseRoots)
	if len(a.UniverseRoots) != len(b.UniverseRoots) {
		return false
	}
	if !fn.All(uniKeys, func(key string) bool {
		_, ok := b.UniverseRoots[key]
		return ok
	}) {

		return false
	}

	// Now that we know the same set of assets are being tracked, we'll
	// ensure that the root values are also the same.
	for uniID := range a.UniverseRoots {
		rootA, ok := a.UniverseRoots[uniID]
		if !ok {
			return false
		}

		rootB, ok := b.UniverseRoots[uniID]
		if !ok {
			return false
		}

		return AssertUniverseRootEqual(rootA, rootB)
	}

	return true
}

func AssertUniverseStateEqual(t *testing.T, a, b unirpc.UniverseClient) bool {
	ctxb := context.Background()

	rootsA, err := assetRoots(ctxb, a, universe.RequestPageSize/100)
	require.NoError(t, err)

	rootsB, err := assetRoots(ctxb, b, universe.RequestPageSize/100)
	require.NoError(t, err)

	return AssertUniverseRootsEqual(rootsA, rootsB)
}

func AssertUniverseLeavesEqual(t *testing.T, uniIDs []*unirpc.ID,
	a, b unirpc.UniverseClient) {

	for _, uniID := range uniIDs {
		aLeaves, err := a.AssetLeaves(context.Background(), uniID)
		require.NoError(t, err)

		bLeaves, err := b.AssetLeaves(context.Background(), uniID)
		require.NoError(t, err)

		require.Equal(t, len(aLeaves.Leaves), len(bLeaves.Leaves))

		for i := 0; i < len(aLeaves.Leaves); i++ {
			require.Equal(
				t, aLeaves.Leaves[i].Asset,
				bLeaves.Leaves[i].Asset,
			)

			require.Equal(
				t, aLeaves.Leaves[i].Proof,
				bLeaves.Leaves[i].Proof,
			)
		}
	}
}

func AssertUniverseKeysEqual(t *testing.T, uniIDs []*unirpc.ID,
	a, b unirpc.UniverseClient) {

	for _, uniID := range uniIDs {
		aUniKeys, err := a.AssetLeafKeys(
			context.Background(),
			&unirpc.AssetLeafKeysRequest{
				Id: uniID,
			},
		)
		require.NoError(t, err)

		bUniKeys, err := b.AssetLeafKeys(
			context.Background(),
			&unirpc.AssetLeafKeysRequest{
				Id: uniID,
			},
		)
		require.NoError(t, err)

		require.Equal(
			t, len(aUniKeys.AssetKeys), len(bUniKeys.AssetKeys),
		)

		for i := 0; i < len(aUniKeys.AssetKeys); i++ {
			require.Equal(
				t, aUniKeys.AssetKeys[i], bUniKeys.AssetKeys[i],
			)
		}
	}
}

func AssertUniverseStats(t *testing.T, client unirpc.UniverseClient,
	numProofs, numAssets, numGroups int) {

	err := wait.NoError(func() error {
		uniStats, err := client.UniverseStats(
			context.Background(), &unirpc.StatsRequest{},
		)
		if err != nil {
			return err
		}

		if numProofs != int(uniStats.NumTotalProofs) {
			return fmt.Errorf("expected %v proofs, got %v",
				numProofs, uniStats.NumTotalProofs)
		}
		if numAssets != int(uniStats.NumTotalAssets) {
			return fmt.Errorf("expected %v assets, got %v",
				numAssets, uniStats.NumTotalAssets)
		}
		if numGroups != int(uniStats.NumTotalGroups) {
			return fmt.Errorf("expected %v groups, got %v",
				numGroups, uniStats.NumTotalGroups)
		}

		return nil
	}, defaultTimeout)
	require.NoError(t, err)
}

func AssertUniverseAssetStats(t *testing.T, node *tapdHarness,
	assets []*taprpc.Asset) {

	ctxb := context.Background()
	assetStats, err := node.QueryAssetStats(ctxb, &unirpc.AssetStatsQuery{})
	require.NoError(t, err)
	require.Len(t, assetStats.AssetStats, len(assets))

	for _, assetStat := range assetStats.AssetStats {
		var statAsset *unirpc.AssetStatsAsset
		if assetStat.GroupAnchor != nil {
			statAsset = assetStat.GroupAnchor
		} else {
			statAsset = assetStat.Asset
		}

		found := fn.Any(assets, func(a *taprpc.Asset) bool {
			groupKeyEqual := true
			if a.AssetGroup != nil {
				groupKeyEqual = bytes.Equal(
					assetStat.GroupKey,
					a.AssetGroup.TweakedGroupKey,
				)
			}

			return groupKeyEqual && bytes.Equal(
				statAsset.AssetId, a.AssetGenesis.AssetId,
			)
		})
		require.True(t, found)

		require.NotZero(t, statAsset.GenesisHeight)
		require.NotZero(t, statAsset.GenesisTimestamp)
		require.NotEmpty(t, statAsset.GenesisPoint)
		require.NotEmpty(t, statAsset.AnchorPoint)
		require.NotEqual(
			t, statAsset.GenesisPoint, statAsset.AnchorPoint,
		)
	}

	eventStats, err := node.QueryEvents(ctxb, &unirpc.QueryEventsRequest{})
	require.NoError(t, err)

	todayStr := time.Now().UTC().Format("2006-01-02")
	require.Len(t, eventStats.Events, 1)

	s := eventStats.Events[0]
	require.Equal(t, todayStr, s.Date)
	require.EqualValues(t, len(assets), s.NewProofEvents)
}

// VerifyGroupAnchor verifies that the correct asset was used as the group
// anchor by re-deriving the group key.
func VerifyGroupAnchor(t *testing.T, assets []*taprpc.Asset,
	anchorName string) *taprpc.Asset {

	anchor, err := fn.First(
		assets, func(asset *taprpc.Asset) bool {
			return asset.AssetGenesis.Name == anchorName
		},
	)
	require.NoError(t, err)

	anchorGen := ParseGenInfo(t, anchor.AssetGenesis)
	anchorGen.Type = asset.Type(anchor.AssetGenesis.AssetType)
	AssertGroupAnchor(t, anchorGen, anchor.AssetGroup)

	return anchor
}

// AssertAssetsMinted makes sure all assets in the minting request were in fact
// minted in the given anchor TX and block. The function returns the list of
// minted assets.
func AssertAssetsMinted(t *testing.T, tapClient commands.RpcClientsBundle,
	assetRequests []*mintrpc.MintAssetRequest, mintTXID,
	blockHash chainhash.Hash) []*taprpc.Asset {

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// The rest of the anchor information should now be populated as well.
	// We also check that the anchor outpoint of all assets is the same,
	// since they were all minted in the same batch.
	var (
		firstOutpoint string
		assetList     []*taprpc.Asset
	)

	listRespConfirmed, err := tapClient.ListAssets(
		ctxt, &taprpc.ListAssetRequest{
			ScriptKeyType: allScriptKeysQuery,
		},
	)
	require.NoError(t, err)
	confirmedAssets := GroupAssetsByName(listRespConfirmed.Assets)

	for _, assetRequest := range assetRequests {
		validMetaType, err := proof.IsValidMetaType(
			assetRequest.Asset.AssetMeta.Type,
		)
		require.NoError(t, err)

		metaReveal := &proof.MetaReveal{
			Data: assetRequest.Asset.AssetMeta.Data,
			Type: validMetaType,
		}
		err = metaReveal.SetDecDisplay(
			assetRequest.Asset.DecimalDisplay,
		)
		require.NoError(t, err)

		metaHash := metaReveal.MetaHash()

		mintedAsset := AssertAssetState(
			t, confirmedAssets, assetRequest.Asset.Name,
			metaHash[:],
			AssetAnchorCheck(mintTXID, blockHash),
			AssetScriptKeyIsLocalCheck(true),
			AssetVersionCheck(assetRequest.Asset.AssetVersion),
			func(a *taprpc.Asset) error {
				anchor := a.ChainAnchor

				if anchor.AnchorOutpoint == "" {
					return fmt.Errorf("missing anchor " +
						"outpoint")
				}

				if firstOutpoint == "" {
					firstOutpoint = anchor.AnchorOutpoint

					return nil
				}

				if anchor.AnchorOutpoint != firstOutpoint {
					return fmt.Errorf("unexpected anchor "+
						"outpoint, got %v wanted %v",
						anchor.AnchorOutpoint,
						firstOutpoint)
				}

				if anchor.BlockHeight == 0 {
					return fmt.Errorf("missing block " +
						"height")
				}

				return nil
			},
			AssetScriptKeyCheck(assetRequest.Asset.ScriptKey),
			AssetIsGroupedCheck(
				assetRequest.Asset.NewGroupedAsset,
				assetRequest.Asset.GroupedAsset,
			),
			AssetGroupTapscriptRootCheck(
				assetRequest.Asset.GroupTapscriptRoot,
			),
			AssetDecimalDisplayCheck(
				assetRequest.Asset.DecimalDisplay,
			),
		)

		assetList = append(assetList, mintedAsset)
	}

	return assetList
}

func AssertGenesisOutput(t *testing.T, output *taprpc.ManagedUtxo,
	sibling commitment.TapscriptPreimage) {

	// Fetch the encoded tapscript sibling from an anchored asset, and check
	// it against the expected sibling.
	require.True(t, len(output.Assets) > 1)
	rpcSibling := output.Assets[0].ChainAnchor.TapscriptSibling
	require.True(t, fn.All(output.Assets, func(a *taprpc.Asset) bool {
		return bytes.Equal(a.ChainAnchor.TapscriptSibling, rpcSibling)
	}))
	encodedSibling, siblingHash, err := commitment.
		MaybeEncodeTapscriptPreimage(&sibling)
	require.NoError(t, err)
	require.Equal(t, encodedSibling, rpcSibling)

	// We should be able to recompute a merkle root from the tapscript
	// sibling hash and the Taproot Asset Commitment root that matches what
	// is stored in the managed output.
	expectedMerkleRoot := asset.NewTapBranchHash(
		(chainhash.Hash)(output.TaprootAssetRoot), *siblingHash,
	)
	require.Equal(t, expectedMerkleRoot[:], output.MerkleRoot)
}

func AssertMintedAssetBalances(t *testing.T, client taprpc.TaprootAssetsClient,
	simpleAssets, issuableAssets []*taprpc.Asset, includeLeased bool) {

	t.Helper()

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// First, we'll ensure that we're able to get the balances of all the
	// assets grouped by their asset IDs.
	assetIDBalances, err := client.ListBalances(
		ctxt, &taprpc.ListBalancesRequest{
			GroupBy:       groupBalancesByAssetID,
			IncludeLeased: includeLeased,
		},
	)
	require.NoError(t, err)

	var allAssets []*taprpc.Asset
	allAssets = append(allAssets, simpleAssets...)
	allAssets = append(allAssets, issuableAssets...)

	require.Equal(t, len(allAssets), len(assetIDBalances.AssetBalances))

	var totalBalance uint64
	for _, balance := range assetIDBalances.AssetBalances {
		totalBalance += balance.Balance
		for _, rpcAsset := range allAssets {
			balanceGen := balance.AssetGenesis
			targetGen := rpcAsset.AssetGenesis

			if balanceGen.Name == targetGen.Name {
				require.Equal(
					t, balance.Balance, rpcAsset.Amount,
				)

				require.Equal(
					t,
					rpcAsset.AssetGenesis,
					balance.AssetGenesis,
				)
			}
		}
	}

	// We should also ensure that the total balance returned by
	// `ListBalances` matches the total balance returned by `ListAssets`.
	assetList, err := client.ListAssets(ctxt, &taprpc.ListAssetRequest{
		IncludeLeased: includeLeased,
	})
	require.NoError(t, err)

	var totalAssetListBalance uint64
	for _, a := range assetList.Assets {
		totalAssetListBalance += a.Amount
	}

	require.Equal(t, totalBalance, totalAssetListBalance)

	// We'll also ensure that we're able to get the balance by key group
	// for all the assets that have one specified.
	assetGroupBalances, err := client.ListBalances(
		ctxt, &taprpc.ListBalancesRequest{
			GroupBy: groupBalancesByGroupKey,
		},
	)
	require.NoError(t, err)

	require.Equal(
		t, len(issuableAssets),
		len(assetGroupBalances.AssetGroupBalances),
	)
}

type balanceConfig struct {
	assetID             []byte
	groupKey            []byte
	groupedAssetBalance uint64
	numAssetUtxos       uint32
	numAnchorUtxos      uint32
	includeLeased       bool
	allScriptKeyTypes   bool
	scriptKeyType       *asset.ScriptKeyType
	scriptKey           []byte
}

type BalanceOption func(*balanceConfig)

func WithAssetID(assetID []byte) BalanceOption {
	return func(c *balanceConfig) {
		c.assetID = assetID
	}
}

func WithGroupKey(groupKey []byte) BalanceOption {
	return func(c *balanceConfig) {
		c.groupKey = groupKey
	}
}

func WithGroupedAssetBalance(groupedAssetBalance uint64) BalanceOption {
	return func(c *balanceConfig) {
		c.groupedAssetBalance = groupedAssetBalance
	}
}

func WithNumUtxos(numAssetUtxos uint32) BalanceOption {
	return func(c *balanceConfig) {
		c.numAssetUtxos = numAssetUtxos
	}
}

func WithNumAnchorUtxos(numAnchorUtxos uint32) BalanceOption {
	return func(c *balanceConfig) {
		c.numAnchorUtxos = numAnchorUtxos
	}
}

func WithIncludeLeased() BalanceOption {
	return func(c *balanceConfig) {
		c.includeLeased = true
	}
}

func WithAllScriptKeyTypes() BalanceOption {
	return func(c *balanceConfig) {
		c.allScriptKeyTypes = true
	}
}

func WithScriptKeyType(scriptKeyType asset.ScriptKeyType) BalanceOption {
	return func(c *balanceConfig) {
		c.scriptKeyType = &scriptKeyType
	}
}

func WithScriptKey(scriptKey []byte) BalanceOption {
	return func(c *balanceConfig) {
		c.scriptKey = scriptKey

		if len(scriptKey) == 33 {
			xOnlyKey, _ := schnorr.ParsePubKey(scriptKey[1:])
			c.scriptKey = xOnlyKey.SerializeCompressed()
		}
	}
}

func AssertBalances(t *testing.T, client taprpc.TaprootAssetsClient,
	balance uint64, opts ...BalanceOption) {

	t.Helper()

	config := &balanceConfig{}
	for _, opt := range opts {
		opt(config)
	}

	var rpcTypeQuery *taprpc.ScriptKeyTypeQuery
	switch {
	case config.allScriptKeyTypes:
		rpcTypeQuery = &taprpc.ScriptKeyTypeQuery{
			Type: &taprpc.ScriptKeyTypeQuery_AllTypes{
				AllTypes: true,
			},
		}

	case config.scriptKeyType != nil:
		rpcTypeQuery = &taprpc.ScriptKeyTypeQuery{
			Type: &taprpc.ScriptKeyTypeQuery_ExplicitType{
				ExplicitType: rpcutils.MarshalScriptKeyType(
					*config.scriptKeyType,
				),
			},
		}
	}

	balanceSum := func(resp *taprpc.ListBalancesResponse,
		group bool) uint64 {

		var totalBalance uint64

		if group {
			for _, currentBalance := range resp.AssetGroupBalances {
				totalBalance += currentBalance.Balance
			}
		} else {
			for _, currentBalance := range resp.AssetBalances {
				totalBalance += currentBalance.Balance
			}
		}

		return totalBalance
	}

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// First, we'll ensure that we're able to get the balances of all the
	// assets grouped by their asset IDs.
	assetIDBalances, err := client.ListBalances(
		ctxt, &taprpc.ListBalancesRequest{
			GroupBy:        groupBalancesByAssetID,
			IncludeLeased:  config.includeLeased,
			ScriptKeyType:  rpcTypeQuery,
			AssetFilter:    config.assetID,
			GroupKeyFilter: config.groupKey,
		},
	)
	require.NoError(t, err)

	// Spent assets (burns/tombstones) are never included in the balance,
	// even if we specifically query for their type. So we skip the balance
	// check in that case. We also skip if we're looking for a specific
	// script key.
	checkBalance := (config.scriptKeyType == nil ||
		(*config.scriptKeyType != asset.ScriptKeyBurn &&
			*config.scriptKeyType != asset.ScriptKeyTombstone)) &&
		len(config.scriptKey) == 0
	if checkBalance {
		require.Equal(
			t, balance, balanceSum(assetIDBalances, false),
			"asset balance, wanted %d, got: %v", balance,
			toJSON(t, assetIDBalances),
		)
	}

	// Next, we do the same but grouped by group keys (if requested, since
	// this only returns the balances for actually grouped assets).
	if config.groupedAssetBalance > 0 {
		assetGroupBalances, err := client.ListBalances(
			ctxt, &taprpc.ListBalancesRequest{
				GroupBy:        groupBalancesByGroupKey,
				IncludeLeased:  config.includeLeased,
				ScriptKeyType:  rpcTypeQuery,
				AssetFilter:    config.assetID,
				GroupKeyFilter: config.groupKey,
			},
		)
		require.NoError(t, err)

		// Spent assets (burns/tombstones) are never included in the
		// balance, even if we specifically query for their type. So we
		// skip the balance check in that case.
		if checkBalance {
			require.Equalf(
				t, config.groupedAssetBalance,
				balanceSum(assetGroupBalances, true),
				"grouped balance, wanted %d, got: %v", balance,
				toJSON(t, assetGroupBalances),
			)
		}
	}

	// Finally, we assert that the sum of all assets queried with the given
	// query parameters matches the expected balance.
	assetList, err := client.ListAssets(ctxt, &taprpc.ListAssetRequest{
		IncludeLeased: config.includeLeased,
		ScriptKeyType: rpcTypeQuery,
	})
	require.NoError(t, err)

	var (
		totalBalance uint64
		numUtxos     uint32
	)
	for _, a := range assetList.Assets {
		if len(config.assetID) > 0 {
			if !bytes.Equal(
				a.AssetGenesis.AssetId, config.assetID,
			) {

				continue
			}
		}

		if len(config.groupKey) > 0 {
			if a.AssetGroup == nil {
				continue
			}

			if !bytes.Equal(
				a.AssetGroup.TweakedGroupKey, config.groupKey,
			) {

				continue
			}
		}

		if len(config.scriptKey) > 0 {
			if !bytes.Equal(a.ScriptKey, config.scriptKey) {
				continue
			}
		}

		totalBalance += a.Amount
		numUtxos++
	}
	require.Equalf(
		t, balance, totalBalance, "ListAssets balance, wanted %d, "+
			"got: %v", balance, toJSON(t, assetList),
	)

	// The number of UTXOs means asset outputs in this case. We check the
	// BTC-level UTXOs below as well, but that's just to make sure the
	// output of that RPC lists the same assets.
	if config.numAssetUtxos > 0 {
		require.Equal(
			t, config.numAssetUtxos, numUtxos, "ListAssets num "+
				"asset utxos",
		)
	}

	utxoList, err := client.ListUtxos(ctxt, &taprpc.ListUtxosRequest{
		IncludeLeased: config.includeLeased,
		ScriptKeyType: rpcTypeQuery,
	})
	require.NoError(t, err)

	// Make sure the ListUtxos call returns the same number of (asset) UTXOs
	// as the ListAssets call.
	var numAnchorUtxos uint32
	totalBalance = 0
	numUtxos = 0
	for _, btcUtxo := range utxoList.ManagedUtxos {
		numAnchorUtxos++
		for _, assetUtxo := range btcUtxo.Assets {
			if len(config.assetID) > 0 {
				if !bytes.Equal(
					assetUtxo.AssetGenesis.AssetId,
					config.assetID,
				) {

					continue
				}
			}

			if len(config.groupKey) > 0 {
				if assetUtxo.AssetGroup == nil {
					continue
				}

				if !bytes.Equal(
					assetUtxo.AssetGroup.TweakedGroupKey,
					config.groupKey,
				) {

					continue
				}
			}

			if len(config.scriptKey) > 0 {
				if !bytes.Equal(
					assetUtxo.ScriptKey, config.scriptKey,
				) {

					continue
				}
			}

			totalBalance += assetUtxo.Amount
			numUtxos++
		}
	}
	require.Equal(t, balance, totalBalance, "ListUtxos balance")

	if config.numAnchorUtxos > 0 {
		require.Equal(
			t, config.numAnchorUtxos, numAnchorUtxos, "num anchor "+
				"utxos",
		)
	}
	if config.numAssetUtxos > 0 {
		require.Equal(
			t, config.numAssetUtxos, numUtxos, "ListUtxos num "+
				"asset utxos",
		)
	}
}

func assertGroups(t *testing.T, client taprpc.TaprootAssetsClient,
	issuableAssets []*mintrpc.MintAssetRequest) {

	t.Helper()

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// We should be able to fetch two groups of one asset each.
	assetGroups, err := client.ListGroups(
		ctxt, &taprpc.ListGroupsRequest{},
	)
	require.NoError(t, err)

	groupKeys := maps.Keys(assetGroups.Groups)
	require.Len(t, groupKeys, 2)

	groupedAssets := assetGroups.Groups[groupKeys[0]].Assets
	require.Len(t, groupedAssets, 1)
	require.Equal(t, 1, len(assetGroups.Groups[groupKeys[1]].Assets))

	groupedAssets = append(
		groupedAssets, assetGroups.Groups[groupKeys[1]].Assets[0],
	)

	// Sort the listed assets to match the order of issuableAssets.
	sort.Slice(groupedAssets, func(i, j int) bool {
		return groupedAssets[i].Amount > groupedAssets[j].Amount
	})

	equalityCheck := func(a *mintrpc.MintAsset,
		b *taprpc.AssetHumanReadable) {

		assetMeta := &proof.MetaReveal{
			Type: proof.MetaOpaque,
			Data: a.AssetMeta.Data,
		}

		err = assetMeta.SetDecDisplay(a.DecimalDisplay)
		require.NoError(t, err)

		metaHash := assetMeta.MetaHash()

		require.Equal(t, a.AssetType, b.Type)
		require.Equal(t, a.Name, b.Tag)

		require.Equal(t, metaHash[:], b.MetaHash)
		require.Equal(t, a.Amount, b.Amount)
	}

	equalityCheck(issuableAssets[0].Asset, groupedAssets[0])
	equalityCheck(issuableAssets[1].Asset, groupedAssets[1])
}

// assetRoots is a helper method that fetches all roots from a given universe
// rpc by scanning for all pages.
func assetRoots(ctx context.Context, uni unirpc.UniverseClient,
	pageSize int32) (*unirpc.AssetRootResponse, error) {

	offset := int32(0)
	roots := make(map[string]*unirpc.UniverseRoot)

	for {
		res, err := uni.AssetRoots(
			ctx,
			&unirpc.AssetRootRequest{
				Offset: offset,
				Limit:  pageSize,
			},
		)
		if err != nil {
			return nil, err
		}

		if len(res.UniverseRoots) == 0 {
			break
		}

		for k, v := range res.UniverseRoots {
			roots[k] = v
		}

		offset += pageSize
	}

	return &unirpc.AssetRootResponse{
		UniverseRoots: roots,
	}, nil
}

// assertNumAssetOutputs makes sure the given node has exactly the given number
// of asset outputs for the specified asset ID.
func assertNumAssetOutputs(t *testing.T, client taprpc.TaprootAssetsClient,
	assetID []byte, numPieces int) []*taprpc.Asset {

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultTimeout)
	defer cancel()

	resp, err := client.ListAssets(ctxt, &taprpc.ListAssetRequest{
		IncludeLeased: true,
		ScriptKeyType: allScriptKeysQuery,
	})
	require.NoError(t, err)

	var outputs []*taprpc.Asset
	for _, a := range resp.Assets {
		if !bytes.Equal(a.AssetGenesis.AssetId, assetID) {
			continue
		}

		outputs = append(outputs, a)
	}

	require.Len(t, outputs, numPieces)

	return outputs
}
