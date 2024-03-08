package itest

import (
	"bytes"
	"context"
	"crypto/rand"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	wrpc "github.com/lightninglabs/taproot-assets/taprpc/assetwalletrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/lightninglabs/taproot-assets/tapscript"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnrpc/chainrpc"
	"github.com/lightningnetwork/lnd/lnrpc/signrpc"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"github.com/lightningnetwork/lnd/lntest/node"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/stretchr/testify/require"
)

func testLoopPkScript(t *harnessTest) {
	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// We mint some grouped assets to use in the test. These assets are
	// minted on the default tapd instance that is always created in the
	// integration test (connected to lnd "Alice").
	firstBatch := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner.Client, t.tapd,
		[]*mintrpc.MintAssetRequest{issuableAssets[0]},
	)[0]

	var (
		firstBatchGenesis = firstBatch.AssetGenesis
		aliceTapd         = t.tapd
		aliceLnd          = t.lndHarness.Alice
		bobLnd            = t.lndHarness.Bob
	)
	// We create a second tapd node that will be used to simulate a second
	// party in the test. This tapd node is connected to lnd "Bob".
	bobTapd := setupTapdHarness(t.t, t, bobLnd, t.universeServer)
	defer func() {
		require.NoError(t.t, bobTapd.stop(!*noDelete))
	}()

	blockRes := aliceLnd.RPC.GetBestBlock(&chainrpc.GetBestBlockRequest{})

	// Create a v3 loop HTLC.
	_, aliceInternalKey := deriveKeys(t.t, aliceTapd)
	_, bobInternalKey := deriveKeys(t.t, bobTapd)

	var (
		preimage = makeLndPreimage(t.t)
		hash     = preimage.Hash()
	)

	successPathScript, err := GenSuccessPathScript(
		bobInternalKey.PubKey, hash,
	)
	require.NoError(t.t, err)

	timeoutPathScript, err := GenTimeoutPathScript(
		aliceInternalKey.PubKey, int64(blockRes.BlockHeight+100),
	)
	require.NoError(t.t, err)

	// Assemble our taproot script tree from our leaves. Calculate the
	// internal aggregate key.
	aggregateKey, err := input.MuSig2CombineKeys(
		input.MuSig2Version100RC2,
		[]*btcec.PublicKey{
			aliceInternalKey.PubKey, bobInternalKey.PubKey,
		},
		true,
		&input.MuSig2Tweaks{},
	)
	require.NoError(t.t, err)

	btcInternalKey := aggregateKey.PreTweakedKey

	successLeaf := txscript.NewBaseTapLeaf(successPathScript)
	timeoutLeaf := txscript.NewBaseTapLeaf(timeoutPathScript)
	branch := txscript.NewTapBranch(successLeaf, timeoutLeaf)
	siblingPreimage := commitment.NewPreimageFromBranch(branch)

	const assetsToSend = 1000
	tapScriptKey, _, _, _ := createOpTrueLeaf(t.t)
	t.t.Logf("Tapscript key: %v", tapScriptKey)

	// Create a new vPacket for transferring 1000 bux using the HTLC anchor.
	assetId := asset.ID{}
	copy(assetId[:], firstBatchGenesis.AssetId)
	pkt := &tappsbt.VPacket{
		Inputs: []*tappsbt.VInput{{
			PrevID: asset.PrevID{
				ID: assetId,
			},
		}},
		Outputs:     make([]*tappsbt.VOutput, 0, 2),
		ChainParams: &address.RegressionNetTap,
	}
	pkt.Outputs = append(pkt.Outputs, &tappsbt.VOutput{
		Amount:            0,
		Type:              tappsbt.TypeSplitRoot,
		AnchorOutputIndex: 0,
		ScriptKey:         asset.NUMSScriptKey,
	})
	pkt.Outputs = append(pkt.Outputs, &tappsbt.VOutput{
		AssetVersion:      asset.Version(issuableAssets[0].Asset.AssetVersion),
		Amount:            assetsToSend,
		Interactive:       true,
		AnchorOutputIndex: 1,
		ScriptKey: asset.NewScriptKey(
			tapScriptKey.PubKey,
		),
		AnchorOutputInternalKey:      btcInternalKey,
		AnchorOutputTapscriptSibling: &siblingPreimage,
	})

	// We can now fund the vpsbt.
	fundResp := fundPacket(t, aliceTapd, pkt)
	vPkt, err := tappsbt.Decode(fundResp.FundedPsbt)
	require.NoError(t.t, err)

	// Now that we have a funded packet we can generate the pkScript for the
	// anchor output.
	assetCommitment, err := commitment.FromAssets(vPkt.Outputs[1].Asset)
	require.NoError(t.t, err)
	siblingHash, err := siblingPreimage.TapHash()
	require.NoError(t.t, err)

	anchorPkScript, err := tapscript.PayToAddrScript(
		*btcInternalKey, siblingHash, *assetCommitment,
	)
	require.NoError(t.t, err)

	// Sign the vpsbt.
	signResp, err := aliceTapd.SignVirtualPsbt(
		ctxt, &wrpc.SignVirtualPsbtRequest{
			FundedPsbt: fundResp.FundedPsbt,
		},
	)
	require.NoError(t.t, err)
	t.Logf("Sign resp: %v", toJSON(t.t, signResp))

	fundedHtlcPkt := deserializeVPacket(
		t.t, signResp.SignedPsbt,
	)

	// Prepare the anchor template and commit the vpsbt.
	htlcVPackets := []*tappsbt.VPacket{fundedHtlcPkt}
	htlcBtcPkt, err := tapsend.PrepareAnchoringTemplate(htlcVPackets)
	require.NoError(t.t, err)

	btcPacket, _, _, _ := commitVirtualPsbts(
		t.t, aliceTapd, htlcBtcPkt, htlcVPackets, nil, -1,
	)

	// We expect that the anchor outputs pkScsript is what we generated
	// above before we prepared the BTC packet.
	require.Equal(
		t.t, btcPacket.UnsignedTx.TxOut[1].PkScript, anchorPkScript,
	)
}

func signMusig2Psbt(t *testing.T, ctx context.Context, aliceLnd, bobLnd *node.HarnessNode,
	aliceSigDesc, bobSigDesc keychain.KeyDescriptor, tx *wire.MsgTx, rootHash []byte,
	prevOut *wire.TxOut) []byte {
	signers := [][]byte{
		aliceSigDesc.PubKey.SerializeCompressed(),
		bobSigDesc.PubKey.SerializeCompressed(),
	}
	// Create the musig2 sessions
	aliceSession, err := aliceLnd.RPC.Signer.MuSig2CreateSession(
		ctx, &signrpc.MuSig2SessionRequest{
			Version: signrpc.MuSig2Version_MUSIG2_VERSION_V100RC2,
			KeyLoc: &signrpc.KeyLocator{
				KeyFamily: int32(aliceSigDesc.Family),
				KeyIndex:  int32(aliceSigDesc.Index),
			},
			AllSignerPubkeys: signers,
			TaprootTweak: &signrpc.TaprootTweakDesc{
				KeySpendOnly: true,
			},
		},
	)
	require.NoError(t, err)

	bobSession, err := bobLnd.RPC.Signer.MuSig2CreateSession(
		ctx, &signrpc.MuSig2SessionRequest{
			Version: signrpc.MuSig2Version_MUSIG2_VERSION_V100RC2,
			KeyLoc: &signrpc.KeyLocator{
				KeyFamily: int32(bobSigDesc.Family),
				KeyIndex:  int32(bobSigDesc.Index),
			},
			AllSignerPubkeys: signers,
			TaprootTweak: &signrpc.TaprootTweakDesc{
				KeySpendOnly: true,
			},
		},
	)
	require.NoError(t, err)

	// Register the nonces with each other.
	regNonceRes, err := aliceLnd.RPC.Signer.MuSig2RegisterNonces(
		ctx, &signrpc.MuSig2RegisterNoncesRequest{
			SessionId:               aliceSession.SessionId,
			OtherSignerPublicNonces: [][]byte{bobSession.LocalPublicNonces},
		},
	)
	require.NoError(t, err)
	require.True(t, regNonceRes.HaveAllNonces)

	_, err = bobLnd.RPC.Signer.MuSig2RegisterNonces(
		ctx, &signrpc.MuSig2RegisterNoncesRequest{
			SessionId:               bobSession.SessionId,
			OtherSignerPublicNonces: [][]byte{aliceSession.LocalPublicNonces},
		},
	)
	require.NoError(t, err)

	prevOutFetcher := txscript.NewCannedPrevOutputFetcher(
		prevOut.PkScript, prevOut.Value,
	)
	sigHashes := txscript.NewTxSigHashes(tx, prevOutFetcher)
	taprootSigHash, err := txscript.CalcTaprootSignatureHash(
		sigHashes, txscript.SigHashDefault,
		tx, 0, prevOutFetcher,
	)
	require.NoError(t, err)

	// Now we can sign the psbt.
	aliceSignRes, err := aliceLnd.RPC.Signer.MuSig2Sign(
		ctx, &signrpc.MuSig2SignRequest{
			SessionId:     aliceSession.SessionId,
			MessageDigest: taprootSigHash,
		},
	)
	require.NoError(t, err)

	_, err = bobLnd.RPC.Signer.MuSig2Sign(
		ctx, &signrpc.MuSig2SignRequest{
			SessionId:     bobSession.SessionId,
			MessageDigest: taprootSigHash,
		},
	)
	require.NoError(t, err)

	// combine the sigs at bob
	combineSigRes, err := bobLnd.RPC.Signer.MuSig2CombineSig(
		ctx, &signrpc.MuSig2CombineSigRequest{
			SessionId: bobSession.SessionId,
			OtherPartialSignatures: [][]byte{
				aliceSignRes.LocalPartialSignature,
			},
		},
	)
	require.NoError(t, err)
	require.True(t, combineSigRes.HaveAllSignatures)

	return combineSigRes.FinalSignature
}

func pubkeyTo33Byte(pubkey *btcec.PublicKey) [33]byte {
	var pub33 [33]byte
	copy(pub33[:], pubkey.SerializeCompressed())
	return pub33
}

func makeLndPreimage(t *testing.T) lntypes.Preimage {
	// Create a random preimage
	var preimage lntypes.Preimage
	_, err := rand.Read(preimage[:])
	require.NoError(t, err)
	return preimage
}

func getOpTrueScript(t *testing.T) []byte {
	builder := txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_TRUE)
	script, err := builder.Script()
	require.NoError(t, err)
	return script
}

func createOpTrueLeaf(t *testing.T) (asset.ScriptKey, txscript.TapLeaf,
	*txscript.IndexedTapScriptTree, *txscript.ControlBlock) {

	// Create the taproot OP_TRUE script.
	tapScript := getOpTrueScript(t)

	tapLeaf := txscript.NewBaseTapLeaf(tapScript)
	tree := txscript.AssembleTaprootScriptTree(tapLeaf)
	rootHash := tree.RootNode.TapHash()
	tapKey := txscript.ComputeTaprootOutputKey(asset.NUMSPubKey, rootHash[:])

	merkleRootHash := tree.RootNode.TapHash()

	controlBlock := &txscript.ControlBlock{
		LeafVersion: txscript.BaseLeafVersion,
		InternalKey: asset.NUMSPubKey,
	}
	tapScriptKey := asset.ScriptKey{
		PubKey: tapKey,
		TweakedScriptKey: &asset.TweakedScriptKey{
			RawKey: keychain.KeyDescriptor{
				PubKey: asset.NUMSPubKey,
			},
			Tweak: merkleRootHash[:],
		},
	}
	if tapKey.SerializeCompressed()[0] ==
		secp256k1.PubKeyFormatCompressedOdd {

		controlBlock.OutputKeyYIsOdd = true
	}

	return tapScriptKey, tapLeaf, tree, controlBlock
}

func partialSignWithKeyTopLevel(t *testing.T, lnd *node.HarnessNode, pkt *psbt.Packet,
	inputIndex uint32, key keychain.KeyDescriptor, tapLeaf txscript.TapLeaf) []byte {

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// The lnd SignPsbt RPC doesn't really understand multi-sig yet, we
	// cannot specify multiple keys that need to sign. So what we do here
	// is just replace the derivation path info for the input we want to
	// sign to the key we want to sign with. If we do this for every signing
	// participant, we'll get the correct signatures for OP_CHECKSIGADD.
	signInput := &pkt.Inputs[inputIndex]
	derivation, trDerivation := tappsbt.Bip32DerivationFromKeyDesc(
		key, lnd.Cfg.NetParams.HDCoinType,
	)
	trDerivation.LeafHashes = [][]byte{fn.ByteSlice(tapLeaf.TapHash())}
	signInput.Bip32Derivation = []*psbt.Bip32Derivation{derivation}
	signInput.TaprootBip32Derivation = []*psbt.TaprootBip32Derivation{
		trDerivation,
	}
	signInput.SighashType = txscript.SigHashDefault

	var buf bytes.Buffer
	err := pkt.Serialize(&buf)
	require.NoError(t, err)

	resp, err := lnd.RPC.WalletKit.SignPsbt(
		ctxt, &walletrpc.SignPsbtRequest{
			FundedPsbt: buf.Bytes(),
		},
	)
	require.NoError(t, err)

	result, err := psbt.NewFromRawBytes(
		bytes.NewReader(resp.SignedPsbt), false,
	)
	require.NoError(t, err)

	// Make sure the input we wanted to sign for was actually signed.
	require.Contains(t, resp.SignedInputs, inputIndex)

	return result.Inputs[inputIndex].TaprootScriptSpendSig[0].Signature
}

func GenSuccessPathScript(receiverHtlcKey *btcec.PublicKey,
	swapHash lntypes.Hash) ([]byte, error) {

	builder := txscript.NewScriptBuilder()

	builder.AddData(schnorr.SerializePubKey(receiverHtlcKey))
	builder.AddOp(txscript.OP_CHECKSIGVERIFY)
	builder.AddOp(txscript.OP_SIZE)
	builder.AddInt64(32)
	builder.AddOp(txscript.OP_EQUALVERIFY)
	builder.AddOp(txscript.OP_HASH160)
	builder.AddData(input.Ripemd160H(swapHash[:]))
	builder.AddOp(txscript.OP_EQUALVERIFY)
	builder.AddInt64(1)
	builder.AddOp(txscript.OP_CHECKSEQUENCEVERIFY)

	return builder.Script()
}

// GenTimeoutPathScript constructs an HtlcScript for the timeout payment path.
// Largest possible bytesize of the script is 32 + 1 + 2 + 1 = 36.
//
//	<senderHtlcKey> OP_CHECKSIGVERIFY <cltvExpiry> OP_CHECKLOCKTIMEVERIFY
func GenTimeoutPathScript(senderHtlcKey *btcec.PublicKey, cltvExpiry int64) (
	[]byte, error) {

	builder := txscript.NewScriptBuilder()
	builder.AddData(schnorr.SerializePubKey(senderHtlcKey))
	builder.AddOp(txscript.OP_CHECKSIGVERIFY)
	builder.AddInt64(cltvExpiry)
	builder.AddOp(txscript.OP_CHECKLOCKTIMEVERIFY)
	return builder.Script()
}

// genSuccessWitness returns the success script to spend this htlc with
// the preimage.
func genSuccessWitness(t *testing.T, lnd *node.HarnessNode,
	controlBlock txscript.ControlBlock, preimage lntypes.Preimage,
	successScript []byte, tx *wire.MsgTx, keyDesc keychain.KeyDescriptor,
	assetTxOut *wire.TxOut, feeInputTxOut *wire.TxOut) wire.TxWitness {

	var buf bytes.Buffer
	err := tx.Serialize(&buf)
	require.NoError(t, err)

	assetSignTxOut := &signrpc.TxOut{
		PkScript: assetTxOut.PkScript,
		Value:    assetTxOut.Value,
	}
	changeSignTxOut := &signrpc.TxOut{
		PkScript: feeInputTxOut.PkScript,
		Value:    feeInputTxOut.Value,
	}
	rawSig, err := lnd.RPC.Signer.SignOutputRaw(
		context.Background(), &signrpc.SignReq{
			RawTxBytes: buf.Bytes(),
			SignDescs: []*signrpc.SignDescriptor{
				{
					KeyDesc: &signrpc.KeyDescriptor{
						KeyLoc: &signrpc.KeyLocator{
							KeyFamily: int32(keyDesc.Family),
							KeyIndex:  int32(keyDesc.Index),
						},
					},
					SignMethod:    signrpc.SignMethod_SIGN_METHOD_TAPROOT_SCRIPT_SPEND,
					WitnessScript: successScript,
					Output:        assetSignTxOut,
					Sighash:       uint32(txscript.SigHashDefault),
					InputIndex:    0,
				},
			},
			PrevOutputs: []*signrpc.TxOut{
				assetSignTxOut, changeSignTxOut,
			},
		},
	)
	require.NoError(t, err)

	controlBlockBytes, err := controlBlock.ToBytes()
	require.NoError(t, err)

	return wire.TxWitness{
		preimage[:],
		rawSig.RawSigs[0],
		successScript,
		controlBlockBytes,
	}
}
