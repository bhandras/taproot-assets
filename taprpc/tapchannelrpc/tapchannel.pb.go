// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.33.0
// 	protoc        v3.21.12
// source: tapchannelrpc/tapchannel.proto

package tapchannelrpc

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type FundChannelRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The asset amount to fund the channel with. The BTC amount is fixed and
	// cannot be customized (for now).
	AssetAmount uint64 `protobuf:"varint,1,opt,name=asset_amount,json=assetAmount,proto3" json:"asset_amount,omitempty"`
	// The asset ID to use for the channel funding.
	AssetId []byte `protobuf:"bytes,2,opt,name=asset_id,json=assetId,proto3" json:"asset_id,omitempty"`
	// The public key of the peer to open the channel with. Must already be
	// connected to this peer.
	PeerPubkey []byte `protobuf:"bytes,3,opt,name=peer_pubkey,json=peerPubkey,proto3" json:"peer_pubkey,omitempty"`
	// The channel funding fee rate in sat/vByte.
	FeeRateSatPerVbyte uint32 `protobuf:"varint,4,opt,name=fee_rate_sat_per_vbyte,json=feeRateSatPerVbyte,proto3" json:"fee_rate_sat_per_vbyte,omitempty"`
}

func (x *FundChannelRequest) Reset() {
	*x = FundChannelRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_tapchannelrpc_tapchannel_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *FundChannelRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FundChannelRequest) ProtoMessage() {}

func (x *FundChannelRequest) ProtoReflect() protoreflect.Message {
	mi := &file_tapchannelrpc_tapchannel_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FundChannelRequest.ProtoReflect.Descriptor instead.
func (*FundChannelRequest) Descriptor() ([]byte, []int) {
	return file_tapchannelrpc_tapchannel_proto_rawDescGZIP(), []int{0}
}

func (x *FundChannelRequest) GetAssetAmount() uint64 {
	if x != nil {
		return x.AssetAmount
	}
	return 0
}

func (x *FundChannelRequest) GetAssetId() []byte {
	if x != nil {
		return x.AssetId
	}
	return nil
}

func (x *FundChannelRequest) GetPeerPubkey() []byte {
	if x != nil {
		return x.PeerPubkey
	}
	return nil
}

func (x *FundChannelRequest) GetFeeRateSatPerVbyte() uint32 {
	if x != nil {
		return x.FeeRateSatPerVbyte
	}
	return 0
}

type FundChannelResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The channel funding transaction ID.
	Txid string `protobuf:"bytes,1,opt,name=txid,proto3" json:"txid,omitempty"`
}

func (x *FundChannelResponse) Reset() {
	*x = FundChannelResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_tapchannelrpc_tapchannel_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *FundChannelResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FundChannelResponse) ProtoMessage() {}

func (x *FundChannelResponse) ProtoReflect() protoreflect.Message {
	mi := &file_tapchannelrpc_tapchannel_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FundChannelResponse.ProtoReflect.Descriptor instead.
func (*FundChannelResponse) Descriptor() ([]byte, []int) {
	return file_tapchannelrpc_tapchannel_proto_rawDescGZIP(), []int{1}
}

func (x *FundChannelResponse) GetTxid() string {
	if x != nil {
		return x.Txid
	}
	return ""
}

var File_tapchannelrpc_tapchannel_proto protoreflect.FileDescriptor

var file_tapchannelrpc_tapchannel_proto_rawDesc = []byte{
	0x0a, 0x1e, 0x74, 0x61, 0x70, 0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x72, 0x70, 0x63, 0x2f,
	0x74, 0x61, 0x70, 0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x12, 0x0d, 0x74, 0x61, 0x70, 0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x72, 0x70, 0x63, 0x22,
	0xa7, 0x01, 0x0a, 0x12, 0x46, 0x75, 0x6e, 0x64, 0x43, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x21, 0x0a, 0x0c, 0x61, 0x73, 0x73, 0x65, 0x74, 0x5f,
	0x61, 0x6d, 0x6f, 0x75, 0x6e, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0b, 0x61, 0x73,
	0x73, 0x65, 0x74, 0x41, 0x6d, 0x6f, 0x75, 0x6e, 0x74, 0x12, 0x19, 0x0a, 0x08, 0x61, 0x73, 0x73,
	0x65, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x07, 0x61, 0x73, 0x73,
	0x65, 0x74, 0x49, 0x64, 0x12, 0x1f, 0x0a, 0x0b, 0x70, 0x65, 0x65, 0x72, 0x5f, 0x70, 0x75, 0x62,
	0x6b, 0x65, 0x79, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0a, 0x70, 0x65, 0x65, 0x72, 0x50,
	0x75, 0x62, 0x6b, 0x65, 0x79, 0x12, 0x32, 0x0a, 0x16, 0x66, 0x65, 0x65, 0x5f, 0x72, 0x61, 0x74,
	0x65, 0x5f, 0x73, 0x61, 0x74, 0x5f, 0x70, 0x65, 0x72, 0x5f, 0x76, 0x62, 0x79, 0x74, 0x65, 0x18,
	0x04, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x12, 0x66, 0x65, 0x65, 0x52, 0x61, 0x74, 0x65, 0x53, 0x61,
	0x74, 0x50, 0x65, 0x72, 0x56, 0x62, 0x79, 0x74, 0x65, 0x22, 0x29, 0x0a, 0x13, 0x46, 0x75, 0x6e,
	0x64, 0x43, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x12, 0x12, 0x0a, 0x04, 0x74, 0x78, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04,
	0x74, 0x78, 0x69, 0x64, 0x32, 0x6c, 0x0a, 0x14, 0x54, 0x61, 0x70, 0x72, 0x6f, 0x6f, 0x74, 0x41,
	0x73, 0x73, 0x65, 0x74, 0x43, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x73, 0x12, 0x54, 0x0a, 0x0b,
	0x46, 0x75, 0x6e, 0x64, 0x43, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x12, 0x21, 0x2e, 0x74, 0x61,
	0x70, 0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x72, 0x70, 0x63, 0x2e, 0x46, 0x75, 0x6e, 0x64,
	0x43, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x22,
	0x2e, 0x74, 0x61, 0x70, 0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x72, 0x70, 0x63, 0x2e, 0x46,
	0x75, 0x6e, 0x64, 0x43, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x42, 0x3e, 0x5a, 0x3c, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d,
	0x2f, 0x6c, 0x69, 0x67, 0x68, 0x74, 0x6e, 0x69, 0x6e, 0x67, 0x6c, 0x61, 0x62, 0x73, 0x2f, 0x74,
	0x61, 0x70, 0x72, 0x6f, 0x6f, 0x74, 0x2d, 0x61, 0x73, 0x73, 0x65, 0x74, 0x73, 0x2f, 0x74, 0x61,
	0x70, 0x72, 0x70, 0x63, 0x2f, 0x74, 0x61, 0x70, 0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x72,
	0x70, 0x63, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_tapchannelrpc_tapchannel_proto_rawDescOnce sync.Once
	file_tapchannelrpc_tapchannel_proto_rawDescData = file_tapchannelrpc_tapchannel_proto_rawDesc
)

func file_tapchannelrpc_tapchannel_proto_rawDescGZIP() []byte {
	file_tapchannelrpc_tapchannel_proto_rawDescOnce.Do(func() {
		file_tapchannelrpc_tapchannel_proto_rawDescData = protoimpl.X.CompressGZIP(file_tapchannelrpc_tapchannel_proto_rawDescData)
	})
	return file_tapchannelrpc_tapchannel_proto_rawDescData
}

var file_tapchannelrpc_tapchannel_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_tapchannelrpc_tapchannel_proto_goTypes = []interface{}{
	(*FundChannelRequest)(nil),  // 0: tapchannelrpc.FundChannelRequest
	(*FundChannelResponse)(nil), // 1: tapchannelrpc.FundChannelResponse
}
var file_tapchannelrpc_tapchannel_proto_depIdxs = []int32{
	0, // 0: tapchannelrpc.TaprootAssetChannels.FundChannel:input_type -> tapchannelrpc.FundChannelRequest
	1, // 1: tapchannelrpc.TaprootAssetChannels.FundChannel:output_type -> tapchannelrpc.FundChannelResponse
	1, // [1:2] is the sub-list for method output_type
	0, // [0:1] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_tapchannelrpc_tapchannel_proto_init() }
func file_tapchannelrpc_tapchannel_proto_init() {
	if File_tapchannelrpc_tapchannel_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_tapchannelrpc_tapchannel_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*FundChannelRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_tapchannelrpc_tapchannel_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*FundChannelResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_tapchannelrpc_tapchannel_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_tapchannelrpc_tapchannel_proto_goTypes,
		DependencyIndexes: file_tapchannelrpc_tapchannel_proto_depIdxs,
		MessageInfos:      file_tapchannelrpc_tapchannel_proto_msgTypes,
	}.Build()
	File_tapchannelrpc_tapchannel_proto = out.File
	file_tapchannelrpc_tapchannel_proto_rawDesc = nil
	file_tapchannelrpc_tapchannel_proto_goTypes = nil
	file_tapchannelrpc_tapchannel_proto_depIdxs = nil
}