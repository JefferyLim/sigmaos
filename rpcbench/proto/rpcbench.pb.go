// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        v3.21.12
// source: rpcbench/proto/rpcbench.proto

package proto

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	proto "sigmaos/tracing/proto"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type SleepRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	DurMS             int64                    `protobuf:"varint,1,opt,name=durMS,proto3" json:"durMS,omitempty"`
	SpanContextConfig *proto.SpanContextConfig `protobuf:"bytes,2,opt,name=spanContextConfig,proto3" json:"spanContextConfig,omitempty"`
}

func (x *SleepRequest) Reset() {
	*x = SleepRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_rpcbench_proto_rpcbench_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SleepRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SleepRequest) ProtoMessage() {}

func (x *SleepRequest) ProtoReflect() protoreflect.Message {
	mi := &file_rpcbench_proto_rpcbench_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SleepRequest.ProtoReflect.Descriptor instead.
func (*SleepRequest) Descriptor() ([]byte, []int) {
	return file_rpcbench_proto_rpcbench_proto_rawDescGZIP(), []int{0}
}

func (x *SleepRequest) GetDurMS() int64 {
	if x != nil {
		return x.DurMS
	}
	return 0
}

func (x *SleepRequest) GetSpanContextConfig() *proto.SpanContextConfig {
	if x != nil {
		return x.SpanContextConfig
	}
	return nil
}

type SleepResult struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	HotelIds []string `protobuf:"bytes,1,rep,name=hotelIds,proto3" json:"hotelIds,omitempty"`
}

func (x *SleepResult) Reset() {
	*x = SleepResult{}
	if protoimpl.UnsafeEnabled {
		mi := &file_rpcbench_proto_rpcbench_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SleepResult) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SleepResult) ProtoMessage() {}

func (x *SleepResult) ProtoReflect() protoreflect.Message {
	mi := &file_rpcbench_proto_rpcbench_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SleepResult.ProtoReflect.Descriptor instead.
func (*SleepResult) Descriptor() ([]byte, []int) {
	return file_rpcbench_proto_rpcbench_proto_rawDescGZIP(), []int{1}
}

func (x *SleepResult) GetHotelIds() []string {
	if x != nil {
		return x.HotelIds
	}
	return nil
}

var File_rpcbench_proto_rpcbench_proto protoreflect.FileDescriptor

var file_rpcbench_proto_rpcbench_proto_rawDesc = []byte{
	0x0a, 0x1d, 0x72, 0x70, 0x63, 0x62, 0x65, 0x6e, 0x63, 0x68, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x2f, 0x72, 0x70, 0x63, 0x62, 0x65, 0x6e, 0x63, 0x68, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a,
	0x1b, 0x74, 0x72, 0x61, 0x63, 0x69, 0x6e, 0x67, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x74,
	0x72, 0x61, 0x63, 0x69, 0x6e, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x66, 0x0a, 0x0c,
	0x53, 0x6c, 0x65, 0x65, 0x70, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x14, 0x0a, 0x05,
	0x64, 0x75, 0x72, 0x4d, 0x53, 0x18, 0x01, 0x20, 0x01, 0x28, 0x03, 0x52, 0x05, 0x64, 0x75, 0x72,
	0x4d, 0x53, 0x12, 0x40, 0x0a, 0x11, 0x73, 0x70, 0x61, 0x6e, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x78,
	0x74, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x12, 0x2e,
	0x53, 0x70, 0x61, 0x6e, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74, 0x43, 0x6f, 0x6e, 0x66, 0x69,
	0x67, 0x52, 0x11, 0x73, 0x70, 0x61, 0x6e, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74, 0x43, 0x6f,
	0x6e, 0x66, 0x69, 0x67, 0x22, 0x29, 0x0a, 0x0b, 0x53, 0x6c, 0x65, 0x65, 0x70, 0x52, 0x65, 0x73,
	0x75, 0x6c, 0x74, 0x12, 0x1a, 0x0a, 0x08, 0x68, 0x6f, 0x74, 0x65, 0x6c, 0x49, 0x64, 0x73, 0x18,
	0x01, 0x20, 0x03, 0x28, 0x09, 0x52, 0x08, 0x68, 0x6f, 0x74, 0x65, 0x6c, 0x49, 0x64, 0x73, 0x32,
	0x33, 0x0a, 0x0b, 0x52, 0x50, 0x43, 0x42, 0x65, 0x6e, 0x63, 0x68, 0x53, 0x72, 0x76, 0x12, 0x24,
	0x0a, 0x05, 0x53, 0x6c, 0x65, 0x65, 0x70, 0x12, 0x0d, 0x2e, 0x53, 0x6c, 0x65, 0x65, 0x70, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x0c, 0x2e, 0x53, 0x6c, 0x65, 0x65, 0x70, 0x52, 0x65,
	0x73, 0x75, 0x6c, 0x74, 0x42, 0x18, 0x5a, 0x16, 0x73, 0x69, 0x67, 0x6d, 0x61, 0x6f, 0x73, 0x2f,
	0x72, 0x70, 0x63, 0x62, 0x65, 0x6e, 0x63, 0x68, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x06,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_rpcbench_proto_rpcbench_proto_rawDescOnce sync.Once
	file_rpcbench_proto_rpcbench_proto_rawDescData = file_rpcbench_proto_rpcbench_proto_rawDesc
)

func file_rpcbench_proto_rpcbench_proto_rawDescGZIP() []byte {
	file_rpcbench_proto_rpcbench_proto_rawDescOnce.Do(func() {
		file_rpcbench_proto_rpcbench_proto_rawDescData = protoimpl.X.CompressGZIP(file_rpcbench_proto_rpcbench_proto_rawDescData)
	})
	return file_rpcbench_proto_rpcbench_proto_rawDescData
}

var file_rpcbench_proto_rpcbench_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_rpcbench_proto_rpcbench_proto_goTypes = []interface{}{
	(*SleepRequest)(nil),            // 0: SleepRequest
	(*SleepResult)(nil),             // 1: SleepResult
	(*proto.SpanContextConfig)(nil), // 2: SpanContextConfig
}
var file_rpcbench_proto_rpcbench_proto_depIdxs = []int32{
	2, // 0: SleepRequest.spanContextConfig:type_name -> SpanContextConfig
	0, // 1: RPCBenchSrv.Sleep:input_type -> SleepRequest
	1, // 2: RPCBenchSrv.Sleep:output_type -> SleepResult
	2, // [2:3] is the sub-list for method output_type
	1, // [1:2] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_rpcbench_proto_rpcbench_proto_init() }
func file_rpcbench_proto_rpcbench_proto_init() {
	if File_rpcbench_proto_rpcbench_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_rpcbench_proto_rpcbench_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SleepRequest); i {
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
		file_rpcbench_proto_rpcbench_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SleepResult); i {
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
			RawDescriptor: file_rpcbench_proto_rpcbench_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_rpcbench_proto_rpcbench_proto_goTypes,
		DependencyIndexes: file_rpcbench_proto_rpcbench_proto_depIdxs,
		MessageInfos:      file_rpcbench_proto_rpcbench_proto_msgTypes,
	}.Build()
	File_rpcbench_proto_rpcbench_proto = out.File
	file_rpcbench_proto_rpcbench_proto_rawDesc = nil
	file_rpcbench_proto_rpcbench_proto_goTypes = nil
	file_rpcbench_proto_rpcbench_proto_depIdxs = nil
}
