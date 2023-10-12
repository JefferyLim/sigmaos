// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0-devel
// 	protoc        v3.12.4
// source: authsrv.proto

package auth_server

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

type AuthRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Text string `protobuf:"bytes,1,opt,name=text,proto3" json:"text,omitempty"`
}

func (x *AuthRequest) Reset() {
	*x = AuthRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_authsrv_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AuthRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AuthRequest) ProtoMessage() {}

func (x *AuthRequest) ProtoReflect() protoreflect.Message {
	mi := &file_authsrv_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AuthRequest.ProtoReflect.Descriptor instead.
func (*AuthRequest) Descriptor() ([]byte, []int) {
	return file_authsrv_proto_rawDescGZIP(), []int{0}
}

func (x *AuthRequest) GetText() string {
	if x != nil {
		return x.Text
	}
	return ""
}

type AuthResult struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Text string `protobuf:"bytes,1,opt,name=text,proto3" json:"text,omitempty"`
}

func (x *AuthResult) Reset() {
	*x = AuthResult{}
	if protoimpl.UnsafeEnabled {
		mi := &file_authsrv_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AuthResult) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AuthResult) ProtoMessage() {}

func (x *AuthResult) ProtoReflect() protoreflect.Message {
	mi := &file_authsrv_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AuthResult.ProtoReflect.Descriptor instead.
func (*AuthResult) Descriptor() ([]byte, []int) {
	return file_authsrv_proto_rawDescGZIP(), []int{1}
}

func (x *AuthResult) GetText() string {
	if x != nil {
		return x.Text
	}
	return ""
}

var File_authsrv_proto protoreflect.FileDescriptor

var file_authsrv_proto_rawDesc = []byte{
	0x0a, 0x0d, 0x61, 0x75, 0x74, 0x68, 0x73, 0x72, 0x76, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22,
	0x21, 0x0a, 0x0b, 0x41, 0x75, 0x74, 0x68, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x12,
	0x0a, 0x04, 0x74, 0x65, 0x78, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x74, 0x65,
	0x78, 0x74, 0x22, 0x20, 0x0a, 0x0a, 0x41, 0x75, 0x74, 0x68, 0x52, 0x65, 0x73, 0x75, 0x6c, 0x74,
	0x12, 0x12, 0x0a, 0x04, 0x74, 0x65, 0x78, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04,
	0x74, 0x65, 0x78, 0x74, 0x32, 0x30, 0x0a, 0x0b, 0x41, 0x75, 0x74, 0x68, 0x53, 0x65, 0x72, 0x76,
	0x69, 0x63, 0x65, 0x12, 0x21, 0x0a, 0x04, 0x41, 0x75, 0x74, 0x68, 0x12, 0x0c, 0x2e, 0x41, 0x75,
	0x74, 0x68, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x0b, 0x2e, 0x41, 0x75, 0x74, 0x68,
	0x52, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x42, 0x15, 0x5a, 0x13, 0x73, 0x69, 0x67, 0x6d, 0x61, 0x6f,
	0x73, 0x2f, 0x61, 0x75, 0x74, 0x68, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_authsrv_proto_rawDescOnce sync.Once
	file_authsrv_proto_rawDescData = file_authsrv_proto_rawDesc
)

func file_authsrv_proto_rawDescGZIP() []byte {
	file_authsrv_proto_rawDescOnce.Do(func() {
		file_authsrv_proto_rawDescData = protoimpl.X.CompressGZIP(file_authsrv_proto_rawDescData)
	})
	return file_authsrv_proto_rawDescData
}

var file_authsrv_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_authsrv_proto_goTypes = []interface{}{
	(*AuthRequest)(nil), // 0: AuthRequest
	(*AuthResult)(nil),  // 1: AuthResult
}
var file_authsrv_proto_depIdxs = []int32{
	0, // 0: AuthService.Auth:input_type -> AuthRequest
	1, // 1: AuthService.Auth:output_type -> AuthResult
	1, // [1:2] is the sub-list for method output_type
	0, // [0:1] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_authsrv_proto_init() }
func file_authsrv_proto_init() {
	if File_authsrv_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_authsrv_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AuthRequest); i {
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
		file_authsrv_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AuthResult); i {
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
			RawDescriptor: file_authsrv_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_authsrv_proto_goTypes,
		DependencyIndexes: file_authsrv_proto_depIdxs,
		MessageInfos:      file_authsrv_proto_msgTypes,
	}.Build()
	File_authsrv_proto = out.File
	file_authsrv_proto_rawDesc = nil
	file_authsrv_proto_goTypes = nil
	file_authsrv_proto_depIdxs = nil
}
