package model

import (
	"context"

	"github.com/sagernet/sing-box/option"
)

// OfficialSingboxOutbound 封装与内置 sing-box 版本一致的官方出站类型。
// value 不直接暴露，防止调用方绕过 WithTag 修改共享节点。
type OfficialSingboxOutbound struct {
	value option.Outbound
}

// NewOfficialSingboxOutbound 创建官方 sing-box 出站。
func NewOfficialSingboxOutbound(outboundType, tag string, options any) *OfficialSingboxOutbound {
	return &OfficialSingboxOutbound{value: option.Outbound{
		Type:    outboundType,
		Tag:     tag,
		Options: options,
	}}
}

// Type 返回出站协议类型。
func (o *OfficialSingboxOutbound) Type() string {
	return o.value.Type
}

// Tag 返回出站标签。
func (o *OfficialSingboxOutbound) Tag() string {
	return o.value.Tag
}

// Options 返回对应协议的官方选项类型。
func (o *OfficialSingboxOutbound) Options() any {
	return o.value.Options
}

// WithTag 返回修改标签后的浅拷贝，不改变原出站。
func (o *OfficialSingboxOutbound) WithTag(tag string) *OfficialSingboxOutbound {
	cloned := o.value
	cloned.Tag = tag
	return &OfficialSingboxOutbound{value: cloned}
}

// MarshalJSON 使用官方 option.Outbound 序列化逻辑合并公共字段和协议字段。
func (o *OfficialSingboxOutbound) MarshalJSON() ([]byte, error) {
	return o.value.MarshalJSONContext(context.Background())
}
