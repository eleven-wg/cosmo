package module

import (
	"fmt"

	"github.com/opentracing/opentracing-go"
)

type TracingHelperKV struct{}

// 获取单例 CalHelper
func NewTracingHelperKV() *TracingHelperKV {
	return &TracingHelperKV{}
}

// submit current rlogid with tracer
func (c *TracingHelperKV) SubmitCurrentRlogid(rlogid, rci, ri string, span opentracing.Span) {
	fmt.Println("##==>submitCurrentRlogid.. rlogid:", rlogid, "rci:", rci, "ri:", ri)
	span.LogKV(
		"type", "URL",
		"name", "LOGID",
		"status", "0",
		"data", fmt.Sprintf("rlogid=%s&rci=%s&ri=%s", rlogid, rci, ri), // 添加这行
		"rlogid", rlogid,
		"rci", rci,
		"ri", ri,
	)
}

// submit upstream/downstream rlogid
func (c *TracingHelperKV) SubmitStreamRlogid(rlogid, rci, ri string, spanType string, parentSpan opentracing.Span) {
	fmt.Println("##==>submitSreamRlogid.. rlogid:", rlogid, "spanType:", spanType)
	if rlogid == "" || spanType == "" {
		fmt.Println("##==>v101 submitSreamRlogid.. rlogid or spanType is empty, skipping submission")
		return
	}
	if tracer == nil {
		fmt.Println("tracer is nil, skipping span creation")
		return
	}

	println("##==>submitSreamRlogid.. parentSpan:", parentSpan)
	parentSpan.LogKV(
		"type", "URL",
		"name", spanType,
		"status", "0",
		"data", fmt.Sprintf("rlogid=%s", rlogid),
		"rlogid", rlogid,
	)
}
