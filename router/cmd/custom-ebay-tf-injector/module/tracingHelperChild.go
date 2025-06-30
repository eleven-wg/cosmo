package module

import (
	"fmt"

	"ebay.com/security-platform/cal-client-go"
	"github.com/opentracing/opentracing-go"
)

type TracingHelperChild struct{}

func NewCalHelperChild() *TracingHelperChild {
	return &TracingHelperChild{}
}

// submit current rlogid with tracer
func (c *TracingHelperChild) SubmitCurrentRlogidWithTracer(rlogid, parentRlogid, rci, ri string, span opentracing.Span) {
	fmt.Println("##==>submitCurrentRlogid.. rlogid:", rlogid, "rci:", rci, "ri:", ri)
	span.SetTag(cal.CalTagName, "LOGID")
	span.SetTag(cal.CalTagStatus, "0")
	span.SetTag(cal.CalTagThreadID, cal.AssignThreadID())
	span.SetTag(cal.CalTagType, "URL")
	// 将核心数据设置为 Tags
	span.SetTag("logid", rlogid)
	// span.SetTag("rci", rci)
	// span.SetTag("ri", ri)
	// span.SetTag("corr_id_", rci)
	span.LogKV(
		"type", "URL",
		"name", "LOGID",
		"status", "0",
		"logid", rlogid, // 核心数据
		// "rci", rci,
		// "ri", ri,
		// "corr_id_", rci,
	)

	span.LogKV(
		"type", "URL",
		"name", "Backward_RLOGID",
		"status", "0",
		"rlogid", parentRlogid, // 核心数据
		"logid", parentRlogid, // 核心数据
	)

	fmt.Println("##==>submitCurrentRlogid.. rlogid:", rlogid, "rci:", rci, "ri:", ri, "span:", span)
}

// submit upstream/downstream rlogid
func (c *TracingHelperChild) SubmitStreamRlogidWithTracer(rlogid, rci, ri string, spanType string, parentSpan opentracing.Span) {
	fmt.Println("##==>SubmitStreamRlogidWithTracer.. rlogid:", rlogid, "rci:", rci, "ri:", ri)
	if rlogid == "" || spanType == "" {
		fmt.Println("##==>v101 submitSreamRlogid.. rlogid or spanType is empty, skipping submission")
		return
	}
	if tracer == nil {
		fmt.Println("tracer is nil, skipping span creation")
		return
	}
	childSpan := tracer.StartSpan("URL", opentracing.ChildOf(parentSpan.Context()))
	childSpan.SetTag(cal.CalTagName, spanType)
	childSpan.SetTag(cal.CalTagStatus, "0")
	childSpan.SetTag(cal.CalTagThreadID, cal.AssignThreadID())
	childSpan.SetTag(cal.CalTagType, "URL")
	// 改为使用 SetTag
	childSpan.SetTag("rlogid", rlogid)
	childSpan.SetTag("rci", rci)
	childSpan.SetTag("ri", ri)
	childSpan.SetTag("corr_id_", rci)

	childSpan.LogKV(
		"rlogid", rlogid,
		"rci", rci,
		"ri", ri,
		"corr_id_", rci,
	)
	childSpan.Finish()
}
