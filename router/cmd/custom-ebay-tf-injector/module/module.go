package module

import (
	"fmt"
	"net/http"

	"ebay.com/security-platform/cal-client-go"
	"github.com/opentracing/opentracing-go"
	"github.com/wundergraph/cosmo/router/core"
	"go.uber.org/zap"
)

func init() {
	// Register your module here
	core.RegisterModule(&TrustFabricInjectorModule{})
}

const (
	ModuleID        = "com.ebay.wgrouter.TrustFabricInjectorModule"
	tokenContextKey = "tf-token"
)

type TrustFabricInjectorModule struct {
	Secret uint64 `mapstructure:"secret"`
	Logger *zap.Logger
}

var (
	calHelper *TracingHelperChild
	//tracingHelperKV *TracingHelperKV
)

func init() {
	// Initialize the tracer and reporter here if needed
	fmt.Println("##==>TrustFabricInjectorModule init...")
	// Initialize the CalHelper singleton
	calHelper = NewCalHelperChild()
	//tracingHelperKV = NewTracingHelperKV()
}

func (m *TrustFabricInjectorModule) Provision(ctx *core.ModuleContext) error {
	// Assign the logger to the module for non-request related logging
	m.Logger = ctx.Logger

	return nil
}

func (m *TrustFabricInjectorModule) Cleanup() error {
	// Shutdown your module here, close connections etc.
	return nil
}

// core.EnginePostOriginHandler
func (m *TrustFabricInjectorModule) OnOriginResponse(response *http.Response, ctx core.RequestContext) *http.Response {
	// Return a new response or nil if you want to pass it to the next handler
	// If you want to modify the response, return a new response
	fmt.Println("##==>OnOriginResponse..")

	// Access the custom value set in OnOriginRequest
	fmt.Println("##==>OnOriginResponse OnOriginResponse value: ", response.Request.URL, response.StatusCode, response.Header.Get("rlogid"))

	// parentSpanValue, exists := ctx.Get("parentSpan")
	// if exists {
	// 	if parentSpan, ok := parentSpanValue.(opentracing.Span); ok {
	// 		tracingHelperKV.SubmitStreamRlogid(response.Header.Get("rlogid"), "Forward_RLOGID", parentSpan)
	// 	}
	// }
	return nil
}

// core.RouterOnRequestHandler
func (m *TrustFabricInjectorModule) OnOriginRequest(request *http.Request, ctx core.RequestContext) (*http.Request, *http.Response) {
	fmt.Println("##==>OnOriginRequest..")

	// Pass the rlogid to all subgraphs
	fmt.Println("##==>OnOriginRequest Setting new rlogid into subgraph request header:", ctx.GetString("currentLogId"))
	request.Header.Set("rlogid", ctx.GetString("currentLogId"))

	return request, nil
}

// core.RouterMiddlewareHandler
// execute once
func (m *TrustFabricInjectorModule) Middleware(ctx core.RequestContext, next http.Handler) {
	fmt.Println("##==>Middleware..")

	// relogid from upstream request
	upstreamRlogid := ctx.Request().Header.Get("rlogid")
	if upstreamRlogid == "" {
		fmt.Println("##==>Middleware rlogid is missing in the request")
	} else {
		fmt.Println("##==>Middleware rlogid from upstream request:", upstreamRlogid)
	}

	currentLogId := GenerateNewRlogId("wgrouter", 0) // Use 0 for threadId to generate a new one
	fmt.Println("##==>Middleware Setting new rlogid in request header:", currentLogId)
	ctx.Set("currentLogId", currentLogId)

	// init parent span
	parentSpan := startParentSpan()
	//defer parentSpan.Finish() // 确保这里有 Finish()

	// submit current rlogid with tracer
	calHelper.SubmitCurrentRlogidWithTracer(currentLogId, upstreamRlogid, GetRci(ctx.Request()), GetRi(ctx.Request()), parentSpan)
	// submit upstream rlogid with tracer
	//calHelper.SubmitStreamRlogidWithTracer(upstreamRlogid, GetRci(ctx.Request()), GetRi(ctx.Request()), "Backward_RLOGID", parentSpan)

	//tracingHelperKV.SubmitCurrentRlogid(currentLogId, GetRci(ctx.Request()), GetRi(ctx.Request()), parentSpan)
	//tracingHelperKV.SubmitStreamRlogid(upstreamRlogid, GetRci(ctx.Request()), GetRi(ctx.Request()), "Backward_RLOGID", parentSpan)

	ctx.Set("parentSpan", parentSpan)

	ctx.ResponseWriter().Header().Set("rlogid", ctx.GetString("currentLogId"))

	next.ServeHTTP(ctx.ResponseWriter(), ctx.Request())

	parentSpan.Finish()
}

func (m *TrustFabricInjectorModule) Module() core.ModuleInfo {
	// Logger is not yet available here!
	fmt.Println("##==>Module Init...")
	return core.ModuleInfo{
		// This is the ID of your module, it must be unique
		ID: ModuleID,
		// The priority of your module, lower numbers are executed first
		Priority: 1,
		New: func() core.Module {
			return &TrustFabricInjectorModule{}
		},
	}
}

func startParentSpan() opentracing.Span {
	span := tracer.StartSpan("URL")
	span.SetTag(cal.CalTagName, "URL")
	span.SetTag(cal.CalTagStatus, "0")
	span.SetTag(cal.CalTagThreadID, cal.AssignThreadID())
	span.SetTag(cal.CalTagType, "URL_ADMIN")
	//defer span.Finish()

	return span
}

// Interface guard
var (
	_ core.RouterMiddlewareHandler = (*TrustFabricInjectorModule)(nil)
	_ core.EnginePreOriginHandler  = (*TrustFabricInjectorModule)(nil)
	_ core.EnginePostOriginHandler = (*TrustFabricInjectorModule)(nil)
	_ core.Provisioner             = (*TrustFabricInjectorModule)(nil)
	_ core.Cleaner                 = (*TrustFabricInjectorModule)(nil)
)
