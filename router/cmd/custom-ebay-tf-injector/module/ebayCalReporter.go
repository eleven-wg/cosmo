package module

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	cal "ebay.com/security-platform/cal-client-go"
	"github.com/google/uuid"
	"github.com/opentracing/opentracing-go"
)

// RequestContext 请求上下文
type RequestContext struct {
	RLogID        string
	CorrelationID string
	ThreadID      int64
	StartTime     time.Time
	EDPContext    *EDPContext
	TraceID       string
	SpanID        string
	ParentRLogID  string
	IsService     bool
	IsSecure      bool
}

// EDPContext EDP 相关上下文
type EDPContext struct {
	CorrID  string
	Channel string
}

// ElevenCalReporter CAL 上报器
type ElevenCalReporter struct {
	calReporter *cal.CalReporter
	tracer      opentracing.Tracer
	poolName    string
	environment string
}

// 初始化 CAL 上报器
func NewElevenCalReporter() (*ElevenCalReporter, error) {

	// 创建 CAL Reporter
	calReporter := reporter
	tracer := tracer

	return &ElevenCalReporter{
		calReporter: calReporter,
		tracer:      tracer,
		poolName:    poolName,
		environment: environment,
	}, nil
}

// 处理请求并生成上下文
func (c *ElevenCalReporter) ProcessRequest(req *http.Request, rlogid string) (*RequestContext, error) {
	startTime := time.Now()

	// 生成线程ID（简单的递增ID或者使用时间戳）
	threadID := time.Now().UnixNano() % 65536

	// 生成 RLogID
	//rlogid := c.generateRLogID(startTime, threadID)

	// 获取父请求的 RLogID
	parentRLogID := c.extractParentRLogID(req)

	// 处理 EDP 上下文
	edpContext := c.processEDPContext(req)

	// 提取 OTEL 信息
	traceID, spanID := c.extractOTELInfo(req)

	// 创建请求上下文
	ctx := &RequestContext{
		RLogID:        rlogid,
		CorrelationID: edpContext.CorrID,
		ThreadID:      threadID,
		StartTime:     startTime,
		EDPContext:    edpContext,
		TraceID:       traceID,
		SpanID:        spanID,
		ParentRLogID:  parentRLogID,
		IsService:     c.isServiceRequest(req),
		IsSecure:      c.isSecureRequest(req),
	}

	// 开始上报流程
	err := c.reportRequestStart(ctx, req)
	if err != nil {
		fmt.Println("Error reporting request start:", err)
	}

	return ctx, nil
}

// // 生成 RLogID（参考 commons-ebay 的实现）
// func (c *ElevenCalReporter) generateRLogID(startTime time.Time, threadID int64) string {
// 	machineName := c.getMachineName()
// 	ts := startTime.UnixMilli()

// 	return fmt.Sprintf("%s-%s-0x%s",
// 		machineName,
// 		strconv.FormatInt(ts, 16),
// 		strconv.FormatInt(threadID, 16))
// }

// // 获取机器名（参考 commons-ebay 逻辑）
// func (c *ElevenCalReporter) getMachineName() string {
// 	poolName := c.poolName

// 	// staging 环境处理
// 	if os.Getenv("PAAS_REALM") == "staging" {
// 		if odbName := os.Getenv("ODBMO_NAME"); odbName != "" {
// 			poolName += "-" + odbName
// 		}
// 	}

// 	// 容器环境处理
// 	if os.Getenv("CONTAINER_PDLC") != "" {
// 		if calPoolName := os.Getenv("CAL_POOL_NAME"); calPoolName != "" {
// 			poolName = calPoolName
// 		}
// 	}

// 	hostname, _ := os.Hostname()
// 	hostname = c.cleanHostname(hostname)

// 	machineStr := poolName + "::" + hostname
// 	encrypted := c.encrypt(machineStr)

// 	return url.QueryEscape(encrypted)
// }

// 清理 hostname
func (c *ElevenCalReporter) cleanHostname(hostname string) string {
	hostname = strings.TrimPrefix(hostname, "http://")
	hostname = strings.TrimPrefix(hostname, "https://")

	if idx := strings.Index(hostname, ":"); idx > 0 {
		hostname = hostname[:idx]
	}

	return hostname
}

// 简单的异或加密（参考 commons-ebay）
// func (c *ElevenCalReporter) encrypt(str string) string {
// 	xorKeys := []byte{6, 7, 3, 5}
// 	result := make([]byte, len(str))
// 	for i, char := range []byte(str) {
// 		result[i] = char ^ xorKeys[i%4]
// 	}
// 	return string(result)
// }

// 上报请求开始
func (c *ElevenCalReporter) reportRequestStart(ctx *RequestContext, req *http.Request) error {
	// 1. 创建主 span
	span := c.tracer.StartSpan("URL")
	span.SetTag(cal.CalTagName, "REQUEST_START")
	span.SetTag(cal.CalTagStatus, "0")
	span.SetTag("thread_id", fmt.Sprintf("0x%x", ctx.ThreadID))
	span.SetTag("rlogid", ctx.RLogID)
	span.SetTag("correlation_id", ctx.CorrelationID)

	// 2. 上报客户端信息
	c.reportClientInfo(span, req, ctx)

	// 3. 上报 OTEL 信息
	if ctx.TraceID != "" && ctx.SpanID != "" {
		c.reportOTELInfo(span, ctx)
	}

	// 4. 上报安全信息
	c.reportSecurityInfo(span, ctx)

	// 5. 上报反向 RLogID 关联
	if ctx.ParentRLogID != "" {
		c.reportBackwardRLogID(span, ctx)
	}

	// 6. 上报 EDP 信息
	c.reportEDPInfo(span, ctx)

	// 7. 检测 IP 欺骗
	c.checkIPSpoofing(span, req)

	span.Finish()
	return nil
}

// 上报客户端信息
func (c *ElevenCalReporter) reportClientInfo(span opentracing.Span, req *http.Request, ctx *RequestContext) {
	clientSpan := c.tracer.StartSpan("URL", opentracing.ChildOf(span.Context()))
	clientSpan.SetTag(cal.CalTagName, "ClientInfo")
	clientSpan.SetTag(cal.CalTagStatus, "0")

	// 添加客户端相关信息
	clientSpan.SetTag("user_agent", req.Header.Get("User-Agent"))
	clientSpan.SetTag("remote_addr", req.RemoteAddr)
	clientSpan.SetTag("method", req.Method)
	clientSpan.SetTag("url", req.URL.String())

	clientSpan.Finish()
}

// 上报负载信息
func (c *ElevenCalReporter) reportPayloadInfo(span opentracing.Span, req *http.Request, ctx *RequestContext) {
	payloadSpan := c.tracer.StartSpan("URL", opentracing.ChildOf(span.Context()))
	payloadSpan.SetTag(cal.CalTagName, "Payload")
	payloadSpan.SetTag(cal.CalTagStatus, "0")

	// 添加负载相关信息
	payloadSpan.SetTag("content_length", req.ContentLength)
	payloadSpan.SetTag("content_type", req.Header.Get("Content-Type"))

	payloadSpan.Finish()
}

// 上报 OTEL 信息
func (c *ElevenCalReporter) reportOTELInfo(span opentracing.Span, ctx *RequestContext) {
	otelSpan := c.tracer.StartSpan("OTEL", opentracing.ChildOf(span.Context()))
	otelSpan.SetTag(cal.CalTagName, "OTEL")
	otelSpan.SetTag(cal.CalTagStatus, "0")
	otelSpan.SetTag("spanId", ctx.SpanID)
	otelSpan.SetTag("traceId", ctx.TraceID)
	otelSpan.SetTag("OTELSampled", "true")

	otelSpan.Finish()
}

// 上报安全信息
func (c *ElevenCalReporter) reportSecurityInfo(span opentracing.Span, ctx *RequestContext) {
	securitySpan := c.tracer.StartSpan("URL", opentracing.ChildOf(span.Context()))
	securitySpan.SetTag(cal.CalTagName, "isSecure")
	securitySpan.SetTag(cal.CalTagStatus, "0")
	securitySpan.SetTag("secure", strconv.FormatBool(ctx.IsSecure))

	securitySpan.Finish()
}

// 上报反向 RLogID 关联
func (c *ElevenCalReporter) reportBackwardRLogID(span opentracing.Span, ctx *RequestContext) {
	backwardSpan := c.tracer.StartSpan("URL", opentracing.ChildOf(span.Context()))
	backwardSpan.SetTag(cal.CalTagName, "Backward_RLOGID")
	backwardSpan.SetTag(cal.CalTagStatus, "0")
	backwardSpan.SetTag("parent_rlogid", ctx.ParentRLogID)
	backwardSpan.SetTag("current_rlogid", ctx.RLogID)

	backwardSpan.Finish()

	// 上报父子关系
	relationSpan := c.tracer.StartSpan("URL", opentracing.ChildOf(span.Context()))
	relationSpan.SetTag(cal.CalTagName, "RLOGID_PARENT_CHILD")
	relationSpan.SetTag(cal.CalTagStatus, "0")
	relationSpan.SetTag("parent", ctx.ParentRLogID)
	relationSpan.SetTag("current", ctx.RLogID)
	relationSpan.SetTag("timestamp", strconv.FormatInt(time.Now().UnixMilli(), 10))

	relationSpan.Finish()
}

// 上报 EDP 信息
func (c *ElevenCalReporter) reportEDPInfo(span opentracing.Span, ctx *RequestContext) {
	edpSpan := c.tracer.StartSpan("edp", opentracing.ChildOf(span.Context()))
	edpSpan.SetTag(cal.CalTagName, "header")
	edpSpan.SetTag(cal.CalTagStatus, "0")
	edpSpan.SetTag("corr_id", ctx.EDPContext.CorrID)
	edpSpan.SetTag("channel", ctx.EDPContext.Channel)
	edpSpan.SetTag("rlogid", ctx.RLogID)

	edpSpan.Finish()
}

// 检测 IP 欺骗
func (c *ElevenCalReporter) checkIPSpoofing(span opentracing.Span, req *http.Request) {
	remoteAddr := req.RemoteAddr
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil && host == "127.0.0.1" {
		spoofingSpan := c.tracer.StartSpan("URL", opentracing.ChildOf(span.Context()))
		spoofingSpan.SetTag(cal.CalTagName, "IP Spoofing Detected")
		spoofingSpan.SetTag(cal.CalTagStatus, "1") // 警告状态

		spoofingSpan.SetTag("x-ebay-akamai-9", req.Header.Get("x-ebay-akamai-9"))
		spoofingSpan.SetTag("x-ebay-client-ip", req.Header.Get("x-ebay-client-ip"))
		spoofingSpan.SetTag("x-forwarded-for", req.Header.Get("x-forwarded-for"))

		spoofingSpan.Finish()
	}
}

// 提取父请求的 RLogID
func (c *ElevenCalReporter) extractParentRLogID(req *http.Request) string {
	if rlogid := req.Header.Get("rlogid"); rlogid != "" {
		return rlogid
	}
	return req.Header.Get("x-ebay-rlogid")
}

// 处理 EDP 上下文
func (c *ElevenCalReporter) processEDPContext(req *http.Request) *EDPContext {
	edp := &EDPContext{}

	// 从 x-ebay-edp 头解析
	if edpHeader := req.Header.Get("x-ebay-edp"); edpHeader != "" {
		c.parseEDPHeader(edpHeader, edp)
	}

	// 如果没有 corr_id，生成新的
	if edp.CorrID == "" {
		edp.CorrID = uuid.New().String()
	}

	// 确定 channel
	if edp.Channel == "" {
		if c.isServiceRequest(req) {
			if c.isAjaxRequest(req) {
				edp.Channel = "WEB"
			} else {
				edp.Channel = "NATIVE"
			}
		} else {
			edp.Channel = "WEB"
		}
	}

	return edp
}

// 解析 EDP 头（简化版本）
func (c *ElevenCalReporter) parseEDPHeader(header string, edp *EDPContext) {
	parts := strings.Split(header, ";")
	for _, part := range parts {
		if kv := strings.Split(part, "="); len(kv) == 2 {
			key := strings.TrimSpace(kv[0])
			value := strings.TrimSpace(kv[1])

			switch key {
			case "corr_id":
				edp.CorrID = value
			case "channel":
				edp.Channel = value
			}
		}
	}
}

// 提取 OTEL 信息
func (c *ElevenCalReporter) extractOTELInfo(req *http.Request) (traceID, spanID string) {
	// 从请求头或上下文中提取 OTEL 信息
	traceID = req.Header.Get("x-trace-id")
	spanID = req.Header.Get("x-span-id")

	// 也可以从 B3 格式的头中提取
	if traceID == "" {
		traceID = req.Header.Get("x-b3-traceid")
	}
	if spanID == "" {
		spanID = req.Header.Get("x-b3-spanid")
	}

	return
}

// 判断是否为服务请求
func (c *ElevenCalReporter) isServiceRequest(req *http.Request) bool {
	return req.Header.Get("x-ebay-service") != ""
}

// 判断是否为 Ajax 请求
func (c *ElevenCalReporter) isAjaxRequest(req *http.Request) bool {
	return req.Header.Get("X-Requested-With") == "XMLHttpRequest"
}

// 判断是否为安全连接
func (c *ElevenCalReporter) isSecureRequest(req *http.Request) bool {
	return req.TLS != nil ||
		req.Header.Get("X-Forwarded-Proto") == "https" ||
		strings.Contains(req.Host, ":8082") // 参考 commons-ebay 的逻辑
}

// 构建出站上下文
func (c *ElevenCalReporter) BuildOutboundContext(ctx *RequestContext) map[string]string {
	headers := make(map[string]string)

	// 添加 rlogid
	headers["rlogid"] = ctx.RLogID
	headers["x-ebay-rlogid"] = ctx.RLogID

	// 添加 EDP 头
	edpHeader := fmt.Sprintf("corr_id=%s;channel=%s", ctx.EDPContext.CorrID, ctx.EDPContext.Channel)
	headers["x-ebay-edp"] = edpHeader

	// 添加关联ID
	if ctx.CorrelationID != "" {
		headers["x-ebay-correlation-id"] = ctx.CorrelationID
	}

	// 添加 OTEL 头
	if ctx.TraceID != "" {
		headers["x-trace-id"] = ctx.TraceID
		headers["x-b3-traceid"] = ctx.TraceID
	}
	if ctx.SpanID != "" {
		headers["x-span-id"] = ctx.SpanID
		headers["x-b3-spanid"] = ctx.SpanID
	}

	// 上报出站事件
	span := c.tracer.StartSpan("URL")
	span.SetTag(cal.CalTagName, "OUTBOUND_REQUEST")
	span.SetTag(cal.CalTagStatus, "0")
	span.SetTag("thread_id", fmt.Sprintf("0x%x", ctx.ThreadID))
	span.SetTag("rlogid", ctx.RLogID)
	span.SetTag("target_headers_count", strconv.Itoa(len(headers)))
	span.SetTag("corr_id", ctx.EDPContext.CorrID)
	span.Finish()

	return headers
}

// 完成请求
func (c *ElevenCalReporter) CompleteRequest(ctx *RequestContext, statusCode int, err error) {
	duration := time.Since(ctx.StartTime)

	span := c.tracer.StartSpan("URL")
	span.SetTag(cal.CalTagName, "REQUEST_COMPLETE")
	span.SetTag("thread_id", fmt.Sprintf("0x%x", ctx.ThreadID))
	span.SetTag("rlogid", ctx.RLogID)
	span.SetTag("status_code", strconv.Itoa(statusCode))
	span.SetTag("duration_ms", strconv.FormatInt(duration.Milliseconds(), 10))

	if err != nil {
		span.SetTag(cal.CalTagStatus, "1") // 错误状态
		span.SetTag("error", err.Error())
	} else if statusCode >= 400 {
		span.SetTag(cal.CalTagStatus, "1") // 警告状态
	} else {
		span.SetTag(cal.CalTagStatus, "0") // 成功状态
	}

	span.Finish()
}

// 关闭上报器
func (c *ElevenCalReporter) Close() {
	if c.calReporter != nil {
		c.calReporter.Close()
	}
}

// // 中间件函数
// func (c *ElevenCalReporter) Middleware(next http.Handler) http.Handler {
// 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		// 处理请求
// 		ctx, err := c.ProcessRequest(r)
// 		if err != nil {
// 			fmt.Printf("Error processing request: %v\n", err)
// 		}

// 		// 将上下文存储到请求中
// 		r = r.WithContext(context.WithValue(r.Context(), "cal_context", ctx))

// 		// 创建响应写入器包装器以捕获状态码
// 		wrapper := &responseWriter{ResponseWriter: w, statusCode: 200}

// 		// 调用下一个处理器
// 		next.ServeHTTP(wrapper, r)

// 		// 完成请求
// 		c.CompleteRequest(ctx, wrapper.statusCode, nil)
// 	})
// }

// 响应写入器包装器
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// 从上下文中获取 CAL 上下文
func GetCalContextFromRequest(r *http.Request) *RequestContext {
	if ctx := r.Context().Value("cal_context"); ctx != nil {
		if calCtx, ok := ctx.(*RequestContext); ok {
			return calCtx
		}
	}
	return nil
}

// 使用示例
func main() {
	// 创建 CAL 上报器
	reporter, err := NewElevenCalReporter("my-service-pool", "prod", "cal.vip.qa.ebay.com:1118")
	if err != nil {
		panic(err)
	}
	defer reporter.Close()

	// 创建 HTTP 服务器
	mux := http.NewServeMux()

	// 添加业务处理器
	mux.HandleFunc("/api/test", func(w http.ResponseWriter, r *http.Request) {
		// 获取 CAL 上下文
		calCtx := GetCalContextFromRequest(r)
		if calCtx != nil {
			fmt.Printf("Request RLogID: %s\n", calCtx.RLogID)
			fmt.Printf("EDP Corr ID: %s\n", calCtx.EDPContext.CorrID)

			// 如果需要调用其他服务，构建出站上下文
			outboundHeaders := reporter.BuildOutboundContext(calCtx)
			fmt.Printf("Outbound Headers: %v\n", outboundHeaders)
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello, World!"))
	})

	// 使用中间件包装处理器
	handler := reporter.Middleware(mux)

	fmt.Println("Starting server on :8080")
	http.ListenAndServe(":8080", handler)
}

// 测试函数
func TestElevenCalReporter() {
	// 创建 CAL 上报器
	reporter, err := NewElevenCalReporter()
	if err != nil {
		fmt.Printf("Error creating reporter: %v\n", err)
		return
	}
	defer reporter.Close()

	// 模拟处理请求
	req, _ := http.NewRequest("GET", "/api/test", nil)
	req.Header.Set("rlogid", "parent-rlogid-123")
	req.Header.Set("x-ebay-edp", "corr_id=existing-corr-id;channel=WEB")
	req.Header.Set("x-trace-id", "trace-123")
	req.Header.Set("x-span-id", "span-456")
	req.Header.Set("User-Agent", "Test-Agent/1.0")
	req.RemoteAddr = "192.168.1.100:12345"

	// 处理请求
	ctx, err := reporter.ProcessRequest(req)
	if err != nil {
		fmt.Printf("Error processing request: %v\n", err)
	} else {
		fmt.Printf("Generated RLogID: %s\n", ctx.RLogID)
		fmt.Printf("EDP Corr ID: %s\n", ctx.EDPContext.CorrID)
		fmt.Printf("Channel: %s\n", ctx.EDPContext.Channel)
		fmt.Printf("Parent RLogID: %s\n", ctx.ParentRLogID)
		fmt.Printf("Is Secure: %v\n", ctx.IsSecure)
	}

	// 构建出站上下文
	if ctx != nil {
		outboundHeaders := reporter.BuildOutboundContext(ctx)
		fmt.Printf("Outbound Headers: %v\n", outboundHeaders)

		// 模拟业务逻辑处理时间
		time.Sleep(100 * time.Millisecond)

		// 完成请求
		reporter.CompleteRequest(ctx, 200, nil)
	}
}
