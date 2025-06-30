package module

import (
	"fmt"

	"ebay.com/security-platform/cal-client-go"
	"github.com/opentracing/opentracing-go"
	"github.com/uber/jaeger-client-go"
)

// singleton tracer and reporter
var (
	tracer   opentracing.Tracer
	reporter *cal.CalReporter
)

// init tracer and reporter
func init() {
	fmt.Println("1. cal config")
	config := cal.NewConfigBuilder().
		ServerAddress("cal.vip.qa.ebay.com:1118").
		CalPoolName("wgrouter").
		BufferSize(512000).
		SamplingRate(1).
		ConnectionPoolSize(10).
		ClassOfService("core_staging").
		Build()

	fmt.Println("2. calrepoter config:", config)
	reporter = cal.NewCalReporter(config)

	fmt.Println("3. cal reporter created")
	//var err error
	tracer, _ = jaeger.NewTracer(
		"fgql",
		jaeger.NewConstSampler(true),
		reporter)
	// if error != nil {
	// 	fmt.Println("Error creating Jaeger tracer:", error)
	// }
}
