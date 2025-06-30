package main

import (
	"fmt"

	routercmd "github.com/wundergraph/cosmo/router/cmd"
	// Import your modules here
	_ "github.com/wundergraph/cosmo/router/cmd/custom-ebay-tf-injector/module"
)

func main() {
	fmt.Println("##==>custom-ebay-tf-injector main")
	routercmd.Main()
}
