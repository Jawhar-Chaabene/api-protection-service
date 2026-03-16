// Gateway entry point. Receives HTTP requests and consults the security
// service via gRPC before forwarding allowed traffic to the application.
package main

import "fmt"

func main() {
	fmt.Println("Gateway Starting...")
}
