package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	pb "api-protection/proto/genProto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

func sendRequest(client pb.SecurityServiceClient, path, method, clientIP string, roles []string, label string) {
	fmt.Printf("\n%s\n", label)
	fmt.Println(strings.Repeat("-", 60))

	// Create context and add metadata with roles
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if len(roles) > 0 {
		md := metadata.Pairs("x-roles", strings.Join(roles, ","))
		ctx = metadata.NewOutgoingContext(ctx, md)
	}

	fmt.Printf("Request: POST %s | ClientIP: %s | Roles: %v\n", path, clientIP, roles)

	response, err := client.Verify(ctx, &pb.VerifyRequest{
		Path:     path,
		Method:   method,
		ClientIp: clientIP,
	})

	if err != nil {
		fmt.Printf("❌ Error: %v\n", err)
		return
	}

	verdict := "✅ ALLOW"
	if response.Verdict == pb.Verdict_DENY {
		verdict = "❌ DENY"
	}
	fmt.Printf("Response: %s\n", verdict)
	if response.Reason != "" {
		fmt.Printf("Reason: %s\n", response.Reason)
	}
}

func main() {
	// Connect to gRPC server
	conn, err := grpc.Dial("localhost:50051", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	client := pb.NewSecurityServiceClient(conn)

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("SECURITY SERVICE - TEST REQUESTS")
	fmt.Println(strings.Repeat("=", 60))

	// Test 1: Public endpoint (ALLOWED - anonymous)
	sendRequest(client, "/api/public/docs", "GET", "192.168.1.100", []string{}, "Test 1: Public Endpoint (Anonymous)")

	// Test 2: Health check (ALLOWED - anonymous)
	sendRequest(client, "/health", "GET", "192.168.1.100", []string{}, "Test 2: Health Check (Anonymous)")

	// Test 3: Users endpoint without role (DENIED)
	sendRequest(client, "/api/users", "GET", "192.168.1.100", []string{}, "Test 3: Users Endpoint (No Role)")

	// Test 4: Users endpoint with user role (ALLOWED)
	sendRequest(client, "/api/users", "GET", "192.168.1.100", []string{"user"}, "Test 4: Users Endpoint (User Role)")

	// Test 5: Admin endpoint with admin role (ALLOWED)
	sendRequest(client, "/admin/dashboard", "GET", "192.168.1.100", []string{"admin"}, "Test 5: Admin Dashboard (Admin Role)")

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("✅ All tests completed! Check MongoDB Compass for the logs.")
	fmt.Println(strings.Repeat("=", 60) + "\n")
}
