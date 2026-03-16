// Security service entry point. Exposes gRPC for allow/deny verification
// before the gateway forwards requests to the protected application.
package main

import (
	"context"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"api-protection/internal/handler"
	"api-protection/internal/interceptor"
	"api-protection/internal/service"
	"api-protection/internal/store"
	"api-protection/pkg/kafka"
	pb "api-protection/proto/genProto"

	"google.golang.org/grpc"
	"golang.org/x/time/rate"
)

func getEnv(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func main() {
	ctx := context.Background()

	mongoURI := getEnv("MONGODB_URI", "mongodb://localhost:27017")
	mongoDB := getEnv("MONGODB_DB", "api_protection")
	kafkaBrokers := strings.Split(getEnv("KAFKA_BROKERS", "localhost:9092"), ",")
	for i, b := range kafkaBrokers {
		kafkaBrokers[i] = strings.TrimSpace(b)
	}

	mongoStore, err := store.NewMongoStore(ctx, mongoURI, mongoDB)
	if err != nil {
		log.Fatalf("failed to connect to MongoDB: %v", err)
	}
	defer func() {
		if err := mongoStore.Close(context.Background()); err != nil {
			log.Printf("mongo close: %v", err)
		}
	}()

	producer, err := kafka.NewProducer(kafkaBrokers)
	if err != nil {
		log.Fatalf("failed to create Kafka producer: %v", err)
	}
	defer producer.Close()

	rlConfig := interceptor.DefaultRateLimitConfig()
	if rps := getEnv("RATE_LIMIT_RPS", ""); rps != "" {
		if n, err := strconv.ParseFloat(rps, 64); err == nil {
			rlConfig.RPS = rate.Limit(n)
		}
	}
	if burst := getEnv("RATE_LIMIT_BURST", ""); burst != "" {
		if n, err := strconv.Atoi(burst); err == nil {
			rlConfig.Burst = n
		}
	}

	chain := grpc.ChainUnaryInterceptor(
		interceptor.NewRateLimitInterceptor(rlConfig),
		interceptor.MetadataInterceptor(),
	)

	svc := service.NewSecurityService(mongoStore, producer, &service.DefaultRBAC{})
	h := handler.NewSecurityGRPCHandler(svc)

	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	defer lis.Close()

	grpcServer := grpc.NewServer(chain)
	pb.RegisterSecurityServiceServer(grpcServer, h)

	log.Println("Security Service listening on :50051")
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("grpc serve: %v", err)
	}
}
