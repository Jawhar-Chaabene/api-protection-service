// Security service entry point. Exposes gRPC for allow/deny verification
// before the gateway forwards requests to the protected application.
package main

import (
	"context"
	"log"
	"net"
	"os"
	"strings"

	"api-protection/internal/handler"
	"api-protection/internal/pipeline"
	"api-protection/internal/service"
	"api-protection/internal/store"
	"api-protection/pkg/kafka"
	pb "api-protection/proto/genProto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
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

	log.Printf("📡 Attempting to connect to MongoDB...")
	log.Printf("   URI: %s", mongoURI)
	log.Printf("   Database: %s", mongoDB)

	mongoStore, err := store.NewMongoStore(ctx, mongoURI, mongoDB)
	if err != nil {
		log.Fatalf("❌ Failed to connect to MongoDB: %v", err)
	}
	log.Printf("✅ Successfully connected to MongoDB")
	log.Printf("✅ Database '%s' and collection 'security_logs' initialized", mongoDB)

	defer func() {
		if err := mongoStore.Close(context.Background()); err != nil {
			log.Printf("⚠️  MongoDB close error: %v", err)
		} else {
			log.Printf("✅ MongoDB connection closed successfully")
		}
	}()

	producer, err := kafka.NewProducer(kafkaBrokers)
	if err != nil {
		log.Fatalf("failed to create Kafka producer: %v", err)
	}
	defer producer.Close()

	cfg := pipeline.FromEnv()
	pipe := pipeline.BuildDefaultPipeline(cfg, mongoStore)
	svc := service.NewSecurityService(mongoStore, producer, pipe)
	h := handler.NewSecurityGRPCHandler(svc)

	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	defer lis.Close()

	grpcServer := grpc.NewServer()
	pb.RegisterSecurityServiceServer(grpcServer, h)
	reflection.Register(grpcServer)

	log.Println("✅ Security Service listening on :50051")
	log.Println("✅ gRPC Reflection enabled (Postman compatible)")
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("grpc serve: %v", err)
	}
}
