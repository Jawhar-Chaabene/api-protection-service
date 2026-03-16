package store

import (
	"context"
	"log"
	"time"

	pb "api-protection/proto/genProto"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const collectionName = "security_logs"

// LogEntry represents a security verification log stored in MongoDB.
type LogEntry struct {
	Path      string    `bson:"path"`
	Method    string    `bson:"method"`
	ClientIP  string    `bson:"client_ip"`
	Verdict   string    `bson:"verdict"`
	Reason    string    `bson:"reason"`
	Timestamp time.Time `bson:"timestamp"`
}

// Store defines the interface for persisting verification logs.
type Store interface {
	SaveLog(ctx context.Context, request *pb.VerifyRequest, response *pb.VerifyResponse) error
}

// MongoStore implements Store using MongoDB.
type MongoStore struct {
	client     *mongo.Client
	collection *mongo.Collection
}

// NewMongoStore creates a MongoDB store and verifies the connection.
func NewMongoStore(ctx context.Context, uri, dbName string) (*MongoStore, error) {
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		return nil, err
	}

	if err := client.Ping(ctx, nil); err != nil {
		_ = client.Disconnect(ctx)
		return nil, err
	}

	collection := client.Database(dbName).Collection(collectionName)
	return &MongoStore{client: client, collection: collection}, nil
}

// SaveLog persists the request metadata and verification decision.
func (m *MongoStore) SaveLog(ctx context.Context, request *pb.VerifyRequest, response *pb.VerifyResponse) error {
	entry := LogEntry{
		Path:      request.GetPath(),
		Method:    request.GetMethod(),
		ClientIP:  request.GetClientIp(),
		Verdict:   response.GetVerdict().String(),
		Reason:    response.GetReason(),
		Timestamp: time.Now().UTC(),
	}

	_, err := m.collection.InsertOne(ctx, entry)
	if err != nil {
		log.Printf("store: failed to save log: %v", err)
		return err
	}
	return nil
}

// Close disconnects the MongoDB client.
func (m *MongoStore) Close(ctx context.Context) error {
	return m.client.Disconnect(ctx)
}
