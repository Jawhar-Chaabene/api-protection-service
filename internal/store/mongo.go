package store

import (
	"context"
	"errors"
	"log"
	"time"

	"api-protection/internal/pipeline"
	pb "api-protection/proto/genProto"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	securityLogsCollection = "security_logs"
	apiKeysCollection      = "api_keys"
	policiesCollection     = "policies"
)

// LogEntry represents a security verification log stored in MongoDB.
type LogEntry struct {
	RequestID     string    `bson:"request_id"`
	Path          string    `bson:"path"`
	Method        string    `bson:"method"`
	ClientIP      string    `bson:"client_ip"`
	Decision      string    `bson:"decision"`
	Reason        string    `bson:"reason"`
	UserID        string    `bson:"user_id,omitempty"`
	Roles         []string  `bson:"roles,omitempty"`
	APIKeyID      string    `bson:"api_key_id,omitempty"`
	HTTPStatus    int32     `bson:"http_status"`
	CorrelationID string    `bson:"correlation_id"`
	Timestamp     time.Time `bson:"timestamp"`
}

// APIKey describes API key records persisted in MongoDB.
type APIKey struct {
	ID        string    `bson:"_id"`
	KeyHash   string    `bson:"key_hash"`
	Name      string    `bson:"name"`
	Status    string    `bson:"status"`
	OwnerID   string    `bson:"owner_id"`
	CreatedAt time.Time `bson:"created_at"`
	ExpiresAt time.Time `bson:"expires_at"`
}

// Policy is reserved for future route policy management.
type Policy struct {
	ID        string    `bson:"_id"`
	Path      string    `bson:"path"`
	Method    string    `bson:"method"`
	Role      string    `bson:"role"`
	CreatedAt time.Time `bson:"created_at"`
}

// Store defines the interface for persisting verification logs.
type Store interface {
	SaveLog(ctx context.Context, request *pb.VerifyRequest, response *pb.VerifyResponse) error
	ValidateAPIKey(ctx context.Context, keyHash string) (*pipeline.APIKeyRecord, error)
	GetPolicy(ctx context.Context, path, method string) (*Policy, error)
}

// MongoStore implements Store using MongoDB.
type MongoStore struct {
	client         *mongo.Client
	logsCollection *mongo.Collection
	keysCollection *mongo.Collection
	polCollection  *mongo.Collection
}

// NewMongoStore creates a MongoDB store and verifies the connection.
func NewMongoStore(ctx context.Context, uri, dbName string) (*MongoStore, error) {
	log.Printf("[MongoDB] Connecting to: %s", uri)
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		log.Printf("[MongoDB] ❌ Connection failed: %v", err)
		return nil, err
	}
	log.Printf("[MongoDB] ✅ Client created successfully")

	log.Printf("[MongoDB] Pinging server to verify connection...")
	if err := client.Ping(ctx, nil); err != nil {
		log.Printf("[MongoDB] ❌ Ping failed: %v", err)
		_ = client.Disconnect(ctx)
		return nil, err
	}
	log.Printf("[MongoDB] ✅ Server ping successful")

	log.Printf("[MongoDB] Getting database: %s", dbName)
	database := client.Database(dbName)
	log.Printf("[MongoDB] ✅ Database '%s' ready", dbName)

	log.Printf("[MongoDB] Getting collection: %s", securityLogsCollection)
	logsCollection := database.Collection(securityLogsCollection)
	keysCollection := database.Collection(apiKeysCollection)
	polCollection := database.Collection(policiesCollection)
	log.Printf("[MongoDB] ✅ Collections initialized: %s, %s, %s", securityLogsCollection, apiKeysCollection, policiesCollection)

	return &MongoStore{
		client:         client,
		logsCollection: logsCollection,
		keysCollection: keysCollection,
		polCollection:  polCollection,
	}, nil
}

// SaveLog persists the request metadata and verification decision.
func (m *MongoStore) SaveLog(ctx context.Context, request *pb.VerifyRequest, response *pb.VerifyResponse) error {
	entry := LogEntry{
		RequestID:     request.GetRequestId(),
		Path:          request.GetPath(),
		Method:        request.GetMethod(),
		ClientIP:      request.GetClientIp(),
		Decision:      response.GetVerdict().String(),
		Reason:        response.GetReason(),
		UserID:        response.GetUserId(),
		Roles:         response.GetRoles(),
		HTTPStatus:    response.GetHttpStatus(),
		CorrelationID: response.GetCorrelationId(),
		Timestamp:     time.Now().UTC(),
	}

	_, err := m.logsCollection.InsertOne(ctx, entry)
	if err != nil {
		log.Printf("store: failed to save log: %v", err)
		return err
	}
	return nil
}

// ValidateAPIKey checks if an API key hash exists and returns key metadata.
func (m *MongoStore) ValidateAPIKey(ctx context.Context, keyHash string) (*pipeline.APIKeyRecord, error) {
	var key APIKey
	err := m.keysCollection.FindOne(ctx, bson.M{"key_hash": keyHash}).Decode(&key)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, pipeline.ErrAPIKeyNotFound
		}
		return nil, err
	}
	return &pipeline.APIKeyRecord{
		ID:        key.ID,
		Status:    key.Status,
		OwnerID:   key.OwnerID,
		ExpiresAt: key.ExpiresAt,
	}, nil
}

// GetPolicy fetches an optional policy record by path and method.
func (m *MongoStore) GetPolicy(ctx context.Context, path, method string) (*Policy, error) {
	var policy Policy
	err := m.polCollection.FindOne(ctx, bson.M{"path": path, "method": method}).Decode(&policy)
	if err != nil {
		return nil, err
	}
	return &policy, nil
}

// Close disconnects the MongoDB client.
func (m *MongoStore) Close(ctx context.Context) error {
	log.Printf("[MongoDB] Disconnecting from MongoDB...")
	return m.client.Disconnect(ctx)
}
