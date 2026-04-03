package kafka

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
)

const topic = "security-alerts"

// AlertRecord represents an alert message sent to Kafka.
type AlertRecord struct {
	Timestamp  time.Time `json:"timestamp"`
	RequestID  string    `json:"request_id"`
	Path       string    `json:"path"`
	Method     string    `json:"method"`
	ClientIP   string    `json:"client_ip"`
	Decision   string    `json:"decision"`
	Reason     string    `json:"reason"`
	UserID     string    `json:"user_id,omitempty"`
	HTTPStatus int32     `json:"http_status"`
}

// Producer wraps a Kafka client for publishing security alerts.
type Producer struct {
	client *kgo.Client
}

// NewProducer creates a Kafka producer with the given brokers.
func NewProducer(brokers []string) (*Producer, error) {
	client, err := kgo.NewClient(kgo.SeedBrokers(brokers...))
	if err != nil {
		return nil, err
	}
	return &Producer{client: client}, nil
}

// PublishAlert sends an alert to the security-alerts topic.
func (p *Producer) PublishAlert(ctx context.Context, record *AlertRecord) error {
	payload, err := json.Marshal(record)
	if err != nil {
		log.Printf("kafka: failed to marshal alert: %v", err)
		return err
	}

	krecord := &kgo.Record{
		Topic: topic,
		Value: payload,
	}

	if err := p.client.ProduceSync(ctx, krecord).FirstErr(); err != nil {
		log.Printf("kafka: failed to publish alert: %v", err)
		return err
	}
	return nil
}

// Close closes the Kafka client.
func (p *Producer) Close() {
	p.client.Close()
}
