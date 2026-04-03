package service

import (
	"context"
	"log"
	"time"

	"api-protection/internal/pipeline"
	"api-protection/internal/store"
	"api-protection/pkg/kafka"
	pb "api-protection/proto/genProto"
)

// AlertPublisher publishes security alerts to a messaging system.
type AlertPublisher interface {
	PublishAlert(ctx context.Context, record *kafka.AlertRecord) error
}

// SecurityService holds the business logic for request verification.
type SecurityService struct {
	store          store.Store
	alertPublisher AlertPublisher
	pipeline       *pipeline.Pipeline
}

// NewSecurityService creates a new security service instance.
func NewSecurityService(store store.Store, alertPublisher AlertPublisher, pipe *pipeline.Pipeline) *SecurityService {
	if pipe == nil {
		cfg := pipeline.FromEnv()
		pipe = pipeline.BuildDefaultPipeline(cfg, store)
	}
	return &SecurityService{
		store:          store,
		alertPublisher: alertPublisher,
		pipeline:       pipe,
	}
}

// Verify decides whether to allow or deny a request.
func (s *SecurityService) Verify(ctx context.Context, req *pb.VerifyRequest) (*pb.VerifyResponse, error) {
	sc := pipeline.NewSecurityContext(req)
	s.pipeline.Run(ctx, sc)
	return s.finishVerify(ctx, req, sc), nil
}

func (s *SecurityService) finishVerify(ctx context.Context, req *pb.VerifyRequest, sc *pipeline.SecurityContext) *pb.VerifyResponse {
	resp := sc.Response
	if err := s.store.SaveLog(ctx, req, resp); err != nil {
		log.Printf("service: SaveLog failed (verdict still returned): %v", err)
	}

	if resp.Verdict == pb.Verdict_DENY && s.alertPublisher != nil {
		record := &kafka.AlertRecord{
			Timestamp:  time.Now().UTC(),
			RequestID:  req.GetRequestId(),
			Path:       req.GetPath(),
			Method:     req.GetMethod(),
			ClientIP:   req.GetClientIp(),
			Decision:   resp.GetVerdict().String(),
			Reason:     resp.GetReason(),
			UserID:     resp.GetUserId(),
			HTTPStatus: resp.GetHttpStatus(),
		}
		go func() {
			if err := s.alertPublisher.PublishAlert(context.Background(), record); err != nil {
				log.Printf("service: PublishAlert failed: %v", err)
			}
		}()
	}

	return resp
}
