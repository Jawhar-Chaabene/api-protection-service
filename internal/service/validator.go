package service

import (
	"strings"

	pb "api-protection/proto/genProto"

	"github.com/go-playground/validator/v10"
)

const maxMetadataLen = 256

var validate *validator.Validate

func init() {
	validate = validator.New()
	_ = validate.RegisterValidation("startswith", func(fl validator.FieldLevel) bool {
		s := fl.Field().String()
		prefix := fl.Param()
		return strings.HasPrefix(s, prefix)
	})
}

// VerifyRequestSchema is used for validation; maps from proto VerifyRequest.
type VerifyRequestSchema struct {
	Path     string `validate:"required,min=1,max=2048,startswith=/"`
	Method   string `validate:"required,oneof=GET POST PUT PATCH DELETE HEAD OPTIONS"`
	ClientIP string `validate:"required,ip"`
}

// ValidateRequest validates the request schema and returns an error with field details if invalid.
func ValidateRequest(req *pb.VerifyRequest) error {
	schema := VerifyRequestSchema{
		Path:     req.GetPath(),
		Method:   req.GetMethod(),
		ClientIP: req.GetClientIp(),
	}
	return validate.Struct(&schema)
}
