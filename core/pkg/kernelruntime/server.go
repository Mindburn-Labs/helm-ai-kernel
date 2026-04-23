package kernelruntime

import (
	"net/http"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/config"
)

type Server struct{}

func New(cfg *config.Config) *Server {
	return &Server{}
}

func (s *Server) Start() error {
	return http.ErrServerClosed
}
