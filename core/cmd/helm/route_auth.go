package main

import (
	"net/http"

	helmauth "github.com/Mindburn-Labs/helm-oss/core/pkg/auth"
)

func protectRuntimeHandler(auth RouteAuth, handler http.HandlerFunc) http.HandlerFunc {
	switch auth {
	case RouteAuthPublic, RouteAuthService:
		return handler
	case RouteAuthAdmin, RouteAuthAuthenticated, RouteAuthTenant:
		protected := helmauth.RequireAdminAuth(handler)
		return protected.ServeHTTP
	default:
		protected := helmauth.RequireAdminAuth(handler)
		return protected.ServeHTTP
	}
}
