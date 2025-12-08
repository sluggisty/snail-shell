package server

import (
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/sluggisty/snail-shell/internal/config"
	"github.com/sluggisty/snail-shell/internal/handlers"
	"github.com/sluggisty/snail-shell/internal/storage"
)

// Server represents the HTTP server
type Server struct {
	config  *config.Config
	storage storage.Storage
	router  chi.Router
}

// New creates a new server instance
func New(cfg *config.Config, store storage.Storage) *Server {
	s := &Server{
		config:  cfg,
		storage: store,
	}
	s.setupRoutes()
	return s
}

// Router returns the chi router
func (s *Server) Router() chi.Router {
	return s.router
}

func (s *Server) setupRoutes() {
	r := chi.NewRouter()

	// Middleware stack
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(LoggerMiddleware)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Compress(5))

	// Create handlers
	h := handlers.New(s.storage)

	// Health and info endpoints (no auth required)
	r.Get("/health", h.Health)
	r.Get("/", h.Info)

	// API routes
	r.Route("/api/v1", func(r chi.Router) {
		// Apply auth middleware if enabled
		if s.config.Auth.Enabled && !s.config.Auth.AllowAll {
			r.Use(AuthMiddleware(s.config.Auth.APIKeys))
		}

		// Ingest endpoint - receives reports from snail-core
		r.Post("/ingest", h.Ingest)

		// Query endpoints
		r.Get("/reports", h.ListReports)
		r.Get("/reports/{id}", h.GetReport)
		r.Delete("/reports/{id}", h.DeleteReport)

		// Summary endpoints
		r.Get("/hosts", h.ListHosts)
		r.Get("/hosts/{hostname}", h.GetHost)
		r.Get("/hosts/{hostname}/reports", h.GetHostReports)
	})

	s.router = r
}
