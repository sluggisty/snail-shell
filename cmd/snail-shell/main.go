package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/sluggisty/snail-shell/internal/config"
	"github.com/sluggisty/snail-shell/internal/generator"
	"github.com/sluggisty/snail-shell/internal/server"
	"github.com/sluggisty/snail-shell/internal/storage"
)

func main() {
	// Parse flags
	configPath := flag.String("config", "", "Path to configuration file")
	debug := flag.Bool("debug", false, "Enable debug logging")
	generateTestData := flag.Bool("generate-test-data", false, "Generate test data instead of running server")
	testDataCount := flag.Int("test-hosts", 50, "Number of test hosts to generate (used with -generate-test-data)")
	flag.Parse()

	// Setup logging
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	if *debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load configuration")
	}

	// Handle test data generation
	if *generateTestData {
		if err := generateData(*testDataCount, *configPath); err != nil {
			log.Fatal().Err(err).Msg("Failed to generate test data")
		}
		return
	}

	log.Info().
		Str("version", "0.1.0").
		Str("listen", cfg.Server.Listen).
		Msg("Starting Snail Shell server")

	// Initialize storage
	store, err := storage.New(cfg.Storage)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize storage")
	}
	defer store.Close()

	// Create and start server
	srv := server.New(cfg, store)
	httpServer := &http.Server{
		Addr:         cfg.Server.Listen,
		Handler:      srv.Router(),
		ReadTimeout:  time.Duration(cfg.Server.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(cfg.Server.WriteTimeout) * time.Second,
		IdleTimeout:  time.Duration(cfg.Server.IdleTimeout) * time.Second,
	}

	// Start server in goroutine
	go func() {
		if cfg.Server.TLSCert != "" && cfg.Server.TLSKey != "" {
			log.Info().Msg("Starting HTTPS server")
			if err := httpServer.ListenAndServeTLS(cfg.Server.TLSCert, cfg.Server.TLSKey); err != nil && err != http.ErrServerClosed {
				log.Fatal().Err(err).Msg("Server failed")
			}
		} else {
			log.Info().Msg("Starting HTTP server")
			if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatal().Err(err).Msg("Server failed")
			}
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info().Msg("Shutting down server...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		log.Error().Err(err).Msg("Server forced to shutdown")
	}

	fmt.Println("Server stopped")
}

// generateData creates test data and stores it
func generateData(count int, configPath string) error {
	log.Info().Int("count", count).Msg("Generating test data")
	
	// Load config to get storage settings
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}
	
	// Initialize storage
	store, err := storage.New(cfg.Storage)
	if err != nil {
		return fmt.Errorf("failed to initialize storage: %w", err)
	}
	defer store.Close()
	
	// Create generator
	gen := generator.New()
	
	// Generate hosts
	reports, err := gen.GenerateHosts(count)
	if err != nil {
		return fmt.Errorf("failed to generate hosts: %w", err)
	}
	
	// Store each report
	log.Info().Msg("Storing test data...")
	for i, report := range reports {
		if err := store.SaveHost(report); err != nil {
			return fmt.Errorf("failed to save host %s: %w", report.Meta.Hostname, err)
		}
		
		if (i+1)%10 == 0 {
			log.Info().Int("progress", i+1).Int("total", count).Msg("Progress")
		}
	}
	
	log.Info().
		Int("hosts_created", len(reports)).
		Msg("Test data generation complete!")
	
	return nil
}
