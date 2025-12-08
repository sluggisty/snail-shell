package handlers

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"github.com/stillness/snail-shell/internal/models"
	"github.com/stillness/snail-shell/internal/storage"
)

// Handlers contains HTTP handlers
type Handlers struct {
	storage storage.Storage
}

// New creates a new Handlers instance
func New(store storage.Storage) *Handlers {
	return &Handlers{storage: store}
}

// Health returns server health status
func (h *Handlers) Health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

// Info returns server information
func (h *Handlers) Info(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"name":    "snail-shell",
		"version": "0.1.0",
		"description": "Backend service for snail-core system reports",
		"endpoints": map[string]string{
			"health":  "GET /health",
			"ingest":  "POST /api/v1/ingest",
			"reports": "GET /api/v1/reports",
			"hosts":   "GET /api/v1/hosts",
		},
	})
}

// Ingest handles incoming reports from snail-core
func (h *Handlers) Ingest(w http.ResponseWriter, r *http.Request) {
	// Handle gzip-compressed requests
	var reader io.Reader = r.Body
	if r.Header.Get("Content-Encoding") == "gzip" {
		gzReader, err := gzip.NewReader(r.Body)
		if err != nil {
			log.Error().Err(err).Msg("Failed to create gzip reader")
			http.Error(w, `{"error": "failed to decompress request"}`, http.StatusBadRequest)
			return
		}
		defer gzReader.Close()
		reader = gzReader
	}

	// Parse the request
	var req models.IngestRequest
	if err := json.NewDecoder(reader).Decode(&req); err != nil {
		log.Error().Err(err).Msg("Failed to parse ingest request")
		http.Error(w, `{"error": "invalid JSON payload"}`, http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.Meta.Hostname == "" {
		http.Error(w, `{"error": "missing hostname in meta"}`, http.StatusBadRequest)
		return
	}

	// Create report
	now := time.Now().UTC()
	report := &models.Report{
		ID:         uuid.New().String(),
		ReceivedAt: now,
		Meta:       req.Meta,
		Data:       req.Data,
		Errors:     req.Errors,
	}

	// Store the report
	if err := h.storage.SaveReport(report); err != nil {
		log.Error().Err(err).Str("hostname", req.Meta.Hostname).Msg("Failed to save report")
		http.Error(w, `{"error": "failed to store report"}`, http.StatusInternalServerError)
		return
	}

	log.Info().
		Str("report_id", report.ID).
		Str("hostname", req.Meta.Hostname).
		Str("collection_id", req.Meta.CollectionID).
		Int("errors", len(req.Errors)).
		Msg("Report ingested")

	// Send response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(models.IngestResponse{
		Status:     "ok",
		ReportID:   report.ID,
		ReceivedAt: now.Format(time.RFC3339),
		Message:    "Report ingested successfully",
	})
}

// ListReports returns a list of all reports
func (h *Handlers) ListReports(w http.ResponseWriter, r *http.Request) {
	// Parse query params
	limit := 100
	offset := 0
	hostname := r.URL.Query().Get("hostname")

	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	if o := r.URL.Query().Get("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	reports, total, err := h.storage.ListReports(hostname, limit, offset)
	if err != nil {
		log.Error().Err(err).Msg("Failed to list reports")
		http.Error(w, `{"error": "failed to retrieve reports"}`, http.StatusInternalServerError)
		return
	}

	// Convert to summaries
	summaries := make([]models.ReportSummary, len(reports))
	for i, r := range reports {
		summaries[i] = r.ToSummary()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"reports": summaries,
		"total":   total,
		"limit":   limit,
		"offset":  offset,
	})
}

// GetReport returns a specific report by ID
func (h *Handlers) GetReport(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		http.Error(w, `{"error": "missing report id"}`, http.StatusBadRequest)
		return
	}

	report, err := h.storage.GetReport(id)
	if err != nil {
		if err == storage.ErrNotFound {
			http.Error(w, `{"error": "report not found"}`, http.StatusNotFound)
			return
		}
		log.Error().Err(err).Str("id", id).Msg("Failed to get report")
		http.Error(w, `{"error": "failed to retrieve report"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(report)
}

// DeleteReport deletes a report by ID
func (h *Handlers) DeleteReport(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		http.Error(w, `{"error": "missing report id"}`, http.StatusBadRequest)
		return
	}

	if err := h.storage.DeleteReport(id); err != nil {
		if err == storage.ErrNotFound {
			http.Error(w, `{"error": "report not found"}`, http.StatusNotFound)
			return
		}
		log.Error().Err(err).Str("id", id).Msg("Failed to delete report")
		http.Error(w, `{"error": "failed to delete report"}`, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ListHosts returns a list of all known hosts
func (h *Handlers) ListHosts(w http.ResponseWriter, r *http.Request) {
	hosts, err := h.storage.ListHosts()
	if err != nil {
		log.Error().Err(err).Msg("Failed to list hosts")
		http.Error(w, `{"error": "failed to retrieve hosts"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"hosts": hosts,
		"total": len(hosts),
	})
}

// GetHost returns summary for a specific host
func (h *Handlers) GetHost(w http.ResponseWriter, r *http.Request) {
	hostname := chi.URLParam(r, "hostname")
	if hostname == "" {
		http.Error(w, `{"error": "missing hostname"}`, http.StatusBadRequest)
		return
	}

	host, err := h.storage.GetHost(hostname)
	if err != nil {
		if err == storage.ErrNotFound {
			http.Error(w, `{"error": "host not found"}`, http.StatusNotFound)
			return
		}
		log.Error().Err(err).Str("hostname", hostname).Msg("Failed to get host")
		http.Error(w, `{"error": "failed to retrieve host"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(host)
}

// GetHostReports returns all reports for a specific host
func (h *Handlers) GetHostReports(w http.ResponseWriter, r *http.Request) {
	hostname := chi.URLParam(r, "hostname")
	if hostname == "" {
		http.Error(w, `{"error": "missing hostname"}`, http.StatusBadRequest)
		return
	}

	reports, total, err := h.storage.ListReports(hostname, 100, 0)
	if err != nil {
		log.Error().Err(err).Str("hostname", hostname).Msg("Failed to get host reports")
		http.Error(w, `{"error": "failed to retrieve reports"}`, http.StatusInternalServerError)
		return
	}

	summaries := make([]models.ReportSummary, len(reports))
	for i, r := range reports {
		summaries[i] = r.ToSummary()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"hostname": hostname,
		"reports":  summaries,
		"total":    total,
	})
}

