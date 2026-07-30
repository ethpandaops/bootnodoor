package webui

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
)

func TestRegisterPprofHandler(t *testing.T) {
	tests := []struct {
		name       string
		enabled    bool
		statusCode int
	}{
		{
			name:       "disabled",
			enabled:    false,
			statusCode: http.StatusNotFound,
		},
		{
			name:       "enabled",
			enabled:    true,
			statusCode: http.StatusOK,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			router := mux.NewRouter()
			registerPprofHandler(router, test.enabled)

			request := httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)

			if response.Code != test.statusCode {
				t.Fatalf("expected status code %d, got %d", test.statusCode, response.Code)
			}
		})
	}
}
