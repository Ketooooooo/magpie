package gui

import (
	"encoding/json"
	"net/http"

	"github.com/yetone/magpie/internal/privacyengine"
)

func privacyModelRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/privacy-model", func(rw http.ResponseWriter, r *http.Request) {
		writeJSON(rw, privacyengine.BuiltinModelState())
	})
	mux.HandleFunc("POST /api/privacy-model", func(rw http.ResponseWriter, r *http.Request) {
		var in privacyengine.BuiltinModelCommand
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			fail(rw, err)
			return
		}
		if err := privacyengine.ApplyBuiltinModel(in); err != nil {
			fail(rw, err)
			return
		}
		writeJSON(rw, privacyengine.BuiltinModelState())
	})
}
