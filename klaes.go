package klaes

import (
	"database/sql"
	"net/http"

	"github.com/emersion/go-openpgp-hkp"
	"golang.org/x/crypto/openpgp"
)

type Server struct {
	backend backend
	hkp hkp.Handler
}

func NewServer(db *sql.DB) *Server {
	s := &Server{}
	s.backend.db = db
	s.hkp.Lookuper = &s.backend
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.hkp.ServeHTTP(w, r)
}

func (s *Server) Import(e *openpgp.Entity) error {
	return s.backend.importEntity(e)
}
