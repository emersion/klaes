package klaes

import (
	"bytes"
	"database/sql"
	"encoding/binary"
	"log"
	"time"

	"github.com/emersion/go-openpgp-wkd"
	"github.com/pkg/errors"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

func primarySelfSignature(e *openpgp.Entity) *packet.Signature {
	var selfSig *packet.Signature
	for _, ident := range e.Identities {
		if selfSig == nil {
			selfSig = ident.SelfSignature
		} else if ident.SelfSignature.IsPrimaryId != nil && *ident.SelfSignature.IsPrimaryId {
			return ident.SelfSignature
		}
	}
	return selfSig
}

func signatureExpirationTime(sig *packet.Signature) time.Time {
	if sig.KeyLifetimeSecs == nil {
		return time.Time{}
	}
	dur := time.Duration(*sig.KeyLifetimeSecs) * time.Second
	return sig.CreationTime.Add(dur)
}

type Server struct {
	db *sql.DB
}

func NewServer(db *sql.DB) *Server {
	return &Server{db}
}

func (s *Server) Import(e *openpgp.Entity) error {
	pub := e.PrimaryKey
	sig := primarySelfSignature(e)

	bitLength, err := pub.BitLength()
	if err != nil {
		return errors.Wrap(err, "failed to get key bit length")
	}

	keyid32 := binary.BigEndian.Uint32(pub.Fingerprint[16:20])

	var b bytes.Buffer
	if err := e.Serialize(&b); err != nil {
		return errors.Wrap(err, "failed to serialize public key")
	}

	tx, err := s.db.Begin()
	if err != nil {
		return errors.Wrap(err, "failed to create transaction")
	}

	var id int
	err = tx.QueryRow(
		`INSERT INTO Key(fingerprint, keyid64, keyid32, creation_time,
			expiration_time, algo, bit_length, packets)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
		pub.Fingerprint[:], int64(pub.KeyId), int32(keyid32),
		sig.CreationTime, signatureExpirationTime(sig), pub.PubKeyAlgo,
		bitLength, b.Bytes(),
	).Scan(&id)
	if err != nil {
		tx.Rollback()
		return errors.Wrap(err, "failed to insert key")
	}

	for _, ident := range e.Identities {
		sig := ident.SelfSignature

		wkdHash, err := wkd.HashAddress(ident.UserId.Email)
		if err != nil {
			tx.Rollback()
			log.Fatal(err)
		}

		_, err = tx.Exec(
			`INSERT INTO Identity key, name, creation_time, expiration_time,
				wkd_hash)
			VALUES ($1, $2, $3, $4, $5)`,
			id, ident.Name, sig.CreationTime,
			signatureExpirationTime(sig), wkdHash,
		)
		if err != nil {
			tx.Rollback()
			return errors.Wrap(err, "failed to insert identity")
		}
	}

	if err := tx.Commit(); err != nil {
		return errors.Wrap(err, "failed to commit transaction")
	}

	return nil
}
