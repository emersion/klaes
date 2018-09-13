package klaes

import (
	"bytes"
	"database/sql"
	"encoding/binary"
	"time"

	"github.com/emersion/go-openpgp-hkp"
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

type backend struct {
	db *sql.DB
}

func (be *backend) lookup(req *hkp.LookupRequest) (where string, v interface{}) {
	keyIDSearch := hkp.ParseKeyIDSearch(req.Search)
	if fingerprint := keyIDSearch.Fingerprint(); fingerprint != nil {
		return "fingerprint = $1", (*fingerprint)[:]
	} else if id64 := keyIDSearch.KeyId(); id64 != nil {
		return "keyid64 = $1", int64(*id64)
	} else if id32 := keyIDSearch.KeyIdShort(); id32 != nil {
		return "keyid32 = $1", int32(*id32)
	}

	return "to_tsvector(Identity.name) @@ to_tsquery($1)", req.Search
}

func (be *backend) Get(req *hkp.LookupRequest) (openpgp.EntityList, error) {
	where, v := be.lookup(req)

	var packets []byte
	err := be.db.QueryRow(
		`SELECT
			Key.packets
		FROM Key, Identity WHERE
			` + where + ` AND
			Key.id = Identity.key`,
		v,
	).Scan(&packets)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	return openpgp.ReadKeyRing(bytes.NewReader(packets))
}

func (be *backend) Index(req *hkp.LookupRequest) ([]hkp.IndexKey, error) {
	where, v := be.lookup(req)

	rows, err := be.db.Query(
		`SELECT
			Key.id, Key.fingerprint, Key.creation_time, Key.expiration_time,
			Key.algo, Key.bit_length
		FROM Key, Identity WHERE
			` + where + ` AND
			Key.id = Identity.key`,
		v,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []hkp.IndexKey
	for rows.Next() {
		var id int
		var key hkp.IndexKey
		var fingerprint []byte
		if err := rows.Scan(&id, &fingerprint, &key.CreationTime, &key.ExpirationTime, &key.Algo, &key.BitLength); err != nil {
			return nil, err
		}

		if len(fingerprint) != 20 {
			return nil, errors.New("klaes: invalid key fingerprint length in DB")
		}
		copy(key.Fingerprint[:], fingerprint)

		identRows, err := be.db.Query(
			`SELECT
				Identity.name, Identity.creation_time, Identity.expiration_time
			FROM Identity WHERE
				Identity.key = $1`,
			id,
		)
		if err != nil {
			return nil, err
		}

		for identRows.Next() {
			var ident hkp.IndexIdentity
			if err := identRows.Scan(&ident.Name, &ident.CreationTime, &ident.ExpirationTime); err != nil {
				return nil, err
			}

			key.Identities = append(key.Identities, ident)
		}
		if err := identRows.Err(); err != nil {
			return nil, err
		}

		keys = append(keys, key)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return keys, nil
}

func (be *backend) importEntity(e *openpgp.Entity) error {
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

	tx, err := be.db.Begin()
	if err != nil {
		return errors.Wrap(err, "failed to create transaction")
	}

	var id int
	err = tx.QueryRow(
		`INSERT INTO Key(fingerprint, keyid64, keyid32, creation_time,
			expiration_time, algo, bit_length, packets)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
		pub.Fingerprint[:], int64(pub.KeyId), int32(keyid32),
		pub.CreationTime, signatureExpirationTime(sig), pub.PubKeyAlgo,
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
			return errors.Wrap(err, "failed to hash email")
		}

		_, err = tx.Exec(
			`INSERT INTO Identity(key, name, creation_time, expiration_time,
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
