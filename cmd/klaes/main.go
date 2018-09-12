package main

import (
	"database/sql"
	"flag"
	"io"
	"log"
	"os"

	"github.com/emersion/klaes"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

var armored bool

func init() {
	flag.BoolVar(&armored, "armored", true, "import: read an armored keyring")
}

func main() {
	flag.Parse()

	db, err := sql.Open("postgres", "host=/run/postgresql user=simon dbname=klaes")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	s := klaes.NewServer(db)

	switch flag.Arg(0) {
	case "serve", "":
		// TODO
	case "import":
		var r io.Reader = os.Stdin
		if armored {
			block, err := armor.Decode(r)
			if err != nil {
				log.Fatal(err)
			} else if block.Type != openpgp.PublicKeyType {
				log.Fatalf("Invalid armor block type: %v", block.Type)
			}
			r = block.Body
		}

		pr := packet.NewReader(r)
		for {
			e, err := openpgp.ReadEntity(pr)
			if err == io.EOF {
				break
			} else if err != nil {
				log.Fatal(err)
			}

			log.Printf("Importing key %X...\n", e.PrimaryKey.Fingerprint[:])

			if err := s.Import(e); err != nil {
				log.Fatal(err)
			}
		}
	default:
		log.Fatal("Unknown command")
	}
}
