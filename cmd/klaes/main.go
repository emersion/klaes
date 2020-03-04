package main

import (
	"database/sql"
	"flag"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/emersion/klaes"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

func main() {
	var (
		armored   bool
		addr      string
		sqlDriver string
		sqlSource string
	)
	flag.BoolVar(&armored, "armor", false, "import, export: use an armored keyring")
	flag.StringVar(&addr, "addr", ":8080", "serve: listening address")
	flag.StringVar(&sqlDriver, "sql-driver", "postgres", "SQL driver name")
	flag.StringVar(&sqlSource, "sql-source", "host=/run/postgresql dbname=klaes", "SQL data source name")
	flag.Parse()

	db, err := sql.Open(sqlDriver, sqlSource)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	s := klaes.NewServer(db)

	switch flag.Arg(0) {
	case "serve", "":
		log.Println("Server listing on address", addr)
		log.Fatal(http.ListenAndServe(addr, s))
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
	case "export":
		var w io.Writer = os.Stdout
		if armored {
			aw, err := armor.Encode(w, openpgp.PublicKeyType, nil)
			if err != nil {
				log.Fatal(err)
			}
			defer aw.Close()
			w = aw
		}

		ch := make(chan openpgp.EntityList, 32)
		done := make(chan error, 1)
		go func() {
			done <- s.Export(ch)
		}()

		for el := range ch {
			for _, e := range el {
				if err := e.Serialize(w); err != nil {
					log.Fatal(err)
				}
			}
		}

		if err := <-done; err != nil {
			log.Fatal(err)
		}
	default:
		log.Fatal("Unknown command")
	}
}
