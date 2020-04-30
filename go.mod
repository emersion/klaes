module github.com/emersion/klaes

go 1.12

require (
	github.com/emersion/go-openpgp-hkp v0.0.0-20180913132822-059dbf2e8bfa
	github.com/emersion/go-openpgp-wkd v0.0.0-20191011220651-01af8781ec9b
	github.com/lib/pq v1.3.0
	github.com/tv42/zbase32 v0.0.0-20190604154422-aacc64a8f915 // indirect
	golang.org/x/crypto v0.0.0-20200302210943-78000ba7a073
)

replace golang.org/x/crypto => github.com/ProtonMail/crypto v2.0.0+incompatible
