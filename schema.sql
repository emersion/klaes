CREATE TABLE Key (
	id SERIAL PRIMARY KEY,
	fingerprint BYTEA UNIQUE,
	-- Key IDs are unsigned, but PostgreSQL only knows about signed integers
	keyid64 BIGINT,
	keyid32 INTEGER,
	creation_time TIMESTAMP WITH TIME ZONE NOT NULL,
	expiration_time TIMESTAMP WITH TIME ZONE,
	algo INTEGER NOT NULL,
	bit_length INTEGER NOT NULL,
	packets BYTEA NOT NULL
);

CREATE TABLE Identity (
	id SERIAL PRIMARY KEY,
	key INTEGER REFERENCES Key(id),
	name VARCHAR NOT NULL,
	creation_time TIMESTAMP WITH TIME ZONE NOT NULL,
	expiration_time TIMESTAMP WITH TIME ZONE,
	wkd_hash VARCHAR(32)
);
