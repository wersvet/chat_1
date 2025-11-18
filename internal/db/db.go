package db

import (
	"fmt"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

func Connect(dsn string) (*sqlx.DB, error) {
	database, err := sqlx.Connect("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("connect to database: %w", err)
	}
	return database, nil
}

func RunMigrations(db *sqlx.DB) error {
	schema := `CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW()
    );`
	if _, err := db.Exec(schema); err != nil {
		return fmt.Errorf("run schema: %w", err)
	}
	return nil
}
