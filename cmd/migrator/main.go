package main

import (
	"errors"
	"flag"
	"fmt"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

func main() {
	var dbUrl, migrationsPath, migrationsTable string

	flag.StringVar(&dbUrl, "db-url", "test:12345@localhost:5433/test_db", "db url connection")
	flag.StringVar(&migrationsPath, "migrations-path", "./migrations", "path to migrations")
	flag.StringVar(&migrationsTable, "migrations-table", "migrations", "name of migrations table")
	flag.Parse()

	if dbUrl == "" {
		panic("storage path is required")
	}
	if migrationsPath == "" {
		panic("migrations path is required")
	}
	m, err := migrate.New(
		"file://"+migrationsPath,
		fmt.Sprintf("postgresql://%s?x-migrations-table=%s&sslmode=disable", dbUrl, migrationsTable),
	)

	if err != nil {
		panic(err)
	}
	if err := m.Up(); err != nil {
		if errors.Is(err, migrate.ErrNoChange) {
			fmt.Println("no migrations to apply")
			return
		}
		panic(err)
	}

	fmt.Println("migrations applied successfully")
}
