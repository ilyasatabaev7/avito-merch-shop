package main

import (
	"context"
	"fmt"
	"github.com/IlyasAtabaev731/avito-merch-shop/internal/api"
	"github.com/IlyasAtabaev731/avito-merch-shop/internal/config"
	"github.com/IlyasAtabaev731/avito-merch-shop/internal/storage/postgres"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	_ "github.com/lib/pq"
)

const (
	envLocal = "local"
	envDev   = "dev"
	envProd  = "prod"
)

func main() {
	cfg := config.MustLoad()

	log := setupLogger(cfg.Env)

	log.Info("Starting application",
		slog.String("env", cfg.Env),
		slog.String("host", cfg.ApiHost),
		slog.Int("port", cfg.ApiPort),
	)

	dbUrl := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		cfg.Postgres.User,
		cfg.Postgres.Pass,
		cfg.Postgres.Host,
		cfg.Postgres.Port,
		cfg.Postgres.Db,
	)

	storage, err := postgres.New(dbUrl)
	if err != nil {
		log.Error("Failed to connect to database", "error", err)
		os.Exit(1)
	}

	inMemoryCache := sync.Map{}

	if err := storage.LoadCacheFromDB(&inMemoryCache, log); err != nil {
		log.Error("Failed to load cache from database", "error", err)
		os.Exit(1)
	}

	jwtSecret := []byte("secret42212")

	apiServer := api.New(cfg, log, &inMemoryCache, storage, jwtSecret)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		apiServer.MustStart()
	}()

	<-sigChan
	log.Info("Got signal to shutdown server")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := apiServer.Stop(ctx); err != nil {
		log.Error("Stopping server error", "error", err)
	}
}

func setupLogger(env string) *slog.Logger {
	var log *slog.Logger
	switch env {
	case envLocal:
		log = slog.New(
			slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
		)
	case envDev:
		log = slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
		)
	case envProd:
		log = slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}),
		)
	}
	return log
}
