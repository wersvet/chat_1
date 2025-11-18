package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"auth-service/internal/db"
	"auth-service/internal/handlers"

	"github.com/gin-gonic/gin"
)

func main() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL is required")
	}

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET is required")
	}

	database, err := db.Connect(dsn)
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}

	if err := db.RunMigrations(database); err != nil {
		log.Fatalf("failed to run migrations: %v", err)
	}

	handler := handlers.NewAuthHandler(database, jwtSecret)

	router := gin.Default()
	router.Use(gin.Logger(), gin.Recovery())

	router.POST("/auth/register", handler.Register)
	router.POST("/auth/login", handler.Login)
	router.GET("/auth/validate", handler.ValidateToken)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	server := &http.Server{
		Addr:         ":" + port,
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Printf("starting auth-service on port %s", port)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}
