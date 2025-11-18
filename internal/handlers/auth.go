package handlers

import (
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"

	"auth-service/internal/middleware"
	"auth-service/internal/models"
)

type AuthHandler struct {
	db        *sqlx.DB
	jwtSecret string
}

func NewAuthHandler(db *sqlx.DB, jwtSecret string) *AuthHandler {
	return &AuthHandler{db: db, jwtSecret: jwtSecret}
}

type registerRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type authResponse struct {
	Token string       `json:"token"`
	User  userResponse `json:"user"`
}

type userResponse struct {
	ID        int64     `json:"id"`
	Username  string    `json:"username"`
	CreatedAt time.Time `json:"created_at"`
}

// Register creates a new user and returns a JWT.
func (h *AuthHandler) Register(c *gin.Context) {
	var req registerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request payload"})
		return
	}

	req.Username = strings.TrimSpace(req.Username)
	if len(req.Password) < 6 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "password must be at least 6 characters"})
		return
	}
	if req.Username == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username is required"})
		return
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to process password"})
		return
	}

	var user models.User
	query := `INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id, username, password_hash, created_at`
	if err := h.db.QueryRowx(query, req.Username, string(hashed)).StructScan(&user); err != nil {
		if isUniqueViolation(err) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "username already exists"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create user"})
		return
	}

	token, err := middleware.GenerateToken(h.jwtSecret, user.ID, user.Username, 72*time.Hour)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, authResponse{Token: token, User: mapUser(user)})
}

// Login authenticates a user and returns a JWT.
func (h *AuthHandler) Login(c *gin.Context) {
	var req registerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request payload"})
		return
	}

	var user models.User
	query := `SELECT id, username, password_hash, created_at FROM users WHERE username=$1`
	if err := h.db.Get(&user, query, req.Username); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch user"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	token, err := middleware.GenerateToken(h.jwtSecret, user.ID, user.Username, 72*time.Hour)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, authResponse{Token: token, User: mapUser(user)})
}

// ValidateToken verifies a JWT and returns user claims.
func (h *AuthHandler) ValidateToken(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing authorization header"})
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenString == authHeader {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization header"})
		return
	}

	claims, err := middleware.ParseToken(h.jwtSecret, tokenString)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		return
	}

	userID, _ := claims["user_id"].(float64)

	c.JSON(http.StatusOK, gin.H{"valid": true, "user_id": int64(userID), "username": claims["username"]})
}

func mapUser(u models.User) userResponse {
	return userResponse{ID: u.ID, Username: u.Username, CreatedAt: u.CreatedAt}
}

func isUniqueViolation(err error) bool {
	// PostgreSQL unique_violation code
	const uniqueViolation = "23505"
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		return pqErr.Code == uniqueViolation
	}
	return false
}
