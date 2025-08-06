#!/bin/bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if required tools are installed
check_dependencies() {
    local missing_deps=()

    if ! command -v go &> /dev/null; then
        missing_deps+=("go")
    fi

    if ! command -v migrate &> /dev/null; then
        print_warning "migrate tool not found. You can install it with: go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest"
    fi

    if ! command -v sqlc &> /dev/null; then
        print_warning "sqlc tool not found. You can install it with: go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest"
    fi

    if [ ${#missing_deps[@]} -ne 0 ]; then
        print_error "Missing required dependencies: ${missing_deps[*]}"
        exit 1
    fi
}

# Function to validate module name
validate_module_name() {
    local module_name="$1"

    if [[ -z "$module_name" ]]; then
        print_error "Module name cannot be empty"
        return 1
    fi

    if [[ ! "$module_name" =~ ^[a-zA-Z0-9._/-]+$ ]]; then
        print_error "Invalid module name. Use only letters, numbers, dots, slashes, and hyphens"
        return 1
    fi

    return 0
}

# Function to create directory structure
create_directories() {
    local project_dir="$1"

    print_info "Creating directory structure..."

    mkdir -p "$project_dir"/{cmd,config,database,internal/pkg,middleware}
    mkdir -p "$project_dir/internal/pkg/postgres"/{migration,queries}
    mkdir -p "$project_dir/internal/pkg/sqlc"
    mkdir -p "$project_dir"/.github/workflows

    print_success "Directory structure created"
}

# Function to initialize go.mod file
init_go_mod() {
    local project_dir="$1"
    local module_name="$2"

    print_info "Initializing go.mod..."

    cd "$project_dir"
    go mod init "$module_name"
    cd - > /dev/null

    print_success "go.mod initialized"
}

# Function to install dependencies
install_dependencies() {
    local project_dir="$1"

    print_info "Installing dependencies..."

    cd "$project_dir"

    # Let Go detect and install required dependencies from import statements
    make tidy
    make vendor

    cd - > /dev/null

    print_success "Dependencies installed"
}

# Function to create main.go
create_main_go() {
    local project_dir="$1"
    local module_name="$2"

    print_info "Creating cmd/main.go..."

    cat > "$project_dir/cmd/main.go" << EOF
package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"$module_name/config"
	"$module_name/database"
	"$module_name/middleware"
)

func main() {
	ctx, cancel := signal.NotifyContext(
		context.Background(), syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGHUP)
	defer cancel()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	logger = logger.With("app", "API")
	slog.SetDefault(logger)

	cfg, err := config.LoadConfig()
	if err != nil {
		exit(err, "config.LoadConfig()")
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, time.Second*30)
	defer cancel()

	conn, err := database.Dial(timeoutCtx, cfg.DBURL)
	if err != nil {
		exit(err, "database.Dial")
	}
	defer conn.Close()
	slog.InfoContext(ctx, "main", "message", "Connected to database successfully")

	port := cmp.Or(cfg.Port, config.DefaultPort)
	mux := defineRoutes(conn)

	handler := middleware.CorsMiddleware(mux)
	handler = middleware.LoggingMiddleware(handler)
	server := http.Server{
		Handler: handler,
		Addr:    fmt.Sprintf(":%d", port),
	}

	go func() {
		err := server.ListenAndServe()
		if !errors.Is(err, http.ErrServerClosed) {
			exit(err, "server.ListenAndServe")
		}
	}()

	slog.Info("main", "message", "Server started successfully", "port", server.Addr, "numCPUS", runtime.NumCPU())

	<-ctx.Done()
	timeoutCtx, cancel = context.WithTimeout(context.Background(), time.Second*15)
	defer cancel()

	if err := server.Shutdown(timeoutCtx); err != nil {
		exit(err, "server.Shutdown")
	}

	slog.Info("main", "message", "Server shutdown successfully")
}

func exit(err error, origin string) {
	slog.Error(origin, "error", err)
	os.Exit(1)
}
EOF

    print_success "cmd/main.go created"
}

# Function to create routes.go
create_routes_go() {
    local project_dir="$1"
    local module_name="$2"

    print_info "Creating cmd/routes.go..."

    cat > "$project_dir/cmd/routes.go" << EOF
package main

import (
	"net/http"

	"$module_name/internal"
	"$module_name/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
)

func defineRoutes(conn *pgxpool.Pool) http.Handler {
	mux := http.NewServeMux()

	// Health check endpoint
	mux.Handle("GET /health", middleware.Handler(func(w http.ResponseWriter, r *http.Request) middleware.Handler {
		return middleware.JSON(middleware.Response{
			Message: "API is healthy",
		})
	}))

	// API v1 routes
	_ = internal.NewAPI(conn)

	// Add your routes here
	// Example: mux.Handle("GET /api/v1/users", middleware.Handler(api.GetUsers))
	// Note: After running 'make sqlc', you can replace the connection with a sqlc.Store

	return mux
}
EOF

    print_success "cmd/routes.go created"
}

# Function to create config files
create_config() {
    local project_dir="$1"
    local module_name="$2"

    print_info "Creating config package..."

    cat > "$project_dir/config/config.go" << EOF
    package config

    import (
	"fmt"
	"os"
	"sync"

	z "github.com/Oudwins/zog"
	"github.com/Oudwins/zog/zenv"
	"github.com/ekediala/read-later-api/internal"
	"github.com/joho/godotenv"
    )

    var (
	config Config
	err    error
	once   sync.Once
    )

    type Config struct {
	Env                string `env:"Env" zog:"Env"`
	Port               int    `env:"PORT" zog:"Port"`
	FrontendURL        string `env:"FRONTEND_URL" zog:"FrontendURL"`
	DBURL              string `env:"DB_URL" zog:"DBURL"`
	DBPassword         string `env:"DB_PASSWORD" zog:"DBPassword"`
	JwtSecret          string `env:"JWT_SECRET" zog:"JwtSecret"`
	SupabaseProjectURL string `env:"SUPABASE_PROJECT_URL" zog:"SupabaseProjectURL"`
	SupabaseAPIKey     string `env:"SUPABASE_API_KEY" zog:"SupabaseAPIKey"`
    }

    const (
	DefaultPort     = 8080
	DevEnvironment  = "development"
	ProdEnvironment = "production"
    )

    var environments = []string{DevEnvironment, ProdEnvironment}

    func loadConfig() (Config, error) {
	if os.Getenv("Env") != DevEnvironment {
		if err := godotenv.Load(); err != nil {
			return Config{}, fmt.Errorf("loading environment variables: %w", err)
		}
	}

	schema := z.Struct(z.Shape{
		"Port":               z.Int().Default(DefaultPort),
		"Env":                z.String().Required(z.Message("Env is required")).OneOf(environments, z.Message(fmt.Sprintf("must be one of: %v", environments))),
		"FrontendURL":        z.String().URL(z.Message("must be a valid URL")).Required(z.Message("Frontend URL is required")),
		"DBURL":              z.String().URL(z.Message("must be a valid URL")).Required(z.Message("Database URL is required")),
		"DBPassword":         z.String().Required(z.Message("Database password is required")),
		"JwtSecret":          z.String().Required(z.Message("JWT secret is required")),
		"SupabaseProjectURL": z.String().URL(z.Message("must be a valid URL")).Required(z.Message("Supabase project URL is required")),
		"SupabaseAPIKey":     z.String().Required(z.Message("Supabase API key is required")),
	})

	var c Config

	errs := schema.Parse(zenv.NewDataProvider(), &c)
	if len(errs) != 0 {
		err := internal.ValidationError(errs)
		return c, fmt.Errorf("loading config: %v", err.RawErrors())
	}

	return c, nil
    }

    func LoadConfig() (Config, error) {
	once.Do(func() {
		config, err = loadConfig()
	})

	return config, err
    }
EOF

    print_success "config package created"
}

# Function to create database package
create_database() {
    local project_dir="$1"
    local module_name="$2"

    print_info "Creating database package..."

    cat > "$project_dir/database/database.go" << EOF
// Package database provides functions for connecting to the database.
package database

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

func Dial(ctx context.Context, address string) (*pgxpool.Pool, error) {
	pool, err := pgxpool.New(ctx, address)
	if err != nil {
		return nil, fmt.Errorf("opening connection to %s: %w", address, err)
	}

	err = pool.Ping(ctx)
	if err != nil {
		return nil, fmt.Errorf("pinging %s: %w", address, err)
	}

	return pool, nil
}
EOF

    print_success "database package created"
}

# Function to create internal packages
create_internal() {
    local project_dir="$1"
    local module_name="$2"

    print_info "Creating internal packages..."

    # errors.go
    cat > "$project_dir/internal/errors.go" << EOF
package internal

import "errors"

var (
	ErrNotExist       = errors.New("resource not found")
	ErrExists         = errors.New("resource already exists")
	ErrInvalidRequest = errors.New("invalid request")
	ErrUnmarshall     = errors.New("unmarshall error")
	ErrGatewayError   = errors.New("gateway error")
	ErrUnauthorized   = errors.New("unauthorized")
	ErrForbidden      = errors.New("forbidden")
	ErrInternal       = errors.New("internal server error")
)
EOF

    # validation.go
    cat > "$project_dir/internal/validation.go" << EOF
package internal

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/Oudwins/zog"
	"github.com/Oudwins/zog/zconst"
)

type ValidationError zog.ZogIssueMap

func (v ValidationError) Error() string {
	return "Incorrect or missing form data."
}

func (v ValidationError) RawErrors() []string {
	var errors []string
	for key, values := range zog.Issues.SanitizeMap(v) {
		if key != zconst.ISSUE_KEY_FIRST {
			errors = append(errors, values...)
		}
	}
	return errors
}

func Validate[T any](schema *zog.StructSchema, body io.Reader) (result T, err error) {
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&result); err != nil {
		return result, fmt.Errorf("%w:decoding json: %w", ErrInvalidRequest, err)
	}

	if err := schema.Validate(&result); len(err) != 0 {
		return result, ValidationError(err)
	}

	return result, nil
}
EOF

    # constants.go
    cat > "$project_dir/internal/constants.go" << EOF
package internal

const (
	// Add your constants here
	DefaultPageSize = 20
	MaxPageSize     = 100
)
EOF

    # utils.go
    cat > "$project_dir/internal/utils.go" << EOF
package internal

import (
	"encoding/json"
	"io"
	"net/http"
)

func DecodeJSON(r *http.Request, dst interface{}) error {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return ErrInvalidRequest
	}
	defer r.Body.Close()

	if err := json.Unmarshal(body, dst); err != nil {
		return ErrUnmarshall
	}

	return nil
}
EOF

    # api.go
    cat > "$project_dir/internal/api.go" << EOF
package internal

import "github.com/jackc/pgx/v5/pgxpool"

type API struct {
	conn *pgxpool.Pool
	// Note: After running 'make sqlc', replace with:
	// store *sqlc.Store
}

func NewAPI(conn *pgxpool.Pool) *API {
	return &API{
		conn: conn,
	}
	// Note: After running 'make sqlc', replace this with:
	// store := sqlc.NewStore(conn)
	// return &API{store: store}
}
EOF

    print_success "internal packages created"
}

# Function to create middleware
create_middleware() {
    local project_dir="$1"
    local module_name="$2"

    print_info "Creating middleware package..."

    cat > "$project_dir/middleware/http.go" << EOF
package middleware

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"$module_name/internal"
)

type Handler func(w http.ResponseWriter, r *http.Request) Handler

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if next := h(w, r); next != nil {
		next.ServeHTTP(w, r)
	}
}

type Response struct {
	Error   string \`json:"error,omitempty"\`
	Data    any    \`json:"data,omitempty"\`
	Message string \`json:"message,omitempty"\`
}

func OK(w http.ResponseWriter, r *http.Request) Handler {
	return nil
}

func FatalError(v Response, err error) Handler {
	return func(w http.ResponseWriter, r *http.Request) Handler {
		slog.ErrorContext(r.Context(), "fatal error", "origin", "JSON > json.NewEncoder", "data", v, "message", err.Error())
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(\`Internal server error. Please try again or contact <a href="mailto:support@example.com">Support</a>\`))
		return OK
	}
}

func Code(code int, next Handler) Handler {
	return func(w http.ResponseWriter, r *http.Request) Handler {
		w.WriteHeader(code)
		return next
	}
}

func Text(s string) Handler {
	return func(w http.ResponseWriter, r *http.Request) Handler {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, s)
		return OK
	}
}

func CodeText(code int, text string) Handler {
	return Code(code, Text(text))
}

func Error(err error) Handler {
	if err == nil {
		return OK
	}

	var code int
	ok := errors.Is(internal.ValidationError{}, err)
	switch {
	case ok:
		code = http.StatusUnprocessableEntity
	case errors.Is(err, internal.ErrExists):
		code = http.StatusConflict
	case errors.Is(err, internal.ErrInvalidRequest):
		code = http.StatusBadRequest
	case errors.Is(err, internal.ErrUnmarshall):
		code = http.StatusBadRequest
	case errors.Is(err, internal.ErrNotExist):
		code = http.StatusNotFound
	case errors.Is(err, internal.ErrGatewayError):
		code = http.StatusBadGateway
	case errors.Is(err, internal.ErrUnauthorized):
		code = http.StatusUnauthorized
	case errors.Is(err, internal.ErrForbidden):
		code = http.StatusForbidden
	default:
		code = http.StatusInternalServerError
	}

	return func(w http.ResponseWriter, r *http.Request) Handler {
		if code == http.StatusInternalServerError {
			slog.Log(r.Context(), slog.LevelError, "internal", "url", r.URL.Path, "error", err)
			err = internal.ErrInternal
		}

		if code == http.StatusBadRequest {
			slog.Log(r.Context(), slog.LevelError, "bad request", "url", r.URL.Path, "error", err)
			err = internal.ErrInvalidRequest
		}

		return Code(code, JSON(Response{
			Error:   err.Error(),
			Message: http.StatusText(code),
		}))
	}
}

func JSON(v Response) Handler {
	return func(w http.ResponseWriter, r *http.Request) Handler {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(v); err != nil {
			return FatalError(v, err)
		}
		return OK
	}
}
EOF

    cat > "$project_dir/middleware/cors.go" << EOF
package middleware

import (
	"net/http"

	"$module_name/config"
)

func CorsMiddleware(next http.Handler) http.Handler {
	cfg, err := config.LoadConfig()
	if err != nil {
		panic(err)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers conditionally
		w.Header().Set("Access-Control-Allow-Origin", cfg.FrontendURL)
		w.Header().Set("Vary", "Origin")

		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Max-Age", "3600")

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}
EOF

    cat > "$project_dir/middleware/logging.go" << EOF
package middleware

import (
	"log/slog"
	"net/http"
	"time"
)

func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		next.ServeHTTP(w, r)

		slog.InfoContext(r.Context(), "request",
			"method", r.Method,
			"path", r.URL.Path,
			"duration", time.Since(start),
		)
	})
}
EOF

    cat > "$project_dir/middleware/auth.go" << EOF
package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"$module_name/config"
	"$module_name/internal"
)

// Define an unexported type for context keys to avoid collisions
type contextKey struct{}

// Define specific keys as instances of the empty struct
var jwtClaimsKey = contextKey{}

// UserMetadata represents the structure of the user_metadata in the JWT
type UserMetadata struct {
	Email         string \`json:"email"\`
	Name          string \`json:"name"\`
	Phone         string \`json:"phone"\`
	EmailVerified bool   \`json:"email_verified"\`
	PhoneVerified bool   \`json:"phone_verified"\`
	Sub           string \`json:"sub"\`
}

// AppMetadata represents the structure of the app_metadata in the JWT
type AppMetadata struct {
	Provider  string   \`json:"provider"\`
	Providers []string \`json:"providers"\`
}

// AMR represents an authentication method record in the JWT
type AMR struct {
	Method    string \`json:"method"\`
	Timestamp int64  \`json:"timestamp"\`
}

// JWTClaims represents the structure of the JWT payload compatible with Supabase
type JWTClaims struct {
	Iss          string       \`json:"iss"\`
	Sub          string       \`json:"sub"\`
	Aud          string       \`json:"aud"\`
	Exp          int64        \`json:"exp"\`
	Iat          int64        \`json:"iat"\`
	Email        string       \`json:"email"\`
	Phone        string       \`json:"phone"\`
	AppMetadata  AppMetadata  \`json:"app_metadata"\`
	UserMetadata UserMetadata \`json:"user_metadata"\`
	Role         string       \`json:"role"\`
	AAL          string       \`json:"aal"\`
	AMR          []AMR        \`json:"amr"\`
	SessionID    string       \`json:"session_id"\`
	IsAnonymous  bool         \`json:"is_anonymous"\`
	jwt.RegisteredClaims
}

// Auth provides JWT authentication middleware compatible with Supabase tokens
// If not using Supabase, you can modify the JWTClaims struct and validation logic
func Auth(next Handler) Handler {
	return func(w http.ResponseWriter, r *http.Request) Handler {
		cfg, err := config.LoadConfig()
		if err != nil {
			return Error(err)
		}

		auth := r.Header.Get("Authorization")
		prefix, tokenString, ok := strings.Cut(auth, " ")
		if !ok {
			return Error(internal.ErrUnauthorized)
		}

		if !strings.EqualFold(prefix, "Bearer") {
			return Error(internal.ErrInvalidRequest)
		}

		// Parse token with custom claims struct
		// NOTE: If not using Supabase, modify the signing key source here
		token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (any, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(cfg.JwtSecret), nil
		})

		if err != nil {
			return Error(fmt.Errorf("parsing token: %w", err))
		}

		if !token.Valid {
			return Error(internal.ErrUnauthorized)
		}

		claims, ok := token.Claims.(*JWTClaims)
		if !ok {
			return Error(fmt.Errorf("invalid token claims"))
		}

		// Update the request context with the claims
		ctx := context.WithValue(r.Context(), jwtClaimsKey, claims)

		// Call the next handler with the updated request
		return next(w, r.WithContext(ctx))
	}
}

// GetClaims returns the full JWT claims object from the context
func GetClaims(ctx context.Context) (*JWTClaims, error) {
	claims, ok := ctx.Value(jwtClaimsKey).(*JWTClaims)
	if !ok {
		return nil, fmt.Errorf("no JWT claims found in context")
	}

	return claims, nil
}

// GetUserID extracts the user ID from the JWT claims in the context
func GetUserID(ctx context.Context) (pgtype.UUID, error) {
	claims, err := GetClaims(ctx)
	if err != nil {
		return pgtype.UUID{}, fmt.Errorf("getting userID: %w", err)
	}

	userID, err := uuid.Parse(claims.Sub)
	if err != nil {
		return pgtype.UUID{}, fmt.Errorf("parsing userID %s: %w", claims.Sub, err)
	}

	return pgtype.UUID{Bytes: userID, Valid: true}, nil
}

// GetUserEmail extracts the user email from the JWT claims in the context
func GetUserEmail(ctx context.Context) (string, error) {
	claims, err := GetClaims(ctx)
	if err != nil {
		return "", fmt.Errorf("getting email: %w", err)
	}

	return claims.Email, nil
}

// GetUserMetadata extracts the user metadata from the JWT claims in the context
func GetUserMetadata(ctx context.Context) (UserMetadata, error) {
	claims, err := GetClaims(ctx)
	if err != nil {
		return UserMetadata{}, fmt.Errorf("getting user metadata: %w", err)
	}

	return claims.UserMetadata, nil
}
EOF

    print_success "middleware package created"
}

# Function to create sqlc configuration
create_sqlc_config() {
    local project_dir="$1"

    print_info "Creating sqlc.yaml..."

    cat > "$project_dir/sqlc.yaml" << EOF
version: "2"
sql:
  - schema: "internal/pkg/postgres/migration"
    queries: "internal/pkg/postgres/queries"
    engine: "postgresql"
    gen:
      go:
        package: "sqlc"
        out: "internal/pkg/sqlc"
        sql_package: "pgx/v5"
        emit_json_tags: true
        emit_interface: true
        emit_empty_slices: true
        overrides:
          - db_type: "timestamptz"
            go_type: "time.Time"
EOF

    print_success "sqlc.yaml created"
}

# Function to create Makefile
create_makefile() {
    local project_dir="$1"

    print_info "Creating Makefile..."

    cat > "$project_dir/Makefile" << 'EOF'
build:
	go build -o bin ./cmd

start: build
	./bin

live_reload:
	air

tidy:
	go mod tidy

vendor:
	go mod vendor

install: tidy vendor

migrate:
	@echo "Migrating database"
	migrate -path internal/pkg/postgres/migration -database $(url) -verbose up
	@echo "Migrate database completed"

migrate_down:
	@echo "Migrating database down"
	migrate -path internal/pkg/postgres/migration -database $(url) -verbose down
	@echo "Migrate database down completed"

migrate_down_count:
	@echo "Migrating database down"
	migrate -path internal/pkg/postgres/migration -database $(url) -verbose down $(count)
	@echo "Migrate database down completed"

migrate_force:
	@echo "Forcing migration"
	migrate -path internal/pkg/postgres/migration -database $(url) -verbose force $(version)
	@echo "Migration forced"

migrateup:
	@echo "Migrating up"
	$(MAKE) migrate url=$(url)
	@echo "Migrate up completed"

migrate_ci:
	@echo "Migrating CI database"
	$(MAKE) migrate url=$(url)
	@echo "Migrate CI database completed"

migratedown:
	@echo "Migrating down"
	$(MAKE) migrate_down url=$(url)
	@echo "Migrate down completed"

forcedown:
	@echo "Forcing down migration"
	$(MAKE) migrate_force url=$(url) version=$(version)
	@echo "Forced down migration completed"

force_fix_migration:
	@echo "Forcing migration fix"
	$(MAKE) migrate_force url=$(url) version=$(version)
	@echo "Migration fixed"

sqlc:
	@echo "Generating sqlc"
	sqlc generate
	@echo "Sqlc generated"

generate_migration:
	migrate create -ext sql -dir internal/pkg/postgres/migration $(name)

generate_32_bit_key:
	openssl rand -base64 32

static_analysis:
	@echo "Running go vet ./..."
	go vet ./...
	@echo "Running staticcheck ./..."
	staticcheck ./...
	@echo "Running errcheck ./..."
	# errcheck ./...
	@echo "static analysis done"

.PHONY: build start tidy vendor clean migrate migrate_down migrate_force migrateup migrate_ci migratedown forcedown force_fix_migration sqlc generate_migration generate_32_bit_key static_analysis
EOF

    print_success "Makefile created"
}

# Function to create basic files
create_basic_files() {
    local project_dir="$1"

    print_info "Creating basic files..."

    # .gitignore
    cat > "$project_dir/.gitignore" << EOF
# Binaries for programs and plugins
*.exe
*.exe~
*.dll
*.so
*.dylib
bin/

# Test binary, built with \`go test -c\`
*.test

# Output of the go coverage tool, specifically when used with LiteIDE
*.out

# Dependency directories
vendor/

# Go workspace file
go.work

# Environment variables
.env
.env.local
.env.*.local

# OS generated files
.DS_Store
.DS_Store?
._*
.Spotlight-V100
.Trashes
ehthumbs.db
Thumbs.db

# IDE files
.vscode/
.idea/
*.swp
*.swo

# Temporary files
tmp/
*.tmp
*.log

# Air live reload
tmp/
EOF

    # README.md
    cat > "$project_dir/README.md" << EOF
# API Project

A Go API project scaffolded with the meet-loop-api template.

## Getting Started

### Prerequisites

- Go 1.24.2 or later
- PostgreSQL
- [golang-migrate](https://github.com/golang-migrate/migrate) for database migrations
- [sqlc](https://sqlc.dev/) for generating type-safe SQL code

### Installation

1. Clone or scaffold the repository
2. Set up your environment variables:
   \`\`\`bash
   cp .env.example .env
   # Edit .env with your database URL
   \`\`\`

3. Create your initial migration:
   \`\`\`bash
   make generate_migration name="initial_migration"
   \`\`\`

4. Edit the migration files in \`internal/pkg/postgres/migration/\`

5. Run database migrations:
   \`\`\`bash
   make migrate url="your_database_url"
   \`\`\`

6. Add your SQL queries to \`internal/pkg/postgres/queries/\`

7. Generate SQL code:
   \`\`\`bash
   make sqlc
   \`\`\`

8. Update \`internal/api.go\` to use the generated sqlc.Store

9. Start the server:
   \`\`\`bash
   make start
   \`\`\`

## Development

### Creating Migrations

\`\`\`bash
make generate_migration name="your_migration_name"
\`\`\`

### Live Reload

Use Air for live reloading during development:

\`\`\`bash
make live_reload
\`\`\`

### Database Operations

- Run migrations: \`make migrate url="your_db_url"\`
- Rollback migrations: \`make migrate_down url="your_db_url"\`
- Generate SQL code: \`make sqlc\`

## Project Structure

- \`cmd/\` - Application entry point
- \`config/\` - Configuration management
- \`database/\` - Database connection
- \`internal/\` - Internal packages
- \`middleware/\` - HTTP middleware
- \`internal/pkg/postgres/\` - Database migrations and queries
- \`internal/pkg/sqlc/\` - Generated SQL code

## API Endpoints

- \`GET /health\` - Health check endpoint

Add your API endpoints here as you build them.

## Authentication

This project includes JWT-based authentication middleware that is **compatible with Supabase** by default.

### Using with Supabase (Recommended)

1. Set up a Supabase project at [supabase.com](https://supabase.com)
2. Configure your environment variables:
   \`\`\`bash
   SUPABASE_PROJECT_URL=https://your-project.supabase.co
   SUPABASE_API_KEY=your-supabase-anon-key
   JWT_SECRET=your-supabase-jwt-secret
   \`\`\`
3. The JWT claims structure is already configured for Supabase tokens

### Using without Supabase (Custom Auth)

If you prefer to use a different authentication provider:

1. **Modify the config structure**: Remove Supabase fields from \`config/config.go\`:
   \`\`\`go
   type Config struct {
       Env         string \`env:"Env" zog:"Env"\`
       Port        int    \`env:"PORT" zog:"Port"\`
       FrontendURL string \`env:"FRONTEND_URL" zog:"FrontendURL"\`
       DBURL       string \`env:"DB_URL" zog:"DBURL"\`
       DBPassword  string \`env:"DB_PASSWORD" zog:"DBPassword"\`
       JwtSecret   string \`env:"JWT_SECRET" zog:"JwtSecret"\`
       // Remove: SupabaseProjectURL and SupabaseAPIKey
   }
   \`\`\`

2. **Update config validation**: Remove Supabase validation from the schema:
   \`\`\`go
   schema := z.Struct(z.Shape{
       "Port":        z.Int().Default(DefaultPort),
       "Env":         z.String().Required().OneOf([]string{DevEnvironment, ProdEnvironment}),
       "FrontendURL": z.String().URL().Required(),
       "DBURL":       z.String().URL().Required(),
       "DBPassword":  z.String().Required(),
       "JwtSecret":   z.String().Required(),
       // Remove: "SupabaseProjectURL" and "SupabaseAPIKey" validation
   })
   \`\`\`

3. **Modify the JWT Claims**: Update the \`JWTClaims\` struct in \`middleware/auth.go\` to match your provider's token structure
4. **Update the signing key**: Modify the token parsing logic to use your provider's signing key/method
5. **Update validation**: Adjust the token validation logic as needed for your provider

### Protected Routes

Use the \`middleware.Auth\` wrapper to protect your routes:

\`\`\`go
mux.Handle("GET /protected", middleware.Auth(yourProtectedHandler))
\`\`\`

### Accessing User Data

Extract user information from the JWT claims:

\`\`\`go
userID, err := middleware.GetUserID(r.Context())
email, err := middleware.GetUserEmail(r.Context())
metadata, err := middleware.GetUserMetadata(r.Context())
\`\`\`

## CI/CD Deployment

This project includes a GitHub Actions workflow for automatic deployment to Google Cloud Run.

### Setup Instructions

1. **Enable Google Cloud APIs:**
   - Cloud Run API
   - Container Registry API
   - Cloud Build API

2. **Create a Service Account:**
   \`\`\`bash
   gcloud iam service-accounts create github-actions \\
     --description="Service account for GitHub Actions" \\
     --display-name="GitHub Actions"
   \`\`\`

3. **Grant necessary permissions:**
   \`\`\`bash
   gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \\
     --member="serviceAccount:github-actions@YOUR_PROJECT_ID.iam.gserviceaccount.com" \\
     --role="roles/run.admin"

   gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \\
     --member="serviceAccount:github-actions@YOUR_PROJECT_ID.iam.gserviceaccount.com" \\
     --role="roles/storage.admin"

   gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \\
     --member="serviceAccount:github-actions@YOUR_PROJECT_ID.iam.gserviceaccount.com" \\
     --role="roles/iam.serviceAccountUser"
   \`\`\`

4. **Create and download service account key:**
   \`\`\`bash
   gcloud iam service-accounts keys create key.json \\
     --iam-account=github-actions@YOUR_PROJECT_ID.iam.gserviceaccount.com
   \`\`\`

5. **Set up GitHub repository secrets:**
   - \`GCP_PROJECT_ID\`: Your Google Cloud project ID
   - \`GCP_SERVICE_KEY\`: Content of the service account key.json file
   - \`DB_URL\`: Production database connection string
   - \`DB_PASSWORD\`: Database password
   - \`JWT_SECRET\`: JWT signing secret
   - \`FRONTEND_URL\`: Frontend application URL
   - \`SUPABASE_PROJECT_URL\`: Supabase project URL
   - \`SUPABASE_API_KEY\`: Supabase API key
   - \`ENV\`: Environment setting (production)

6. **Push to main branch** to trigger automatic deployment

### Workflow Features

- **Automatic deployment** on main branch push
- **Google Artifact Registry** for container storage
- **Service account authentication** for security
- **Multi-stage Docker build** for optimized images
- **Environment variable injection** from secrets
- **Zero-downtime deployment** to Cloud Run
EOF

    # .env.example
    cat > "$project_dir/.env.example" << EOF
# Copy this file to .env and fill in your values

# Environment Configuration
Env=development

# Database Configuration
DB_URL=postgres://username:password@localhost:5432/dbname?sslmode=disable
DB_PASSWORD=your-db-password

# Server Configuration
PORT=8080
FRONTEND_URL=http://localhost:3000

# JWT Configuration (required for authentication)
JWT_SECRET=your-jwt-secret-key

# Supabase Configuration (optional - only if using Supabase for authentication)
SUPABASE_PROJECT_URL=https://your-project.supabase.co
SUPABASE_API_KEY=your-supabase-anon-key

# Note: If not using Supabase, you can ignore the Supabase variables
# and modify the config validation schema to remove the required Supabase fields
EOF

    # GitHub Actions workflow
    cat > "$project_dir/.github/workflows/deploy.yml" << EOF
name: Deploy to Cloud Run

on:
  push:
    branches:
      - main

env:
  PROJECT_ID: \${{ secrets.GCP_PROJECT_ID }}
  REGION: europe-west2
  REPOSITORY: artifact-registry-repo
  IMAGE_NAME: image-name

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Set up gcloud
        uses: google-github-actions/auth@v2
        with:
          credentials_json: \${{ secrets.GCP_SERVICE_KEY }}

      - name: Configure gcloud project
        run: |
          gcloud config set project \$PROJECT_ID

      - name: Set up docker auth for Artifact Registry
        run: |
          gcloud auth configure-docker europe-west2-docker.pkg.dev

      - name: Build and push Docker image
        run: |
          docker build -t europe-west2-docker.pkg.dev/\$PROJECT_ID/\$REPOSITORY/\$IMAGE_NAME .
          docker push europe-west2-docker.pkg.dev/\$PROJECT_ID/\$REPOSITORY/\$IMAGE_NAME

      - name: Deploy to Cloud Run
        run: |
          gcloud run deploy \$IMAGE_NAME \\
            --image europe-west2-docker.pkg.dev/\$PROJECT_ID/\$REPOSITORY/\$IMAGE_NAME \\
            --platform managed \\
            --region \$REGION \\
            --service-account continous-deployment@\$PROJECT_ID.iam.gserviceaccount.com \\
            --set-env-vars DB_PASSWORD="\${{ secrets.DB_PASSWORD }}" \\
            --set-env-vars DB_URL="\${{ secrets.DB_URL }}" \\
            --set-env-vars SUPABASE_PROJECT_URL="\${{ secrets.SUPABASE_PROJECT_URL }}" \\
            --set-env-vars SUPABASE_API_KEY="\${{ secrets.SUPABASE_API_KEY }}" \\
            --set-env-vars FRONTEND_URL="\${{ secrets.FRONTEND_URL }}" \\
            --set-env-vars JWT_SECRET="\${{ secrets.JWT_SECRET }}" \\
            --set-env-vars Env="\${{ secrets.ENV }}" \\
            --allow-unauthenticated
EOF

    # .air.toml
    cat > "$project_dir/.air.toml" << EOF
root = "."
testdata_dir = "testdata"
tmp_dir = "tmp"

[build]
  args_bin = []
  bin = "./tmp/main"
  cmd = "go build -o ./tmp/main ./cmd"
  delay = 0
  exclude_dir = ["assets", "tmp", "vendor", "testdata"]
  exclude_file = []
  exclude_regex = ["_test.go"]
  exclude_unchanged = false
  follow_symlink = false
  full_bin = ""
  include_dir = []
  include_ext = ["go", "tpl", "tmpl", "html"]
  include_file = []
  kill_delay = "0s"
  log = "build-errors.log"
  poll = false
  poll_interval = 0
  rerun = false
  rerun_delay = 500
  send_interrupt = false
  stop_on_root = false

[color]
  app = ""
  build = "yellow"
  main = "magenta"
  runner = "green"
  watcher = "cyan"

[log]
  main_only = false
  time = false

[misc]
  clean_on_exit = false

[screen]
  clear_on_rebuild = false
  keep_scroll = true
EOF

    # Dockerfile
    cat > "$project_dir/Dockerfile" << EOF
# Build stage
FROM golang:1.24-alpine AS builder

# Install necessary build tools
RUN apk add build-base

# Set environment variable
ENV ENVIRONMENT=production

# Set the current working directory inside the container
WORKDIR /build

# Copy the entire application code to the working directory
COPY . .

# Build the Go binary for the dashboard service
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /build/bin ./cmd/

# Final stage
FROM alpine:latest

# Install CA certificates for HTTPS
RUN apk add ca-certificates

# Create a non-root user and group
RUN addgroup -g 3000 appgroup && \\
    adduser -D -u 1000 -G appgroup appuser

# Create app directory and set ownership
RUN mkdir -p /app && chown -R appuser:appgroup /app

# Set the working directory to /app (not /root)
WORKDIR /app

# Copy the built binary from the builder stage to /app directory
COPY --from=builder /build/bin /app/bin

# Set execute permissions and ownership for the non-root user
RUN chmod +x /app/bin && chown appuser:appgroup /app/bin

# Expose the port your dashboard service listens on
EXPOSE 8080

# Switch to non-root user
USER appuser

# Run the binary (now located at /app/dashboard)
CMD ["/app/bin"]
EOF

    print_success "Basic files created"
}

# Function to create placeholder query files
create_query_placeholder() {
    local project_dir="$1"

    print_info "Creating query placeholder files..."

    # Ensure the queries directory exists
    mkdir -p "$project_dir/internal/pkg/postgres/queries"

    # Create a placeholder query file
    cat > "$project_dir/internal/pkg/postgres/queries/.gitkeep" << EOF
# This directory will contain your SQL query files
# Example: users.sql, posts.sql, etc.
#
# After adding your SQL files, run 'make sqlc' to generate Go code
EOF

    print_success "Query placeholder files created"
}

# Function to create initial migration
create_initial_migration() {
    local project_dir="$1"

    print_info "Creating initial migration..."

    cd "$project_dir"

    # Check if migrate tool is available
    if command -v migrate &> /dev/null; then
        make generate_migration name="initial_migration"
        print_success "Initial migration created"
    else
        print_warning "migrate tool not found. Run 'make generate_migration name=\"initial_migration\"' manually after installing migrate"
    fi

    cd - > /dev/null
}

# Function to initialize git repository
init_git() {
    local project_dir="$1"

    if command -v git &> /dev/null; then
        print_info "Initializing git repository..."
        cd "$project_dir"
        git init
        git add .
        git commit -m "Initial commit: API scaffolding"
        print_success "Git repository initialized"
        cd - > /dev/null
    else
        print_warning "Git not found, skipping repository initialization"
    fi
}

# Main function
main() {
    echo ""
    echo "🚀 Go API Scaffolding Tool"
    echo "=========================="
    echo ""

    # Check dependencies
    check_dependencies

    # Get module name
    if [ -z "$1" ]; then
        echo -n "Enter the module name (e.g., github.com/username/project): "
        read -r module_name
    else
        module_name="$1"
    fi

    # Validate module name
    if ! validate_module_name "$module_name"; then
        exit 1
    fi

    # Extract project name from module
    project_name=$(basename "$module_name")
    project_dir="./$project_name"

    # Check if directory already exists
    if [ -d "$project_dir" ]; then
        print_error "Directory '$project_dir' already exists"
        exit 1
    fi

    print_info "Creating project: $project_name"
    print_info "Module name: $module_name"
    print_info "Project directory: $project_dir"
    echo ""

    # Create the project
    create_directories "$project_dir"
    init_go_mod "$project_dir" "$module_name"
    create_main_go "$project_dir" "$module_name"
    create_routes_go "$project_dir" "$module_name"
    create_config "$project_dir" "$module_name"
    create_database "$project_dir" "$module_name"
    create_internal "$project_dir" "$module_name"
    create_middleware "$project_dir" "$module_name"
    create_sqlc_config "$project_dir"
    create_makefile "$project_dir"
    create_basic_files "$project_dir"
    create_query_placeholder "$project_dir"

    # Initialize git repository
    init_git "$project_dir"

    # Install dependencies after all files are created so Go can detect imports
    install_dependencies "$project_dir"

    # Create initial migration file
    create_initial_migration "$project_dir"

    echo ""
    print_success "Project scaffolding completed successfully!"
    echo ""
    echo "Next steps:"
    echo "1. cd $project_name"
    echo "2. cp .env.example .env (and edit with your database URL)"
    echo "3. Edit the migration files in internal/pkg/postgres/migration/"
    echo "4. make migrate url=\"your_database_url\""
    echo "5. Add your SQL queries to internal/pkg/postgres/queries/"
    echo "6. make sqlc (this will generate the store and update your API)"
    echo "7. Update internal/api.go to use the generated sqlc.Store"
    echo "8. Set up authentication (see README for Supabase or custom auth)"
    echo "9. make start"
    echo ""
    echo "For CI/CD deployment:"
    echo "1. Set up these GitHub repository secrets:"
    echo "   - GCP_PROJECT_ID: Your Google Cloud project ID"
    echo "   - GCP_SERVICE_KEY: Service account credentials JSON"
    echo "   - DB_URL: Production database connection string"
    echo "   - DB_PASSWORD: Database password"
    echo "   - JWT_SECRET: JWT signing secret"
    echo "   - FRONTEND_URL: Frontend application URL"
    echo "   - SUPABASE_PROJECT_URL: Supabase project URL"
    echo "   - SUPABASE_API_KEY: Supabase API key"
    echo "   - ENV: Environment (production)"
    echo "2. Push to main branch to trigger deployment"
    echo ""
    echo "Optional tools to install:"
    echo "- golang-migrate: go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest"
    echo "- sqlc: go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest"
    echo "- air (for live reload): go install github.com/air-verse/air@latest"
    echo ""
}

# Run main function with all arguments
main "$@"
