# 🚀 Go API Scaffolding Tool

A powerful command-line tool that generates a complete, production-ready Go API project with best practices, database integration, middleware, and CI/CD setup.

## Features

- **Complete Project Structure**: Creates a well-organized Go project with standard directories
- **Database Integration**: PostgreSQL with migrations and SQLC for type-safe queries
- **Middleware**: Built-in HTTP middleware for CORS, authentication, logging, and more
- **Configuration Management**: Environment-based configuration with validation
- **CI/CD Ready**: GitHub Actions workflow for automated deployment to Google Cloud Platform
- **Authentication**: Support for Supabase authentication or custom JWT
- **Development Tools**: Makefile with common tasks, hot reload support
- **Production Ready**: Containerized deployment with Docker

## Installation

### Install as CLI Tool

```bash
go install github.com/ekediala/scaffold@main
```

### Build from Source

```bash
git clone https://github.com/ekediala/scaffold.git
cd scaffold
go install .
```

## Usage

### Basic Usage

```bash
scaffold
```

The tool will prompt you for a module name (e.g., `github.com/username/myproject`).

### With Module Name Argument

```bash
scaffold github.com/username/myproject
```

## Project Structure

The scaffolding tool creates the following structure:

```
myproject/
├── cmd/
│   ├── main.go              # Application entry point
│   └── routes.go            # HTTP route definitions
├── config/
│   └── config.go            # Configuration management
├── database/
│   └── database.go          # Database connection
├── internal/
│   ├── api.go               # API handlers
│   ├── errors.go            # Custom error types
│   └── pkg/
│       ├── postgres/
│       │   ├── migration/   # Database migrations
│       │   └── queries/     # SQL query files
│       └── sqlc/            # Generated SQLC code
├── middleware/
│   └── http.go              # HTTP middleware
├── .github/
│   └── workflows/
│       └── deploy.yml       # CI/CD pipeline
├── .env.example             # Environment variables template
├── .gitignore               # Git ignore rules
├── Dockerfile               # Container configuration
├── Makefile                 # Development tasks
├── README.md                # Project documentation
├── go.mod                   # Go module file
└── sqlc.yaml                # SQLC configuration
```

## Quick Start

After running the scaffolding tool:

1. **Navigate to your project**:
   ```bash
   cd myproject
   ```

2. **Set up environment variables**:
   ```bash
   cp .env.example .env
   # Edit .env with your database URL and other settings
   ```

3. **Create database migrations**:
   ```bash
   # Edit migration files in internal/pkg/postgres/migration/
   make migrate url="postgresql://user:password@localhost/dbname?sslmode=disable"
   ```

4. **Add SQL queries**:
   ```bash
   # Add your SQL queries to internal/pkg/postgres/queries/
   make sqlc  # Generate type-safe Go code from SQL
   ```

5. **Start development server**:
   ```bash
   make start
   ```

## Available Make Commands

- `make build` - Build the application
- `make start` - Start the development server
- `make migrate url="..."` - Run database migrations
- `make sqlc` - Generate SQLC code from SQL queries
- `make generate_migration name="migration_name"` - Create new migration
- `make test` - Run tests
- `make lint` - Run linter

## Environment Variables

The generated project uses the following environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Server port | `8080` |
| `DB_URL` | PostgreSQL connection string | Required |
| `JWT_SECRET` | JWT signing secret | Required |
| `FRONTEND_URL` | Frontend application URL | `http://localhost:3000` |
| `SUPABASE_PROJECT_URL` | Supabase project URL | Optional |
| `SUPABASE_API_KEY` | Supabase API key | Optional |
| `ENV` | Environment (development/production) | `development` |

## Database Setup

### Using PostgreSQL

1. Install PostgreSQL locally or use a cloud provider
2. Create a database for your project
3. Set the `DB_URL` environment variable
4. Run migrations: `make migrate url="your_database_url"`

### Using Supabase

1. Create a Supabase project
2. Set `SUPABASE_PROJECT_URL` and `SUPABASE_API_KEY`
3. Use Supabase's built-in authentication features

## CI/CD Deployment

The generated project includes a GitHub Actions workflow for deployment to Google Cloud Platform.

### Setup GitHub Secrets

Add these secrets to your GitHub repository:

- `GCP_PROJECT_ID`: Your Google Cloud project ID
- `GCP_SERVICE_KEY`: Service account credentials JSON
- `DB_URL`: Production database connection string
- `DB_PASSWORD`: Database password
- `JWT_SECRET`: JWT signing secret
- `FRONTEND_URL`: Frontend application URL
- `SUPABASE_PROJECT_URL`: Supabase project URL (if using)
- `SUPABASE_API_KEY`: Supabase API key (if using)
- `ENV`: Environment (production)

### Deployment

Push to the `main` branch to trigger automatic deployment.

## Dependencies

The scaffolding tool installs these key dependencies:

- **Web Framework**: Gorilla Mux for HTTP routing
- **Database**: PostgreSQL driver and SQLC for type-safe queries
- **Authentication**: JWT-go for token handling
- **Configuration**: Godotenv for environment variables
- **CORS**: Gorilla handlers for CORS middleware
- **Migrations**: golang-migrate for database migrations

## Optional Tools

Install these tools for enhanced development experience:

```bash
# Database migrations
go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest

# Type-safe SQL
go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest

# Hot reload during development
go install github.com/air-verse/air@latest
```

## Requirements

- Go 1.21 or higher
- PostgreSQL database
- Git (for repository initialization)

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

If you encounter any issues or have questions:

1. Check the generated project's README for specific guidance
2. Open an issue on GitHub
3. Review the example projects in the documentation

---

**Happy coding! 🎉**