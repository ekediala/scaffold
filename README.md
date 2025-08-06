# Go API Scaffolding Tool

A powerful command-line tool that generates a complete, production-ready Go API project with best practices, minimal dependencies, database integration, middleware, and CI/CD setup. We try to use the standard library wherever possible. At the moment only zog for validation, pgx/v5 for database connections, uuid, golang-jwt, and godotenv for loading environment variables are included. Middleware and routing are handled using the standard library.

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
go install github.com/ekediala/scaffold@latest
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

- **Database**: PostgreSQL driver and SQLC for type-safe queries
- **Authentication**: JWT-go for token handling
- **Configuration**: Godotenv for environment variables
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

We welcome contributions to the Go API Scaffolding Tool! Here's how to get started:

### Development Setup

1. **Fork the repository**
   ```bash
   git clone https://github.com/your-username/scaffold.git
   cd scaffold
   ```

2. **Install dependencies**
   ```bash
   go mod tidy
   ```

3. **Make the script executable**
   ```bash
   chmod +x scaffold.sh
   ```

4. **Test your changes locally**
   ```bash
   go run main.go -h
   go run main.go github.com/test/project
   ```

### Making Changes

1. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**
   - Edit `scaffold.sh` for scaffolding logic changes
   - Edit `main.go` for CLI interface changes
   - Update `README.md` for documentation changes

3. **Test thoroughly**
   - Test the CLI flags (`-h`, `-v`)
   - Test with and without module name arguments
   - Verify generated projects compile and run
   - Test on different operating systems if possible

4. **Commit your changes**
   ```bash
   git add .
   git commit -m "feat: add your feature description"
   ```

5. **Push and create pull request**
   ```bash
   git push origin feature/your-feature-name
   ```

### Code Guidelines

- Follow Go conventions and best practices
- Keep shell script functions focused and well-documented
- Maintain backward compatibility when possible
- Add error handling for edge cases
- Update documentation for any new features

### Testing Generated Projects

When making changes to the scaffolding logic, always test that generated projects:

1. Compile successfully: `go build -o bin .`
2. Pass basic tests: `go test ./...`
3. Have valid dependencies: `go mod tidy && go mod verify`
4. Follow Go project structure conventions

## Version Tagging

This project uses semantic versioning. Here's how to create and publish new versions:

### Creating a New Version

1. **Determine version bump**
   - **Patch** (1.0.x): Bug fixes, small improvements
   - **Minor** (1.x.0): New features, backward compatible
   - **Major** (x.0.0): Breaking changes

2. **Update version in code**
   ```bash
   # Edit main.go and update the version constant
   const version = "1.1.0"  # Update this line
   ```

3. **Commit version bump**
   ```bash
   git add main.go
   git commit -m "bump version to v1.1.0"
   git push origin main
   ```

4. **Create and push tag**
   ```bash
   git tag v1.1.0
   git push origin v1.1.0
   ```

### Version Tag Format

- Use semantic versioning: `vMAJOR.MINOR.PATCH`
- Examples: `v1.0.0`, `v1.2.3`, `v2.0.0`
- Always prefix with `v`

### Publishing Process

1. **Automated via tags**: Once you push a tag, users can install with:
   ```bash
   go install github.com/ekediala/scaffold@v1.1.0
   go install github.com/ekediala/scaffold@latest  # installs latest tag
   ```

2. **GitHub Releases**: Create a GitHub release for the tag with:
   - Release notes describing changes
   - Binary attachments (if applicable)
   - Migration instructions (for breaking changes)

### Pre-release Versions

For beta or release candidate versions:

```bash
git tag v1.1.0-beta.1
git tag v1.1.0-rc.1
git push origin v1.1.0-beta.1
```

Users can install pre-releases with:
```bash
go install github.com/ekediala/scaffold@v1.1.0-beta.1
```

### Example Release Workflow

```bash
# 1. Make your changes and test
go run main.go github.com/test/myproject

# 2. Update version
vim main.go  # Update version constant

# 3. Commit and tag
git add main.go
git commit -m "bump version to v1.2.0"
git push origin main
git tag v1.2.0
git push origin v1.2.0

# 4. Verify installation works
go install github.com/ekediala/scaffold@v1.2.0
scaffold -v  # Should show v1.2.0
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

If you encounter any issues or have questions:

1. Check the generated project's README for specific guidance
2. Open an issue on GitHub
3. Review the example projects in the documentation

---

**Happy coding! 🎉**
