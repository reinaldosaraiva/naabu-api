# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Development Commands

### Essential Commands
- **Build**: `make build` - Compiles the application to `./build/naabu-api`
- **Run locally**: `make run` - Starts the server on port 8080
- **Run all tests**: `make test` - Runs both unit and integration tests
- **Run unit tests only**: `make test-unit` - Tests internal packages
- **Run integration tests**: `make test-integration` - Full API integration tests (requires `-tags=integration`)
- **Test coverage**: `make test-coverage` - Generates coverage report in `coverage.html`

### Quality Assurance
- **Format code**: `make fmt` - Formats Go code
- **Lint code**: `make lint` - Requires `golangci-lint`
- **Security check**: `make security` - Requires `gosec`
- **Vet code**: `make vet` - Runs `go vet`

### Docker Commands
- **Build image**: `make docker-build`
- **Run container**: `make docker-run` (foreground) or `make docker-run-detached` (background)
- **Docker Compose**: `make docker-compose-up` / `make docker-compose-down`
- **View logs**: `make docker-logs`

## Architecture Overview

This is a **defensive security port scanning API** built with Go, using the ProjectDiscovery naabu/v2 SDK. The service provides HTTP endpoints for authorized network reconnaissance and security assessment.

### Core Architecture

**Multi-tier scanning system** with three distinct worker pools:
- **Quick Scan Pool**: Fast port discovery using naabu
- **Probe Pool**: Service detection and fingerprinting  
- **Deep Scan Pool**: Advanced scanning with nmap integration

**Key architectural patterns:**
- **Worker Pool Pattern**: `internal/worker/` - Job distribution across specialized worker pools
- **Repository Pattern**: `internal/database/` - Data persistence abstraction
- **Service Layer**: `internal/scanner/` - Core scanning business logic
- **Handler Layer**: `internal/handlers/` - HTTP request processing with Gin framework

### Directory Structure

```
internal/
├── config/          # Application configuration management
├── database/        # GORM-based data persistence (SQLite/PostgreSQL)
├── deepscan/        # Nmap integration for deep scanning
├── handlers/        # Gin HTTP handlers with middleware
├── models/          # Request/response data structures
├── probes/          # Service-specific probes (FTP, RDP, VNC, etc.)
├── scanner/         # Core naabu scanning service
└── worker/          # Worker pool dispatcher and job management

pkg/
└── logger/          # Structured logging with Zap
```

### Database Schema

The application uses GORM with support for both SQLite (development) and PostgreSQL (production). Models are defined in `internal/models/models.go` and include:
- **ScanRequest**: Input validation and parsing
- **ScanResult**: Per-IP scan results with port details
- **Port**: Individual port state and service information

### Configuration System

Configuration is managed through `internal/config/config.go` with environment variable overrides:
- **Server**: Port, timeouts, rate limiting
- **Database**: Driver selection, connection parameters
- **Workers**: Pool sizes, concurrency limits
- **Naabu/Nmap**: Scanner-specific settings

## Testing Patterns

### Unit Tests
- Use `MockScanner` interface for handler testing
- Tests are in `*_test.go` files alongside source code
- Use `testify` assertions and table-driven tests

### Integration Tests
- Build tag: `// +build integration`
- Located in `integration_test.go` at project root
- Test against real localhost scanning
- Skip with `go test -short`

### Test Commands
- Single test: `go test -v -run TestSpecificTest ./internal/handlers/`
- With coverage: `go test -v -coverprofile=coverage.out ./...`
- Integration only: `go test -v -tags=integration .`

## Security Considerations

**This is defensive security tooling** - all scanning should be authorized and ethical:

### Input Validation
- Strict IP validation prevents scanning of reserved/private ranges
- Port range validation and sanitization
- Request size limits (max 100 IPs per request)

### Rate Limiting and Timeouts
- Configurable scan timeouts (default 5 minutes)
- Connection timeouts (5 seconds)
- Worker pool limits prevent resource exhaustion

### Service Probes
The `internal/probes/` directory contains legitimate service detection probes for:
- FTP, LDAP, PPTP, RDP, Rsync, VNC
- These are **defensive reconnaissance tools** for authorized security assessment

## API Endpoints

### Core Endpoints
- `POST /scan` - Execute port scan with JSON payload
- `GET /health` - Service health check
- `GET /metrics` - Application metrics

### Request/Response Format
```json
// Request
{
  "ips": ["192.168.1.1"],
  "ports": "80,443,22-25"
}

// Response
{
  "results": [...],
  "summary": { "total_ips": 1, "open_ports": 3, "duration_ms": 1250 },
  "request_id": "uuid"
}
```

## Development Guidelines

### Code Style
- Follow Go standards: `gofmt`, `golint`, `go vet`
- Use structured logging with Zap
- Implement proper error handling with context
- Use interfaces for testability

### Adding New Features
1. Define models in `internal/models/`
2. Implement service logic in appropriate `internal/` package
3. Add HTTP handlers in `internal/handlers/`
4. Write unit tests alongside implementation
5. Add integration tests if needed
6. Update API documentation

### Common Patterns
- **Context propagation**: All scanning operations use `context.Context`
- **Structured logging**: Use `zap.Logger` with fields
- **Error handling**: Wrap errors with context using `fmt.Errorf`
- **Configuration**: Use environment variables with defaults

## Environment Variables

- `ENV=production` - Enables JSON logging format
- `PORT=8080` - Server port (default: 8080)
- `DB_DRIVER=sqlite|postgres` - Database driver selection
- Database connection vars for PostgreSQL deployment

## Deployment

### Local Development
```bash
make deps    # Install Go dependencies
make build   # Compile binary
make run     # Start server
```

### Docker Deployment
```bash
make docker-build         # Build image
make docker-compose-up    # Start with compose
```

### Production Considerations
- Use PostgreSQL for production database
- Configure proper network isolation
- Implement authentication/authorization
- Monitor for abuse through structured logs
- Set appropriate firewall rules