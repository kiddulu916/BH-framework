# Bug Hunting Framework

A modular, full-stack application designed for automated, ethical security testing and comprehensive reporting.

## 🏗️ Architecture

The Bug Hunting Framework is built with a containerized, microservices architecture:

- **Backend**: Django + Django Ninja (async REST API)
- **Database**: PostgreSQL with SQLAlchemy ORM
- **Frontend**: Next.js 14+ with React and TypeScript
- **Containerization**: Docker + Docker Compose
- **Authentication**: JWT with HTTP-only cookies

## 🚀 Quick Start

### Prerequisites

- Docker and Docker Compose installed
- Git

### Setup Instructions

1. **Clone the repository**
   ```bash
   git clone https://github.com/kiddulu916/BH-framework.git
   cd BH-framework
   ```

2. **Configure environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. **Start the infrastructure**
   ```bash
   docker-compose up -d
   ```

4. **Verify services are running**
   ```bash
   docker-compose ps
   ```

5. **Access the application**
   - Frontend: http://localhost:3000
   - Backend API: http://localhost:8000
   - Database: localhost:5432

## 📁 Project Structure

```
bug-hunting-framework/
├── backend/                 # Django Ninja backend
│   ├── api/                # Django project settings
│   ├── core/               # Main Django app
│   ├── Dockerfile          # Backend container
│   └── requirements.txt    # Python dependencies
├── frontend/               # Next.js frontend
│   ├── src/                # React components
│   ├── Dockerfile          # Frontend container
│   └── package.json        # Node.js dependencies
├── db/                     # Database configuration
│   ├── Dockerfile          # PostgreSQL container
│   └── postgres/           # Database initialization
├── stages/                 # Bug hunting stage containers
├── outputs/                # Stage outputs (mounted volume)
├── docker-compose.yml      # Container orchestration
├── .env                    # Environment variables
└── README.md              # This file
```

## 🔧 Development

### Running in Development Mode

The infrastructure is configured for development with hot reloading:

```bash
# Start all services
docker-compose up

# Start specific service
docker-compose up backend

# View logs
docker-compose logs -f backend
```

### Database Management

```bash
# Access database
docker-compose exec db psql -U postgres -d bug_hunting_framework

# Run Django migrations
docker-compose exec backend python manage.py migrate

# Create superuser
docker-compose exec backend python manage.py createsuperuser
```

### Frontend Development

```bash
# Install dependencies
docker-compose exec frontend pnpm install

# Run development server
docker-compose exec frontend pnpm dev
```

## 🏥 Health Checks

All services include health checks:

- **Database**: `docker-compose exec db pg_isready -U postgres -d bug_hunting_framework`
- **Backend**: http://localhost:8000/health/
- **Frontend**: http://localhost:3000/

## 🔒 Security

### Environment Variables

- All sensitive configuration is stored in environment variables
- Default development values are provided in `.env.example`
- **Important**: Change default secrets in production

### Security Features

- JWT authentication with HTTP-only cookies
- CORS configuration for frontend-backend communication
- Rate limiting on API endpoints
- Input validation with Pydantic schemas
- Security headers middleware

## 📊 Monitoring

### Logs

```bash
# View all logs
docker-compose logs

# View specific service logs
docker-compose logs backend

# Follow logs in real-time
docker-compose logs -f
```

### Health Monitoring

- Health check endpoints for all services
- Database connectivity monitoring
- Service dependency management

## 🐛 Troubleshooting

### Common Issues

1. **Port conflicts**: Ensure ports 3000, 8000, and 5432 are available
2. **Database connection**: Wait for database to be ready before starting backend
3. **Permission issues**: Ensure Docker has proper permissions

### Reset Environment

```bash
# Stop all services
docker-compose down

# Remove volumes (WARNING: This will delete all data)
docker-compose down -v

# Rebuild containers
docker-compose build --no-cache

# Start fresh
docker-compose up -d
```

## 📚 API Documentation

Once the backend is running, access the API documentation at:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## 🤝 Contributing

1. Follow the established architecture patterns
2. Use the provided development environment
3. Run tests before submitting changes
4. Update documentation as needed

## 📄 License

[Add your license information here]

---

**Note**: This is a development setup. For production deployment, additional security and performance configurations are required. 
