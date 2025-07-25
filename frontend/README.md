# Bug Hunting Framework - Frontend

A modern, containerized frontend application for the Bug Hunting Framework, built with Next.js 15.4.2, React 19.1.0, and TypeScript. This application provides an intuitive interface for creating and managing bug hunting target profiles with comprehensive form validation, real-time feedback, and performance optimizations.

## 🚀 Features

### Core Functionality
- **Target Profile Builder**: Multi-step form for creating comprehensive bug hunting target profiles
- **Real-time Validation**: Instant feedback and error handling with comprehensive validation rules
- **Platform Integration**: Support for major bug bounty platforms (HackerOne, Bugcrowd, etc.)
- **Form Persistence**: Automatic form data saving and recovery across sessions
- **Responsive Design**: Optimized for all device sizes with mobile-first approach

### Performance & Optimization
- **Core Web Vitals**: Optimized for excellent performance scores (FCP < 1.8s, LCP < 2.5s, FID < 100ms)
- **Bundle Optimization**: Code splitting, tree shaking, and lazy loading for optimal bundle size
- **Caching Strategies**: React Query for intelligent API caching and background updates
- **Container Optimized**: Multi-stage Docker builds with Alpine Linux for minimal footprint (~200MB)
- **Performance Monitoring**: Real-time Core Web Vitals tracking and custom metrics

### Developer Experience
- **TypeScript**: Full type safety with comprehensive interfaces and enums
- **Testing**: Comprehensive test suite with Vitest and React Testing Library (84% pass rate)
- **Error Boundaries**: Robust error handling with fallback UI and recovery mechanisms
- **Hot Reloading**: Fast development with Next.js hot reloading
- **ESLint**: Code quality enforcement with TypeScript-specific rules

## 🏗️ Architecture

### Technology Stack
- **Framework**: Next.js 15.4.2 with App Router
- **Language**: TypeScript 5.0
- **UI Library**: React 19.1.0
- **Styling**: Tailwind CSS 4.0
- **State Management**: Zustand 5.0.6
- **Data Fetching**: React Query (TanStack Query)
- **Animations**: Framer Motion 12.23.6
- **Icons**: Lucide React 0.525.0
- **HTTP Client**: Axios 1.10.0

### Component Architecture
```
src/
├── app/                    # Next.js App Router pages
├── components/
│   ├── atoms/             # Basic UI components (Button, Input, Select)
│   ├── molecules/         # Compound components (StepProgress)
│   ├── organisms/         # Complex components (form steps)
│   ├── pages/             # Page-level components
│   ├── providers/         # Context providers (QueryProvider)
│   └── templates/         # Layout templates
├── lib/
│   ├── api/               # API client and endpoints
│   ├── state/             # Zustand stores
│   ├── utils/             # Utility functions
│   └── websocket/         # WebSocket utilities
└── types/                 # TypeScript type definitions
```

### State Management
- **Zustand**: Global state management for form data and application state
- **React Query**: Server state management with caching and background updates
- **Local Storage**: Form data persistence across sessions
- **URL State**: Step navigation and form progress tracking

## 📦 Installation & Setup

### Prerequisites
- Node.js 20+ 
- npm or pnpm
- Docker (for containerized deployment)
- Git

### Local Development Setup

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd bug-hunting-framework/frontend
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Set up environment variables**
   ```bash
   cp .env.example .env.local
   # Edit .env.local with your configuration
   ```

4. **Start development server**
   ```bash
   npm run dev
   ```

5. **Open your browser**
   Navigate to `http://localhost:3000`

### Environment Variables

```bash
# API Configuration
NEXT_PUBLIC_API_URL=http://localhost:8000
NEXT_PUBLIC_WS_URL=ws://localhost:8000/ws

# Development Configuration
NODE_ENV=development
DOCKER_ENV=false

# Performance Monitoring
NEXT_TELEMETRY_DISABLED=1
```

## 🐳 Container Deployment

### Docker Build

1. **Build the container**
   ```bash
   docker build -t bug-hunting-frontend .
   ```

2. **Run the container**
   ```bash
   docker run -p 3000:3000 bug-hunting-frontend
   ```

### Docker Compose

The frontend is designed to work with the complete Bug Hunting Framework stack:

```bash
# From the root directory
docker-compose up frontend
```

### Container Features
- **Multi-stage builds** for optimized image size (~200MB)
- **Alpine Linux base** for security and minimal footprint
- **Non-root user** execution for enhanced security
- **Health checks** for container orchestration
- **Signal handling** with dumb-init for proper lifecycle management

## 🧪 Testing

### Running Tests
```bash
# Run all tests
npm run test

# Run tests with UI
npm run test:ui

# Run tests with coverage
npm run test:coverage

# Run tests in watch mode
npm run test:watch
```

### Test Coverage
- **Unit Tests**: 139 passing tests (84% pass rate)
- **Component Tests**: Comprehensive component testing
- **Integration Tests**: End-to-end workflow testing
- **Accessibility Tests**: WCAG compliance testing

### Test Structure
```
tests/
├── components/            # Component tests
├── lib/                   # Utility tests
├── integration/           # Integration tests
└── setup/                 # Test configuration
```

## 📊 Performance

### Core Web Vitals Targets
- **First Contentful Paint (FCP)**: < 1.8s
- **Largest Contentful Paint (LCP)**: < 2.5s
- **First Input Delay (FID)**: < 100ms
- **Cumulative Layout Shift (CLS)**: < 0.1
- **Time to First Byte (TTFB)**: < 600ms

### Performance Optimizations
- **Bundle Analysis**: `npm run analyze` for bundle size analysis
- **Code Splitting**: Dynamic imports and route-based splitting
- **Tree Shaking**: Aggressive dead code elimination
- **Image Optimization**: WebP and AVIF formats with responsive sizes
- **Caching**: React Query for API caching, browser caching for static assets

### Performance Monitoring
- **Development Dashboard**: Real-time metrics in development mode
- **Core Web Vitals**: Automatic tracking and reporting
- **Custom Metrics**: Component render times and async operations
- **Container Metrics**: Container-specific performance tracking

## 🔧 Development

### Available Scripts
```bash
# Development
npm run dev              # Start development server
npm run build            # Build for production
npm run start            # Start production server

# Testing
npm run test             # Run tests
npm run test:ui          # Run tests with UI
npm run test:coverage    # Run tests with coverage
npm run test:watch       # Run tests in watch mode

# Linting
npm run lint             # Run ESLint

# Performance
npm run analyze          # Analyze bundle size
npm run analyze:dev      # Analyze development bundle

# Container
npm run docker:build     # Build for Docker
npm run docker:start     # Start in Docker mode
npm run docker:dev       # Development in Docker mode
npm run health           # Health check
```

### Code Style
- **TypeScript**: Strict mode with comprehensive type checking
- **ESLint**: Enforced code quality with TypeScript-specific rules
- **Prettier**: Automatic code formatting
- **Conventional Commits**: Standardized commit message format

### Git Workflow
1. Create feature branch from `main`
2. Make changes with proper TypeScript types
3. Write/update tests
4. Run linting and tests
5. Create pull request with descriptive title and description

## 🚀 Deployment

### Production Build
```bash
# Build for production
npm run build

# Start production server
npm run start
```

### Docker Production
```bash
# Build production image
docker build -t bug-hunting-frontend:prod .

# Run production container
docker run -p 3000:3000 -e NODE_ENV=production bug-hunting-frontend:prod
```

### Health Checks
The application provides a health check endpoint at `/health`:
```bash
curl http://localhost:3000/health
```

Response:
```json
{
  "status": "healthy",
  "timestamp": "2025-01-27T10:00:00.000Z",
  "environment": "production",
  "container_id": "container-123",
  "version": "1.0.0",
  "uptime": 3600,
  "memory": {
    "rss": 123456789,
    "heapTotal": 987654321,
    "heapUsed": 123456789
  }
}
```

## 📚 API Documentation

### Target Management API
The frontend integrates with the Bug Hunting Framework backend API for target management:

#### Create Target
```typescript
POST /api/targets/
Content-Type: application/json

{
  "name": "Example Target",
  "domain": "example.com",
  "platform": "hackerone",
  "scope": {
    "in_scope": ["*.example.com"],
    "out_scope": ["api.example.com"]
  }
}
```

#### Get Target
```typescript
GET /api/targets/{target_id}
```

#### Update Target
```typescript
PUT /api/targets/{target_id}
Content-Type: application/json

{
  "name": "Updated Target",
  "domain": "example.com",
  "platform": "bugcrowd"
}
```

#### Delete Target
```typescript
DELETE /api/targets/{target_id}
```

### Error Handling
All API responses follow a standardized format:
```typescript
interface APIResponse<T> {
  success: boolean;
  message: string;
  data?: T;
  errors?: string[];
}
```

## 🔒 Security

### Security Features
- **Non-root container execution** for enhanced security
- **Security headers** including XSS protection and content type options
- **Input validation** with comprehensive TypeScript types
- **Error boundaries** to prevent information leakage
- **Container isolation** with proper network configuration

### Security Headers
The application includes comprehensive security headers:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy: camera=(), microphone=(), geolocation=()`

## 🐛 Troubleshooting

### Common Issues

#### Build Failures
```bash
# Clear Next.js cache
rm -rf .next
npm run build

# Check for TypeScript errors
npx tsc --noEmit
```

#### Container Issues
```bash
# Check container logs
docker logs <container-name>

# Check container health
docker exec <container-name> npm run health

# Restart container
docker-compose restart frontend
```

#### Performance Issues
```bash
# Analyze bundle size
npm run analyze

# Check Core Web Vitals
# Use browser DevTools Performance tab
# Check performance monitoring dashboard in development
```

### Debug Mode
Enable debug logging by setting:
```bash
NODE_ENV=development
DEBUG=true
```

## 🤝 Contributing

### Development Setup
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

### Code Review Checklist
- [ ] TypeScript types are comprehensive
- [ ] Tests are written and passing
- [ ] Performance impact is considered
- [ ] Accessibility requirements are met
- [ ] Documentation is updated
- [ ] Code follows project conventions

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

### Getting Help
- **Documentation**: Check this README and the `/docs` directory
- **Issues**: Create an issue on GitHub with detailed information
- **Discussions**: Use GitHub Discussions for questions and ideas

### Reporting Bugs
When reporting bugs, please include:
- Browser and version
- Operating system
- Steps to reproduce
- Expected vs actual behavior
- Console errors (if any)
- Performance metrics (if relevant)

## 🔄 Changelog

### Version 1.0.0 (2025-01-27)
- ✅ Initial release with target profile builder
- ✅ Comprehensive form validation and state management
- ✅ Performance optimizations and monitoring
- ✅ Container deployment support
- ✅ Complete test suite with 84% pass rate
- ✅ Accessibility compliance
- ✅ Docker containerization with Alpine Linux
- ✅ Health checks and monitoring
- ✅ Error boundaries and recovery mechanisms

---

**Built with ❤️ for the bug hunting community**
