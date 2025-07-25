# Developer Guide

## Overview

This guide provides comprehensive information for developers working on the Bug Hunting Framework Frontend. It covers development setup, coding standards, testing procedures, and contribution guidelines.

## Development Setup

### Prerequisites

- **Node.js**: 20.x or higher
- **npm**: 8.x or higher
- **Git**: For version control
- **VS Code**: Recommended IDE (with extensions)
- **Docker**: For containerized development

### Initial Setup

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

### VS Code Extensions

Recommended extensions for development:

```json
{
  "recommendations": [
    "bradlc.vscode-tailwindcss",
    "esbenp.prettier-vscode",
    "ms-vscode.vscode-typescript-next",
    "formulahendry.auto-rename-tag",
    "christian-kohler.path-intellisense",
    "ms-vscode.vscode-json",
    "ms-vscode.vscode-eslint",
    "ms-vscode.vscode-prettier"
  ]
}
```

## Code Style and Standards

### TypeScript Guidelines

1. **Strict Mode**: Always use TypeScript strict mode
2. **Type Definitions**: Define interfaces for all props and data structures
3. **Type Imports**: Use type imports for better tree shaking
4. **Generic Types**: Use generics for reusable components

```typescript
// Good: Type imports
import type { ButtonProps } from './Button';

// Good: Interface definitions
interface UserProfile {
  id: string;
  name: string;
  email: string;
}

// Good: Generic components
interface ListProps<T> {
  items: T[];
  renderItem: (item: T) => React.ReactNode;
}
```

### React Guidelines

1. **Functional Components**: Use functional components with hooks
2. **Props Interface**: Define props interface for each component
3. **Default Props**: Use default parameters instead of defaultProps
4. **Memoization**: Use React.memo for pure components

```typescript
// Good: Functional component with props interface
interface ButtonProps {
  children: React.ReactNode;
  variant?: 'primary' | 'secondary';
  onClick?: () => void;
}

const Button = React.memo<ButtonProps>(({ 
  children, 
  variant = 'primary', 
  onClick 
}) => {
  return (
    <button 
      className={`btn btn-${variant}`}
      onClick={onClick}
    >
      {children}
    </button>
  );
});
```

### File Organization

1. **Atomic Design**: Organize components by atomic design principles
2. **File Naming**: Use PascalCase for components, camelCase for utilities
3. **Directory Structure**: Follow established directory structure
4. **Index Files**: Use index files for clean imports

```
src/
├── components/
│   ├── atoms/
│   │   ├── Button/
│   │   │   ├── Button.tsx
│   │   │   ├── Button.test.tsx
│   │   │   └── index.ts
│   │   └── index.ts
│   └── molecules/
├── lib/
│   ├── api/
│   ├── utils/
│   └── hooks/
└── types/
```

### Import Organization

1. **Group Imports**: Group imports by type
2. **Absolute Imports**: Use absolute imports with `@/` prefix
3. **Type Imports**: Separate type imports from value imports

```typescript
// External libraries
import React from 'react';
import { motion } from 'framer-motion';

// Internal components
import { Button } from '@/components/atoms/Button';
import { Input } from '@/components/atoms/Input';

// Types
import type { UserProfile } from '@/types/user';

// Utilities
import { formatDate } from '@/lib/utils/date';
```

## Testing Guidelines

### Test Structure

1. **Test Files**: Co-locate test files with components
2. **Test Naming**: Use descriptive test names
3. **Test Organization**: Group related tests with describe blocks
4. **Test Coverage**: Aim for 80%+ test coverage

```typescript
// Button.test.tsx
import { render, screen, fireEvent } from '@testing-library/react';
import { Button } from './Button';

describe('Button', () => {
  it('renders with correct text', () => {
    render(<Button>Click me</Button>);
    expect(screen.getByRole('button', { name: 'Click me' })).toBeInTheDocument();
  });

  it('calls onClick when clicked', () => {
    const handleClick = jest.fn();
    render(<Button onClick={handleClick}>Click me</Button>);
    fireEvent.click(screen.getByRole('button'));
    expect(handleClick).toHaveBeenCalledTimes(1);
  });

  it('applies correct variant class', () => {
    render(<Button variant="secondary">Click me</Button>);
    expect(screen.getByRole('button')).toHaveClass('btn-secondary');
  });
});
```

### Testing Best Practices

1. **User-Centric Testing**: Test from user perspective
2. **Accessibility Testing**: Test accessibility features
3. **Integration Testing**: Test component interactions
4. **Mock External Dependencies**: Mock API calls and external services

```typescript
// Mock API calls
jest.mock('@/lib/api/targets');

const mockTargetsApi = targetsApi as jest.Mocked<typeof targetsApi>;

describe('TargetForm', () => {
  beforeEach(() => {
    mockTargetsApi.createTarget.mockClear();
  });

  it('submits form data correctly', async () => {
    mockTargetsApi.createTarget.mockResolvedValue({
      success: true,
      message: 'Target created',
      data: { id: '123', name: 'Test Target' }
    });

    render(<TargetForm />);
    
    fireEvent.change(screen.getByLabelText('Name'), {
      target: { value: 'Test Target' }
    });
    
    fireEvent.click(screen.getByRole('button', { name: 'Create Target' }));
    
    await waitFor(() => {
      expect(mockTargetsApi.createTarget).toHaveBeenCalledWith({
        name: 'Test Target'
      });
    });
  });
});
```

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

# Run specific test file
npm test Button.test.tsx

# Run tests matching pattern
npm test -- --testNamePattern="Button"
```

## Performance Guidelines

### Component Optimization

1. **React.memo**: Use for pure components
2. **useMemo**: For expensive computations
3. **useCallback**: For event handlers
4. **Lazy Loading**: For large components

```typescript
// Optimized component
const ExpensiveComponent = React.memo<Props>(({ data, onUpdate }) => {
  // Memoize expensive computation
  const processedData = useMemo(() => {
    return data.map(item => ({
      ...item,
      processed: expensiveOperation(item)
    }));
  }, [data]);

  // Memoize event handler
  const handleUpdate = useCallback((id: string) => {
    onUpdate(id);
  }, [onUpdate]);

  return (
    <div>
      {processedData.map(item => (
        <Item key={item.id} item={item} onUpdate={handleUpdate} />
      ))}
    </div>
  );
});
```

### Bundle Optimization

1. **Code Splitting**: Use dynamic imports for large components
2. **Tree Shaking**: Use ES6 imports for better tree shaking
3. **Bundle Analysis**: Regularly analyze bundle size
4. **Dependency Management**: Keep dependencies minimal

```typescript
// Dynamic import for large component
const HeavyComponent = lazy(() => import('./HeavyComponent'));

// Use in component
function App() {
  return (
    <Suspense fallback={<Loading />}>
      <HeavyComponent />
    </Suspense>
  );
}
```

### Performance Monitoring

1. **Core Web Vitals**: Monitor CWV scores
2. **Bundle Analysis**: Regular bundle size checks
3. **Performance Profiling**: Use React DevTools Profiler
4. **Custom Metrics**: Track custom performance metrics

```typescript
// Performance monitoring hook
const usePerformanceMeasure = (name: string) => {
  const startTime = useRef(performance.now());

  useEffect(() => {
    const duration = performance.now() - startTime.current;
    performanceMonitor.addCustomMetric(`${name}_render`, duration);
  });

  return {
    measureAsync: <T>(fn: () => Promise<T>) => 
      performanceMonitor.measureAsync(`${name}_async`, fn),
  };
};
```

## Git Workflow

### Branch Strategy

1. **Main Branch**: Production-ready code
2. **Feature Branches**: For new features
3. **Bug Fix Branches**: For bug fixes
4. **Release Branches**: For release preparation

```bash
# Create feature branch
git checkout -b feature/user-authentication

# Create bug fix branch
git checkout -b bugfix/login-validation

# Create release branch
git checkout -b release/v1.2.0
```

### Commit Messages

Use conventional commit format:

```bash
# Feature
feat: add user authentication system

# Bug fix
fix: resolve login validation issue

# Documentation
docs: update API documentation

# Refactoring
refactor: improve component performance

# Test
test: add unit tests for auth components

# Chore
chore: update dependencies
```

### Pull Request Process

1. **Create PR**: Create pull request with descriptive title
2. **Description**: Include detailed description of changes
3. **Tests**: Ensure all tests pass
4. **Review**: Request code review from team members
5. **Merge**: Merge after approval

**PR Template:**
```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual testing completed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] No console errors
```

## Debugging Guidelines

### Common Issues

1. **Build Errors**
   ```bash
   # Clear Next.js cache
   rm -rf .next
   npm run build
   
   # Check TypeScript errors
   npx tsc --noEmit
   ```

2. **Test Failures**
   ```bash
   # Run tests with verbose output
   npm test -- --verbose
   
   # Run specific test
   npm test -- --testNamePattern="Button"
   ```

3. **Performance Issues**
   ```bash
   # Analyze bundle
   npm run analyze
   
   # Profile with React DevTools
   # Use Performance tab in browser DevTools
   ```

### Debug Tools

1. **React DevTools**: For component debugging
2. **Redux DevTools**: For state debugging (if using Redux)
3. **Network Tab**: For API debugging
4. **Console**: For general debugging

### Error Boundaries

Use error boundaries for graceful error handling:

```typescript
class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error('Error caught by boundary:', error, errorInfo);
    // Send to error reporting service
  }

  render() {
    if (this.state.hasError) {
      return <ErrorFallback error={this.state.error} />;
    }

    return this.props.children;
  }
}
```

## Security Guidelines

### Input Validation

1. **Client-Side Validation**: Validate all user inputs
2. **Server-Side Validation**: Never trust client-side validation
3. **Type Safety**: Use TypeScript for type safety
4. **Sanitization**: Sanitize user inputs

```typescript
// Input validation
const validateEmail = (email: string): boolean => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

// Sanitize input
const sanitizeInput = (input: string): string => {
  return input.replace(/[<>]/g, '');
};
```

### Security Headers

Ensure security headers are configured:

```typescript
// next.config.ts
async headers() {
  return [
    {
      source: '/(.*)',
      headers: [
        { key: 'X-Content-Type-Options', value: 'nosniff' },
        { key: 'X-Frame-Options', value: 'DENY' },
        { key: 'X-XSS-Protection', value: '1; mode=block' },
      ],
    },
  ];
}
```

### Environment Variables

1. **Never Commit Secrets**: Never commit secrets to version control
2. **Use .env.local**: Use .env.local for local development
3. **Validate Environment**: Validate required environment variables
4. **Type Environment**: Type environment variables

```typescript
// Environment validation
const requiredEnvVars = [
  'NEXT_PUBLIC_API_URL',
  'NEXT_PUBLIC_WS_URL',
];

requiredEnvVars.forEach(varName => {
  if (!process.env[varName]) {
    throw new Error(`Missing required environment variable: ${varName}`);
  }
});
```

## Contribution Guidelines

### Getting Started

1. **Fork Repository**: Fork the repository
2. **Create Branch**: Create feature branch
3. **Make Changes**: Implement your changes
4. **Write Tests**: Add tests for new functionality
5. **Submit PR**: Create pull request

### Code Review Checklist

- [ ] Code follows style guidelines
- [ ] Tests are written and passing
- [ ] Documentation is updated
- [ ] No console errors or warnings
- [ ] Performance impact is considered
- [ ] Accessibility requirements are met
- [ ] Security considerations are addressed

### Release Process

1. **Version Bump**: Update version in package.json
2. **Changelog**: Update CHANGELOG.md
3. **Tag Release**: Create git tag
4. **Deploy**: Deploy to production
5. **Announce**: Announce release

```bash
# Version bump
npm version patch  # or minor/major

# Create tag
git tag -a v1.2.0 -m "Release v1.2.0"

# Push tag
git push origin v1.2.0
```

## Support and Resources

### Documentation

- **README.md**: Project overview and setup
- **API.md**: API documentation
- **COMPONENTS.md**: Component documentation
- **DEPLOYMENT.md**: Deployment guide
- **PERFORMANCE.md**: Performance optimization guide

### Tools and Services

- **GitHub**: Source code and issues
- **GitHub Discussions**: Questions and ideas
- **GitHub Actions**: CI/CD pipeline
- **Vercel**: Deployment platform (optional)

### Getting Help

1. **Documentation**: Check existing documentation
2. **Issues**: Search existing issues
3. **Discussions**: Ask in GitHub Discussions
4. **Create Issue**: Create new issue with details

When asking for help, include:
- Clear description of the problem
- Steps to reproduce
- Expected vs actual behavior
- Environment details
- Error messages and logs 