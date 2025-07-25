# Component Documentation

## Overview

This document provides comprehensive documentation for all components in the Bug Hunting Framework Frontend. The application follows atomic design principles with components organized into atoms, molecules, organisms, templates, and pages.

## Component Architecture

### Atomic Design Structure
```
src/components/
├── atoms/               # Basic building blocks
│   ├── Button.tsx
│   ├── Input.tsx
│   ├── Select.tsx
│   ├── ValidationError.tsx
│   ├── ErrorBoundary.tsx
│   └── PerformanceMonitor.tsx
├── molecules/           # Simple combinations of atoms
│   └── StepProgress.tsx
├── organisms/           # Complex components
│   └── steps/
│       ├── BasicInfoStep.tsx
│       ├── ProgramDetailsStep.tsx
│       ├── ScopeConfigStep.tsx
│       ├── RateLimitStep.tsx
│       ├── AdditionalRulesStep.tsx
│       └── ReviewStep.tsx
├── pages/               # Page-level components
│   └── TargetProfileBuilder.tsx
├── providers/           # Context providers
│   ├── HydrationProvider.tsx
│   └── QueryProvider.tsx
└── templates/           # Layout templates
```

## Atoms

### Button

A reusable button component with various styles and states.

**File:** `src/components/atoms/Button.tsx`

**Props:**
```typescript
interface ButtonProps {
  children: React.ReactNode;
  variant?: 'primary' | 'secondary' | 'outline' | 'ghost';
  size?: 'sm' | 'md' | 'lg';
  disabled?: boolean;
  loading?: boolean;
  onClick?: () => void;
  type?: 'button' | 'submit' | 'reset';
  className?: string;
}
```

**Usage:**
```tsx
import { Button } from '@/components/atoms/Button';

// Primary button
<Button variant="primary" onClick={handleClick}>
  Create Target
</Button>

// Loading button
<Button variant="primary" loading={true}>
  Creating...
</Button>

// Disabled button
<Button variant="secondary" disabled={true}>
  Submit
</Button>
```

**Features:**
- Multiple variants (primary, secondary, outline, ghost)
- Different sizes (sm, md, lg)
- Loading state with spinner
- Disabled state
- TypeScript support
- Accessibility features

### Input

A form input component with validation and error handling.

**File:** `src/components/atoms/Input.tsx`

**Props:**
```typescript
interface InputProps {
  label: string;
  name: string;
  type?: 'text' | 'email' | 'password' | 'url' | 'number';
  placeholder?: string;
  value: string;
  onChange: (value: string) => void;
  error?: string;
  required?: boolean;
  disabled?: boolean;
  className?: string;
}
```

**Usage:**
```tsx
import { Input } from '@/components/atoms/Input';

<Input
  label="Target Name"
  name="name"
  type="text"
  placeholder="Enter target name"
  value={name}
  onChange={setName}
  error={errors.name}
  required={true}
/>
```

**Features:**
- Label and error display
- Multiple input types
- Validation integration
- Accessibility support
- Memoized for performance

### Select

A dropdown select component with search and multi-select capabilities.

**File:** `src/components/atoms/Select.tsx`

**Props:**
```typescript
interface SelectProps {
  label: string;
  name: string;
  options: Array<{ value: string; label: string }>;
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  error?: string;
  required?: boolean;
  disabled?: boolean;
  searchable?: boolean;
  className?: string;
}
```

**Usage:**
```tsx
import { Select } from '@/components/atoms/Select';

const platformOptions = [
  { value: 'hackerone', label: 'HackerOne' },
  { value: 'bugcrowd', label: 'Bugcrowd' },
  { value: 'intigriti', label: 'Intigriti' },
];

<Select
  label="Platform"
  name="platform"
  options={platformOptions}
  value={platform}
  onChange={setPlatform}
  placeholder="Select a platform"
  error={errors.platform}
  required={true}
/>
```

**Features:**
- Searchable dropdown
- Keyboard navigation
- Custom styling
- Error handling
- Accessibility support

### ValidationError

A component for displaying validation errors.

**File:** `src/components/atoms/ValidationError.tsx`

**Props:**
```typescript
interface ValidationErrorProps {
  error?: string;
  className?: string;
}
```

**Usage:**
```tsx
import { ValidationError } from '@/components/atoms/ValidationError';

<ValidationError error={errors.name} />
```

**Features:**
- Consistent error styling
- Accessibility support
- Memoized for performance

### ErrorBoundary

A React error boundary component for catching and handling errors.

**File:** `src/components/atoms/ErrorBoundary.tsx`

**Props:**
```typescript
interface ErrorBoundaryProps {
  children: React.ReactNode;
  fallback?: React.ComponentType<{ error: Error; resetError: () => void }>;
}
```

**Usage:**
```tsx
import { ErrorBoundary } from '@/components/atoms/ErrorBoundary';

<ErrorBoundary>
  <TargetProfileBuilder />
</ErrorBoundary>
```

**Features:**
- Error catching and display
- Retry functionality
- Custom fallback UI
- Error reporting integration

### PerformanceMonitor

A component for displaying real-time performance metrics in development.

**File:** `src/components/atoms/PerformanceMonitor.tsx`

**Props:**
```typescript
interface PerformanceMonitorProps {
  className?: string;
}
```

**Usage:**
```tsx
import { PerformanceMonitor } from '@/components/atoms/PerformanceMonitor';

// Only in development
{process.env.NODE_ENV === 'development' && (
  <PerformanceMonitor />
)}
```

**Features:**
- Core Web Vitals display
- Custom metrics tracking
- Real-time updates
- Development-only rendering

## Molecules

### StepProgress

A progress indicator for multi-step forms.

**File:** `src/components/molecules/StepProgress.tsx`

**Props:**
```typescript
interface StepProgressProps {
  currentStep: number;
  totalSteps: number;
  steps: Array<{ title: string; description?: string }>;
  className?: string;
}
```

**Usage:**
```tsx
import { StepProgress } from '@/components/molecules/StepProgress';

const steps = [
  { title: 'Basic Info', description: 'Target details' },
  { title: 'Program Details', description: 'Platform settings' },
  { title: 'Scope', description: 'In/out scope configuration' },
  { title: 'Rate Limits', description: 'API rate limiting' },
  { title: 'Additional Rules', description: 'Custom rules' },
  { title: 'Review', description: 'Final review' },
];

<StepProgress
  currentStep={currentStep}
  totalSteps={steps.length}
  steps={steps}
/>
```

**Features:**
- Visual progress indicator
- Step titles and descriptions
- Responsive design
- Accessibility support

## Organisms

### Form Steps

Complex form components that combine multiple atoms and molecules.

#### BasicInfoStep

**File:** `src/components/organisms/steps/BasicInfoStep.tsx`

**Props:**
```typescript
interface BasicInfoStepProps {
  data: {
    name: string;
    domain: string;
  };
  errors: Record<string, string>;
  onChange: (field: string, value: string) => void;
  onNext: () => void;
  onBack: () => void;
}
```

**Features:**
- Target name and domain inputs
- Real-time validation
- Navigation controls
- Error handling

#### ProgramDetailsStep

**File:** `src/components/organisms/steps/ProgramDetailsStep.tsx`

**Props:**
```typescript
interface ProgramDetailsStepProps {
  data: {
    platform: string;
    program_url?: string;
    program_id?: string;
  };
  errors: Record<string, string>;
  onChange: (field: string, value: string) => void;
  onNext: () => void;
  onBack: () => void;
}
```

**Features:**
- Platform selection
- Program URL and ID inputs
- Platform-specific validation
- Conditional field display

#### ScopeConfigStep

**File:** `src/components/organisms/steps/ScopeConfigStep.tsx`

**Props:**
```typescript
interface ScopeConfigStepProps {
  data: {
    scope: {
      in_scope: string[];
      out_scope: string[];
    };
  };
  errors: Record<string, string>;
  onChange: (field: string, value: any) => void;
  onNext: () => void;
  onBack: () => void;
}
```

**Features:**
- In-scope and out-scope configuration
- Dynamic list management
- Pattern validation
- Bulk import/export

#### RateLimitStep

**File:** `src/components/organisms/steps/RateLimitStep.tsx`

**Props:**
```typescript
interface RateLimitStepProps {
  data: {
    rate_limits: RateLimitConfig[];
  };
  errors: Record<string, string>;
  onChange: (field: string, value: any) => void;
  onNext: () => void;
  onBack: () => void;
}
```

**Features:**
- Rate limit configuration
- Dynamic form fields
- Validation rules
- Preset templates

#### AdditionalRulesStep

**File:** `src/components/organisms/steps/AdditionalRulesStep.tsx`

**Props:**
```typescript
interface AdditionalRulesStepProps {
  data: {
    additional_rules: string;
  };
  errors: Record<string, string>;
  onChange: (field: string, value: string) => void;
  onNext: () => void;
  onBack: () => void;
}
```

**Features:**
- Text area for custom rules
- Character count
- Markdown support
- Template suggestions

#### ReviewStep

**File:** `src/components/organisms/steps/ReviewStep.tsx`

**Props:**
```typescript
interface ReviewStepProps {
  data: TargetFormData;
  errors: Record<string, string>;
  onSubmit: () => void;
  onBack: () => void;
  isSubmitting: boolean;
}
```

**Features:**
- Data review display
- Edit functionality
- Submission handling
- Loading states

## Pages

### TargetProfileBuilder

The main page component that orchestrates the entire target creation workflow.

**File:** `src/components/pages/TargetProfileBuilder.tsx`

**Props:**
```typescript
interface TargetProfileBuilderProps {
  initialData?: Partial<TargetFormData>;
  onComplete?: (data: TargetFormData) => void;
}
```

**Features:**
- Multi-step form orchestration
- State management integration
- Navigation controls
- Progress tracking
- Error handling
- Form persistence
- API integration

**Usage:**
```tsx
import { TargetProfileBuilder } from '@/components/pages/TargetProfileBuilder';

<TargetProfileBuilder
  initialData={savedData}
  onComplete={handleTargetCreated}
/>
```

## Providers

### HydrationProvider

A provider for handling hydration mismatches in SSR.

**File:** `src/components/providers/HydrationProvider.tsx`

**Props:**
```typescript
interface HydrationProviderProps {
  children: React.ReactNode;
}
```

**Usage:**
```tsx
import { HydrationProvider } from '@/components/providers/HydrationProvider';

<HydrationProvider>
  <App />
</HydrationProvider>
```

### QueryProvider

A provider for React Query configuration.

**File:** `src/components/providers/QueryProvider.tsx`

**Props:**
```typescript
interface QueryProviderProps {
  children: React.ReactNode;
}
```

**Usage:**
```tsx
import { QueryProvider } from '@/components/providers/QueryProvider';

<QueryProvider>
  <App />
</QueryProvider>
```

## Component Patterns

### Performance Optimization

All components are optimized for performance:

```tsx
// Memoization for expensive components
const Button = React.memo<ButtonProps>(({ children, ...props }) => {
  // Component implementation
});

// useMemo for expensive computations
const options = useMemo(() => {
  return platforms.map(platform => ({
    value: platform.value,
    label: platform.label,
  }));
}, [platforms]);

// useCallback for event handlers
const handleChange = useCallback((value: string) => {
  onChange(value);
}, [onChange]);
```

### Accessibility

All components include accessibility features:

```tsx
// Proper labeling
<label htmlFor={id} className="block text-sm font-medium text-gray-700">
  {label}
</label>
<input
  id={id}
  aria-describedby={error ? `${id}-error` : undefined}
  aria-invalid={!!error}
  // ... other props
/>

// Error association
{error && (
  <div id={`${id}-error`} role="alert" className="text-red-600 text-sm">
    {error}
  </div>
)}
```

### Error Handling

Components implement comprehensive error handling:

```tsx
// Error boundaries
<ErrorBoundary fallback={ErrorFallback}>
  <Component />
</ErrorBoundary>

// Form validation
const errors = validateForm(data);
if (Object.keys(errors).length > 0) {
  setErrors(errors);
  return;
}
```

### Testing

All components include comprehensive tests:

```tsx
// Component test example
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
});
```

## Best Practices

### Component Design

1. **Single Responsibility**: Each component has a single, well-defined purpose
2. **Composition**: Use composition over inheritance
3. **Props Interface**: Define clear TypeScript interfaces for all props
4. **Default Props**: Provide sensible defaults where appropriate
5. **Documentation**: Include JSDoc comments for complex components

### Performance

1. **Memoization**: Use React.memo for pure components
2. **useMemo/useCallback**: Optimize expensive computations and callbacks
3. **Lazy Loading**: Implement lazy loading for large components
4. **Bundle Splitting**: Use dynamic imports for code splitting

### Accessibility

1. **Semantic HTML**: Use appropriate HTML elements
2. **ARIA Labels**: Provide proper ARIA attributes
3. **Keyboard Navigation**: Ensure keyboard accessibility
4. **Screen Reader Support**: Test with screen readers
5. **Color Contrast**: Maintain proper color contrast ratios

### Testing

1. **Unit Tests**: Test individual component functionality
2. **Integration Tests**: Test component interactions
3. **Accessibility Tests**: Test accessibility features
4. **Visual Tests**: Test component appearance
5. **Performance Tests**: Test component performance

## Component Library

### Installation

The component library is built into the application and doesn't require separate installation.

### Usage

```tsx
import { Button, Input, Select } from '@/components/atoms';
import { StepProgress } from '@/components/molecules';
import { TargetProfileBuilder } from '@/components/pages';
```

### Customization

Components can be customized through:

1. **Props**: Pass custom props to override defaults
2. **CSS Classes**: Use className prop for custom styling
3. **Theme**: Modify Tailwind CSS theme configuration
4. **Composition**: Combine components to create new patterns

## Future Enhancements

### Planned Components

1. **DataTable**: For displaying tabular data
2. **Modal**: For modal dialogs and overlays
3. **Toast**: For notification messages
4. **Tabs**: For tabbed interfaces
5. **Accordion**: For collapsible content
6. **Pagination**: For paginated content

### Component Improvements

1. **Storybook Integration**: For component documentation and testing
2. **Design System**: Comprehensive design tokens and guidelines
3. **Animation Library**: Enhanced animation capabilities
4. **Internationalization**: Multi-language support
5. **Theme System**: Dark mode and custom themes

## Support

For component support:
- **Documentation**: This document and inline code comments
- **Examples**: Check the test files for usage examples
- **Issues**: Create an issue on GitHub with detailed information
- **Discussions**: Use GitHub Discussions for questions and ideas

When reporting component issues, please include:
- Component name and file path
- Props being passed
- Expected vs actual behavior
- Steps to reproduce
- Browser and version information 