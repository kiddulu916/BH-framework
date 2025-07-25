import React, { useMemo } from 'react';
import { AlertCircle } from 'lucide-react';

interface ValidationErrorProps {
  errors?: string[];
  className?: string;
}

const ValidationError = React.memo(({ errors, className = '' }: ValidationErrorProps) => {
  if (!Array.isArray(errors) || errors.length === 0) {
    return null;
  }
  const errorElements = useMemo(() => 
    errors.map((error, index) => (
      <div key={index} className="flex items-center gap-1">
        <AlertCircle 
          size={14} 
          className="flex-shrink-0" 
          data-testid="alert-circle-icon"
        />
        <span>{error}</span>
      </div>
    )), 
    [errors]
  );

  return (
    <div className={`text-red-400 text-sm mt-1 ${className}`}>
      {errorElements}
    </div>
  );
});

ValidationError.displayName = 'ValidationError';

export default ValidationError; 