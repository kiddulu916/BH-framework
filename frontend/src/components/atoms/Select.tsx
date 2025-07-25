import React, { useMemo } from 'react';

interface SelectProps extends React.SelectHTMLAttributes<HTMLSelectElement> {
  label?: string;
  options: { value: string; label: string }[];
  error?: string;
  helperText?: string;
  icon?: React.ReactNode;
}

const SelectWithRef = React.forwardRef<HTMLSelectElement, SelectProps>(
  ({ label, options, error, helperText, icon, id, className = '', ...props }, ref) => {
    const selectId = useMemo(() => 
      id || `select-${Math.random().toString(36).substr(2, 9)}`, 
      [id]
    );
    
    const selectClassName = useMemo(() => `
      w-full bg-zinc-800 border text-gray-100 rounded-md p-2
      ${error ? 'border-red-500' : 'border-zinc-700'}
      ${icon ? 'pl-10' : ''}
      ${props.disabled ? 'opacity-50 cursor-not-allowed' : ''}
      focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent
    `.trim(), [error, icon, props.disabled]);
    
    const optionElements = useMemo(() => 
      options.map((option) => (
        <option key={option.value} value={option.value}>
          {option.label}
        </option>
      )), 
      [options]
    );
    
    return (
      <div className={className}>
        {label && (
          <label htmlFor={selectId} className="block text-gray-200 text-sm font-medium mb-2">
            {label}
          </label>
        )}
        <div className="relative">
          {icon && (
            <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
              {icon}
            </div>
          )}
          <select
            ref={ref}
            id={selectId}
            className={selectClassName}
            {...props}
          >
            {optionElements}
          </select>
        </div>
        {error && (
          <p className="text-red-400 text-sm mt-1">{error}</p>
        )}
        {helperText && !error && (
          <p className="text-gray-400 text-sm mt-1">{helperText}</p>
        )}
      </div>
    );
  }
);

SelectWithRef.displayName = 'Select';

const Select = React.memo(SelectWithRef);

export default Select; 