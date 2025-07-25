import React, { useMemo } from 'react';

interface InputProps {
  id?: string;
  label: string;
  placeholder?: string;
  value: string;
  onChange: (e: React.ChangeEvent<HTMLInputElement>) => void;
  type?: string;
  required?: boolean;
  disabled?: boolean;
  className?: string;
  min?: string | number;
  max?: string | number;
  title?: string;
  onBlur?: (e: React.FocusEvent<HTMLInputElement>) => void;
  onFocus?: (e: React.FocusEvent<HTMLInputElement>) => void;
  error?: string;
  helperText?: string;
  icon?: React.ReactNode;
}

const Input: React.FC<InputProps> = ({ 
  id, 
  label, 
  placeholder, 
  value, 
  onChange, 
  type = 'text', 
  required, 
  disabled, 
  className, 
  min, 
  max, 
  title, 
  onBlur,
  onFocus,
  error,
  helperText,
  icon
}) => {
  const inputId = id || (label ? `input-${label.toLowerCase().replace(/\s+/g, '-')}` : `input-${Math.random().toString(36).substr(2, 9)}`);
  
  const inputClasses = useMemo(() => {
    const baseClasses = "w-full bg-zinc-800 border text-gray-100 placeholder-gray-400 rounded-md p-2 border-zinc-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent";
    const errorClasses = error ? "border-red-500 focus:ring-red-500" : "";
    const disabledClasses = disabled ? "opacity-50 cursor-not-allowed" : "";
    return `${baseClasses} ${errorClasses} ${disabledClasses}`.trim();
  }, [error, disabled]);

  return (
    <div>
      {label && (
        <label htmlFor={inputId} className="block text-gray-200 text-sm font-medium mb-2">{label}</label>
      )}
      <div className={`relative ${className || ''}`}>
        {icon && (
          <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
            {icon}
          </div>
        )}
        <input
          id={inputId}
          type={type}
          className={inputClasses}
          style={icon ? { paddingLeft: '2.5rem' } : undefined}
          placeholder={placeholder}
          value={value}
          onChange={onChange}
          required={required}
          disabled={disabled}
          min={min}
          max={max}
          title={title}
          onBlur={onBlur}
          onFocus={onFocus}
        />
      </div>
      {error && (
        <p className="mt-1 text-sm text-red-400">{error}</p>
      )}
      {helperText && !error && (
        <p className="mt-1 text-sm text-gray-400">{helperText}</p>
      )}
    </div>
  );
};

export default React.memo(Input); 