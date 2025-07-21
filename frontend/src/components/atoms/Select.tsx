import React from 'react';

interface SelectProps extends React.SelectHTMLAttributes<HTMLSelectElement> {
  label: string;
  options: { value: string; label: string }[];
}

const SelectWithRef = React.forwardRef<HTMLSelectElement, SelectProps>(({ label, options, ...props }, ref) => (
  <div>
    <label className="block text-gray-200 text-sm font-medium mb-2">{label}</label>
    <select
      ref={ref}
      className="w-full bg-zinc-800 border border-zinc-700 text-gray-100 rounded-md p-2"
      {...props}
    >
      {options.map((option) => (
        <option key={option.value} value={option.value}>
          {option.label}
        </option>
      ))}
    </select>
  </div>
));

SelectWithRef.displayName = 'Select';

export default function Select(props: SelectProps) {
    return <SelectWithRef {...props} />;
} 