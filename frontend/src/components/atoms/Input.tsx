import React from 'react';

interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label: string;
}

const InputWithRef = React.forwardRef<HTMLInputElement, InputProps>(({ label, ...props }, ref) => (
  <div>
    <label className="block text-gray-200 text-sm font-medium mb-2">{label}</label>
    <input
      ref={ref}
      className="w-full bg-zinc-800 border border-zinc-700 text-gray-100 placeholder-gray-400 rounded-md p-2"
      {...props}
    />
  </div>
));

InputWithRef.displayName = 'Input';

export default function Input(props: InputProps) {
    return <InputWithRef {...props} />;
} 