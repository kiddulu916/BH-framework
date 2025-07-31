'use client';

interface CheckboxGroupProps {
  tools: string[];
  selectedTools: string[];
  onToolChange: (tool: string, checked: boolean) => void;
}

export function CheckboxGroup({ tools, selectedTools, onToolChange }: CheckboxGroupProps) {
  const isAllSelected = selectedTools.length === 0;
  const isAllUnselected = selectedTools.length === tools.length;

  return (
    <div className="space-y-4">
      {/* "All" checkbox */}
      <label className="flex items-center space-x-3 cursor-pointer group">
        <input
          type="checkbox"
          checked={isAllSelected}
          onChange={(e) => onToolChange('All', e.target.checked)}
          className="w-4 h-4 text-blue-600 bg-gray-700 border-gray-600 rounded focus:ring-blue-500 focus:ring-2 focus:ring-offset-2 focus:ring-offset-gray-800 transition-colors duration-200"
        />
        <span className="text-gray-300 text-sm font-medium group-hover:text-white transition-colors duration-200">
          All
        </span>
      </label>

      {/* Individual tool checkboxes - arranged in two rows */}
      <div className="grid grid-cols-2 gap-3">
        {tools.map((tool, index) => (
          <label key={tool} className="flex items-center space-x-2 cursor-pointer group">
            <input
              type="checkbox"
              checked={selectedTools.includes(tool)}
              onChange={(e) => onToolChange(tool, e.target.checked)}
              disabled={isAllSelected}
              className={`w-3.5 h-3.5 text-blue-600 bg-gray-700 border-gray-600 rounded focus:ring-blue-500 focus:ring-2 focus:ring-offset-1 focus:ring-offset-gray-800 transition-all duration-200 ${
                isAllSelected ? 'opacity-50 cursor-not-allowed' : 'hover:border-gray-500'
              }`}
            />
            <span className={`text-gray-300 text-xs transition-all duration-200 ${
              isAllSelected ? 'opacity-50' : 'group-hover:text-gray-200'
            }`}>
              {tool}
            </span>
          </label>
        ))}
      </div>
    </div>
  );
} 