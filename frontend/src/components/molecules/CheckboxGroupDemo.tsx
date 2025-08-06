'use client';

import { useState } from 'react';
import { CheckboxGroup } from './CheckboxGroup';

export function CheckboxGroupDemo() {
  const [selectedTools, setSelectedTools] = useState<string[]>([]);

  const handleToolChange = (tool: string, checked: boolean) => {
    if (tool === 'All') {
      if (checked) {
        // If "All" is checked, clear the selection (empty array means all tools)
        setSelectedTools([]);
      } else {
        // If "All" is unchecked, keep current selection (allows individual tool selection)
        setSelectedTools(selectedTools);
      }
    } else {
      // Handle individual tool selection
      if (checked) {
        setSelectedTools([...selectedTools, tool]);
      } else {
        setSelectedTools(selectedTools.filter(t => t !== tool));
      }
    }
  };

  const tools = ['Nuclei', 'Nmap', 'Nikto', 'ZAP', 'Wapiti', 'Arachni'];

  return (
    <div className="p-6 bg-gray-800 rounded-lg">
      <h3 className="text-lg font-semibold text-white mb-4">Tool Selection Demo</h3>
      <div className="mb-4">
        <p className="text-gray-300 text-sm">
          Selected Tools: {selectedTools.length === 0 ? 'All tools' : selectedTools.join(', ')}
        </p>
        <p className="text-gray-400 text-xs mt-1">
          Array: [{selectedTools.length === 0 ? 'empty (All selected)' : `"${selectedTools.join('", "')}"`}]
        </p>
      </div>
      <CheckboxGroup
        tools={tools}
        selectedTools={selectedTools}
        onToolChange={handleToolChange}
      />
    </div>
  );
} 