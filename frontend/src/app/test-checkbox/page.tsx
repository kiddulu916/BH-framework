'use client';

import { useState } from 'react';
import { CheckboxGroup } from '@/components/molecules/CheckboxGroup';

export default function TestCheckboxPage() {
  const [selectedTools, setSelectedTools] = useState<string[]>([]);

  const handleToolChange = (tool: string, checked: boolean) => {
    console.log('Test page: Tool change:', tool, checked);
    
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
    <div className="min-h-screen bg-gray-900 text-white p-8">
      <div className="max-w-2xl mx-auto">
        <h1 className="text-2xl font-bold mb-6">CheckboxGroup Test</h1>
        
        <div className="bg-gray-800 rounded-lg p-6 mb-6">
          <h2 className="text-lg font-semibold mb-4">Current State</h2>
          <div className="space-y-2 text-sm">
            <p>Selected Tools: {selectedTools.length === 0 ? 'All tools' : selectedTools.join(', ')}</p>
            <p>Array: [{selectedTools.length === 0 ? 'empty (All selected)' : `"${selectedTools.join('", "')}"`}]</p>
            <p>Is All Selected: {selectedTools.length === 0 ? 'Yes' : 'No'}</p>
          </div>
        </div>

        <div className="bg-gray-800 rounded-lg p-6">
          <h2 className="text-lg font-semibold mb-4">CheckboxGroup Component</h2>
          <CheckboxGroup
            tools={tools}
            selectedTools={selectedTools}
            onToolChange={handleToolChange}
          />
        </div>
      </div>
    </div>
  );
} 