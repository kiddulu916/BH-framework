import React from 'react';

interface StepProgressProps {
  currentStep: number;
  totalSteps: number;
}

export default function StepProgress({ currentStep, totalSteps }: StepProgressProps) {
  return (
    <div className="mb-8">
      <div className="flex items-center justify-between">
        {Array.from({ length: totalSteps }, (_, index) => (
          <React.Fragment key={index}>
            <div className="flex flex-col items-center">
              <div
                className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-medium transition-colors ${
                  index + 1 <= currentStep
                    ? 'bg-blue-600 text-white'
                    : 'bg-gray-600 text-gray-300'
                }`}
              >
                {index + 1}
              </div>
              <span className="text-xs text-gray-400 mt-1">Step {index + 1}</span>
            </div>
            {index < totalSteps - 1 && (
              <div
                className={`flex-1 h-0.5 mx-2 transition-colors ${
                  index + 1 < currentStep ? 'bg-blue-600' : 'bg-gray-600'
                }`}
              />
            )}
          </React.Fragment>
        ))}
      </div>
      <div className="text-center mt-4">
        <span className="text-sm text-gray-400">
          Step {currentStep} of {totalSteps}
        </span>
      </div>
    </div>
  );
} 