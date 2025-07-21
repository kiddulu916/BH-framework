'use client';

import React, { useState } from 'react';
import { useTargetFormStore } from '@/lib/state/targetFormStore';
import { AnimatePresence, motion, Variants } from 'framer-motion';
import BasicInfoStep from '@/components/organisms/steps/BasicInfoStep';
import ProgramDetailsStep from '@/components/organisms/steps/ProgramDetailsStep';
import ScopeConfigStep from '@/components/organisms/steps/ScopeConfigStep';
import AdditionalRulesStep from '@/components/organisms/steps/AdditionalRulesStep';
import RateLimitStep from '@/components/organisms/steps/RateLimitStep';
import ReviewStep from '@/components/organisms/steps/ReviewStep';

function PlaceholderDashboard({ target }: { target?: string | null }) {
  return (
    <div className="min-h-screen flex flex-col items-center justify-center">
      <h1 className="text-5xl font-bold mb-6 text-white drop-shadow-lg">Bug Hunting Framework</h1>
      {target && (
        <div className="bg-white/10 rounded-xl p-8 shadow-xl text-center text-white max-w-lg">
          <p className="mb-2 text-xl">Last Target Created:</p>
          <p className="font-semibold text-2xl">{target}</p>
        </div>
      )}
    </div>
  );
}

const stepComponents = [
  BasicInfoStep,
  ProgramDetailsStep,
  ScopeConfigStep,
  AdditionalRulesStep,
  RateLimitStep,
  ReviewStep,
];

export default function TargetProfileBuilder() {
  const { currentStep, nextStep, prevStep, formData, resetForm } = useTargetFormStore();
  const [stepperActive, setStepperActive] = useState(true);
  const [lastTarget, setLastTarget] = useState<string | null>(null);
  const [direction, setDirection] = useState(0);

  const handleNext = () => {
    setDirection(1);
    nextStep();
  };
  const handlePrev = () => {
    setDirection(-1);
    prevStep();
  };

  const handleSubmit = async () => {
    setLastTarget(formData.target || 'New Target');
    setStepperActive(false);
    resetForm();
  };

  const StepComponent = stepComponents[currentStep - 1];

  const variants: Variants = {
    initial: (dir: number) => ({
      x: dir === 0 ? 0 : dir > 0 ? 300 : -300,
      opacity: 0,
      y: dir === 0 ? 100 : 0,
    }),
    animate: {
      x: 0,
      opacity: 1,
      y: 0,
      transition: { type: 'spring', stiffness: 300, damping: 30 },
    },
    exit: (dir: number) => ({
      x: dir > 0 ? -300 : 300,
      opacity: 0,
      y: 0,
      transition: { duration: 0.3 },
    }),
  };

  return (
    <div className="relative min-h-screen bg-zinc-900">
      <div className="fixed inset-0 z-0">
        <PlaceholderDashboard target={lastTarget} />
      </div>
      <AnimatePresence>
        {stepperActive && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.5 }}
            className="fixed inset-0 z-10 bg-black/60 backdrop-blur-md"
          />
        )}
      </AnimatePresence>
      <AnimatePresence mode="wait" custom={direction}>
        {stepperActive && (
          <motion.div
            key={currentStep}
            custom={direction}
            variants={variants}
            initial="initial"
            animate="animate"
            exit="exit"
            className="fixed inset-0 z-50 flex items-center justify-center p-4"
          >
            <div className="w-full max-w-xl bg-zinc-900 rounded-xl p-8 shadow-lg">
              <StepComponent />
              <div className="flex justify-between mt-8">
                <button
                  onClick={handlePrev}
                  disabled={currentStep === 1}
                  className="inline-flex items-center gap-2 px-4 py-2 bg-white text-zinc-900 rounded-md font-medium shadow hover:bg-gray-100 transition disabled:opacity-50"
                >
                  <span>&larr;</span> Previous
                </button>
                {currentStep < stepComponents.length ? (
                  <button
                    onClick={handleNext}
                    className="inline-flex items-center gap-2 px-4 py-2 bg-white text-zinc-900 rounded-md font-medium shadow hover:bg-gray-100 transition"
                  >
                    Next <span>&rarr;</span>
                  </button>
                ) : (
                  <button
                    onClick={handleSubmit}
                    className="inline-flex items-center gap-2 px-4 py-2 bg-white text-zinc-900 rounded-md font-medium shadow hover:bg-gray-100 transition"
                  >
                    Submit <span>&rarr;</span>
                  </button>
                )}
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}; 