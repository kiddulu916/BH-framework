'use client';

import React, { useRef, useState, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useTargetFormStore } from '@/lib/state/targetFormStore';
import BasicInfoStep from '@/components/organisms/steps/BasicInfoStep';
import ProgramDetailsStep from '@/components/organisms/steps/ProgramDetailsStep';
import ScopeConfigStep from '@/components/organisms/steps/ScopeConfigStep';
import RateLimitStep from '@/components/organisms/steps/RateLimitStep';
import AdditionalInfoStep from '@/components/organisms/steps/AdditionalInfoStep';
import ReviewStep from '@/components/organisms/steps/ReviewStep';
import StepProgress from '@/components/molecules/StepProgress';
import { StepRef } from '@/components/organisms/steps/BasicInfoStep';
import { createTarget } from '@/lib/api/targets';
import { useRouter } from 'next/navigation';

export default function TargetProfileBuilder() {
  const router = useRouter();
  const { 
    currentStep, 
    nextStep, 
    prevStep, 
    formData, 
    resetForm, 
    validationErrors, 
    isSubmitting, 
    submitError,
    setSubmitting, 
    setSubmitError 
  } = useTargetFormStore();
  
  const step1Ref = useRef<StepRef | null>(null);
  const step2Ref = useRef<StepRef | null>(null);
  const step3Ref = useRef<StepRef | null>(null);
  const step4Ref = useRef<StepRef | null>(null);
  const step5Ref = useRef<StepRef | null>(null);
  const step6Ref = useRef<StepRef | null>(null);
  const [isSubmittingForm, setIsSubmittingForm] = useState(false);

  const steps = [
    { title: 'Basic Info', component: BasicInfoStep },
    { title: 'Program Details', component: ProgramDetailsStep },
    { title: 'Scope Config', component: ScopeConfigStep },
    { title: 'Rate Limiting', component: RateLimitStep },
    { title: 'Additional Info', component: AdditionalInfoStep },
    { title: 'Review', component: ReviewStep },
  ];

  const getCurrentStepRef = () => {
    switch (currentStep) {
      case 1: return step1Ref;
      case 2: return step2Ref;
      case 3: return step3Ref;
      case 4: return step4Ref;
      case 5: return step5Ref;
      case 6: return step6Ref;
      default: return step1Ref;
    }
  };

  const handleNext = async () => {
    const currentStepRef = getCurrentStepRef();
    if (currentStepRef.current && currentStepRef.current.validate) {
      const isValid = currentStepRef.current.validate();
      if (!isValid) {
        return;
      }
    }
    
    if (currentStepRef.current && currentStepRef.current.handleSave) {
      currentStepRef.current.handleSave();
    }
    
    if (currentStep < steps.length) {
      nextStep();
    }
  };

  const handlePrevious = () => {
    if (currentStep > 1) {
      prevStep();
    }
  };

  const handleSubmit = async () => {
    if (validationErrors.length > 0) {
      return;
    }

    setIsSubmittingForm(true);
    setSubmitting(true);
    setSubmitError(null);

    try {
      // Note: createTarget expects TargetFormData but formData is TargetFormData
      // The API client handles the mapping internally
      const res = await createTarget(formData as any);
      console.log('createTarget response', res);
      const newId = res?.data?.data?.id ?? res?.data?.id;
      if (newId) {
        // Navigate to dashboard for the new target
        router.push(`/dashboard?target=${newId}`);
      } else {
        // Fallback: reload targets list
        router.push('/dashboard');
      }
      resetForm();
    } catch (error) {
      console.error('Failed to create target:', error);
      setSubmitError(error instanceof Error ? error.message : 'Failed to create target profile');
    } finally {
      setIsSubmittingForm(false);
      setSubmitting(false);
    }
  };

  const renderCurrentStep = () => {
    switch (currentStep) {
      case 1:
        return <BasicInfoStep stepRef={step1Ref} />;
      case 2:
        return <ProgramDetailsStep stepRef={step2Ref} />;
      case 3:
        return <ScopeConfigStep stepRef={step3Ref} />;
      case 4:
        return <RateLimitStep stepRef={step4Ref} />;
      case 5:
        return <AdditionalInfoStep stepRef={step5Ref} />;
      case 6:
        return <ReviewStep stepRef={step6Ref} />;
      default:
        return <BasicInfoStep stepRef={step1Ref} />;
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-zinc-900 via-zinc-800 to-zinc-900 flex items-center justify-center p-4 overflow-y-auto">
      {/* Blurry Dashboard Background */}
      <div className="absolute inset-0 bg-gradient-to-br from-blue-900/20 via-purple-900/20 to-pink-900/20 backdrop-blur-sm">
        <div className="absolute inset-0 bg-black/40"></div>
      </div>

      <div
        className="relative z-10 w-full max-w-2xl"
        data-testid="main-container"
      >
        <AnimatePresence mode="wait">
          <motion.div
            key={currentStep}
            initial={{ x: 300, opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            exit={{ x: -300, opacity: 0 }}
            transition={{ duration: 0.3, ease: "easeInOut" }}
            className="bg-zinc-800/90 backdrop-blur-md rounded-2xl p-8 shadow-2xl border border-zinc-700/50 max-h-[90vh] overflow-y-auto"
            data-testid="form-container"
          >
            <StepProgress currentStep={currentStep} totalSteps={steps.length} />
            
            <div className="mt-8">
              {renderCurrentStep()}
            </div>

            {/* Submit Error */}
            {submitError && (
              <div className="mt-6 p-4 bg-red-900/20 border border-red-500/30 rounded-md">
                <h4 className="text-red-400 font-medium mb-2">Submission Error:</h4>
                <p className="text-red-300 text-sm">{submitError}</p>
              </div>
            )}

            {/* Navigation Buttons */}
            <div className="flex justify-between items-center mt-8">
              <button
                onClick={handlePrevious}
                disabled={currentStep === 1}
                className="flex items-center gap-2 text-gray-300 hover:text-white disabled:text-gray-600 disabled:cursor-not-allowed transition-colors"
              >
                <span>‹</span>
                <span>Previous</span>
              </button>

              <div className="flex items-center gap-4">
                {currentStep < steps.length ? (
                  <>
                    <button
                      onClick={() => {
                        const currentStepRef = getCurrentStepRef();
                        if (currentStepRef.current && currentStepRef.current.handleSave) {
                          currentStepRef.current.handleSave();
                        }
                      }}
                      className="px-4 py-2 text-sm text-gray-300 hover:text-white transition-colors"
                    >
                      Save to Target&apos;s Profile
                    </button>
                    <button
                      onClick={handleNext}
                      disabled={validationErrors.length > 0}
                      className="flex items-center gap-2 px-6 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white rounded-lg transition-colors"
                    >
                      <span>Next</span>
                      <span>›</span>
                    </button>
                  </>
                ) : (
                  <button
                    onClick={handleSubmit}
                    disabled={isSubmittingForm || isSubmitting || validationErrors.length > 0}
                    className="px-6 py-2 bg-green-600 hover:bg-green-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white rounded-lg transition-colors"
                  >
                    {isSubmittingForm ? 'Creating...' : 'Create Target Profile'}
                  </button>
                )}
              </div>
            </div>
          </motion.div>
        </AnimatePresence>
      </div>
    </div>
  );
} 