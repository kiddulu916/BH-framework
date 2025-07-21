import { create } from 'zustand';
import { TargetCreateRequest, BugBountyPlatform } from '@/types/target';

interface TargetFormState {
  formData: Partial<TargetCreateRequest>;
  currentStep: number;
  nextStep: () => void;
  prevStep: () => void;
  updateFormData: (data: Partial<TargetCreateRequest>) => void;
  resetForm: () => void;
}

const initialFormData: Partial<TargetCreateRequest> = {
  target: '',
  domain: '',
  is_primary: false,
  platform: BugBountyPlatform.HACKERONE,
  platform_email: '',
  researcher_email: '',
  in_scope: [],
  out_of_scope: [],
  rules_to_follow: [],
  rules_to_avoid: [],
  rate_limit_requests: 0,
  rate_limit_seconds: 0,
};

export const useTargetFormStore = create<TargetFormState>((set) => ({
  formData: initialFormData,
  currentStep: 1,
  nextStep: () => set((state) => ({ currentStep: Math.min(state.currentStep + 1, 6) })),
  prevStep: () => set((state) => ({ currentStep: Math.max(state.currentStep - 1, 1) })),
  updateFormData: (data) => set((state) => ({ formData: { ...state.formData, ...data } })),
  resetForm: () => set({ formData: initialFormData, currentStep: 1 }),
})); 