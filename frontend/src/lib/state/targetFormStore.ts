import { create } from 'zustand';
import { TargetCreateRequest, BugBountyPlatform, CustomHeader, TargetStatus } from '@/types/target';
import { ValidationError } from '@/lib/validation';

// Extended interface for form data that includes legacy fields for backward compatibility
interface TargetFormData extends Partial<TargetCreateRequest> {
  // Legacy field mappings for backward compatibility
  id?: string;
  target?: string;
  domain?: string;
  login_email?: string;
  researcher_email?: string;
  in_scope?: string[];
  out_of_scope?: string[];
  rate_limit_requests?: number;
  rate_limit_seconds?: number;
  custom_headers?: CustomHeader[];
  additional_info?: string[];
  notes?: string[];
}

interface TargetFormState {
  formData: TargetFormData;
  currentStep: number;
  validationErrors: ValidationError[];
  isSubmitting: boolean;
  submitError: string | null;
  nextStep: () => void;
  prevStep: () => void;
  updateFormData: (data: Partial<TargetFormData>) => void;
  setValidationErrors: (errors: ValidationError[]) => void;
  clearValidationErrors: () => void;
  setSubmitting: (isSubmitting: boolean) => void;
  setSubmitError: (error: string | null) => void;
  resetForm: () => void;
}

const initialFormData: TargetFormData = {
  // Basic target information
  id: crypto.randomUUID(),
  target: '',
  domain: '',
  is_primary: false,
  platform: BugBountyPlatform.HACKERONE,
  login_email: '',
  researcher_email: '',
  status: TargetStatus.ACTIVE,
  in_scope: [],
  out_of_scope: [],
  rate_limit_requests: 0,
  rate_limit_seconds: 0,
  custom_headers: [],
  additional_info: [],
  notes: [],
};

export const useTargetFormStore = create<TargetFormState>((set, get) => ({
  formData: initialFormData,
  currentStep: 1,
  validationErrors: [],
  isSubmitting: false,
  submitError: null,
  
  nextStep: () => set((state) => ({ currentStep: Math.min(state.currentStep + 1, 6) })),
  prevStep: () => set((state) => ({ currentStep: Math.max(state.currentStep - 1, 1) })),
  
  updateFormData: (data) => set((state) => ({ 
    formData: { ...state.formData, ...data },
    validationErrors: [], // Clear validation errors when data is updated
    submitError: null
  })),
  
  setValidationErrors: (errors) => set({ validationErrors: errors }),
  clearValidationErrors: () => set({ validationErrors: [] }),
  setSubmitting: (isSubmitting) => set({ isSubmitting }),
  setSubmitError: (error) => set({ submitError: error }),
  
  resetForm: () => set({ 
    formData: initialFormData, 
    currentStep: 1, 
    validationErrors: [], 
    isSubmitting: false, 
    submitError: null 
  }),
})); 