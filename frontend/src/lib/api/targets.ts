import axios from 'axios';
import { TargetCreateRequest, TargetScope, RateLimitConfig, TargetFilters, BugBountyPlatform, CustomHeader } from '@/types/target';

// Interface for form data that includes legacy fields for backward compatibility
interface TargetFormData {
  // Basic target information
  name?: string;
  target?: string; // Legacy field
  domain?: string; // Legacy field
  is_primary?: boolean;
  user_id?: string;
  
  // Bug Bounty Program Information
  platform?: BugBountyPlatform;
  login_email?: string;
  researcher_email?: string; // Legacy field
  
  // Scope Configuration
  in_scope?: string[]; // Legacy field
  out_of_scope?: string[]; // Legacy field
  additional_info?: string[]; // Legacy field
  notes?: string[];
  
  // Rate Limiting Configuration
  rate_limits?: RateLimitConfig;
  rate_limit_requests?: number; // Legacy field
  rate_limit_seconds?: number; // Legacy field
  
  // Custom Headers
  custom_headers?: CustomHeader[];
}

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

export const createTarget = async (formData: TargetFormData) => {
  // Transform frontend data to backend schema
  const backendData: TargetCreateRequest = {
    // Basic target information
    name: formData.target || formData.name || '',
    scope: TargetScope.DOMAIN, // Defaulting to DOMAIN as per previous implementation
    domain: formData.domain || '',
    is_primary: formData.is_primary || false,
    user_id: formData.user_id,
    // Bug Bounty Program Information
    platform: formData.platform,
    login_email: formData.login_email,
    researcher_email: formData.researcher_email,
    // Scope Configuration
    in_scope: (Array.isArray(formData.in_scope)
      ? formData.in_scope
      : formData.in_scope
        ? [formData.in_scope]
        : []) as string[],
    out_of_scope: (Array.isArray(formData.out_of_scope)
      ? formData.out_of_scope
      : formData.out_of_scope
        ? [formData.out_of_scope]
        : []) as string[],
    custom_headers: (Array.isArray(formData.custom_headers)
      ? formData.custom_headers
      : formData.custom_headers
        ? [formData.custom_headers]
        : []) as CustomHeader[],
    additional_info: (Array.isArray(formData.additional_info)
      ? formData.additional_info
      : formData.additional_info
        ? [formData.additional_info]
        : []) as string[],
    notes: (Array.isArray(formData.notes)
      ? formData.notes
      : formData.notes
        ? [formData.notes]
        : []) as string[],
    // Rate Limiting Configuration
    rate_limits: {
      requests_per_second: formData.rate_limits?.requests_per_second ?? 0,
      requests_per_minute: formData.rate_limits?.requests_per_minute ?? 0,
      requests_per_hour: formData.rate_limits?.requests_per_hour ?? 0,
    },
  };

  try {
    const response = await axios.post(`${API_URL}/api/targets/`, backendData);
    return response.data;
  } catch (error) {
    console.error('Failed to create target:', error);
    throw error;
  }
};

export const getTargets = async (filters?: TargetFilters) => {
  try {
    const response = await axios.get(`${API_URL}/api/targets/`, { params: filters });
    return response.data;
  } catch (error) {
    console.error('Failed to fetch targets:', error);
    throw error;
  }
};

export const getTarget = async (id: string) => {
  try {
    const response = await axios.get(`${API_URL}/api/targets/${id}`);
    return response.data;
  } catch (error) {
    console.error('Failed to fetch target:', error);
    throw error;
  }
};

export const updateTarget = async (id: string, data: Partial<TargetCreateRequest>) => {
  try {
    const response = await axios.put(`${API_URL}/api/targets/${id}`, data);
    return response.data;
  } catch (error) {
    console.error('Failed to update target:', error);
    throw error;
  }
};

export const deleteTarget = async (id: string) => {
  try {
    const response = await axios.delete(`${API_URL}/api/targets/${id}`);
    return response.data;
  } catch (error) {
    console.error('Failed to delete target:', error);
    throw error;
  }
}; 