import axios from 'axios';
import { TargetCreateRequest, TargetFilters, BugBountyPlatform, CustomHeader } from '@/types/target';
// Interface for form data that includes legacy fields for backward compatibility
interface TargetFormData {
  // Basic target information
  id?: string;
  target?: string; // Legacy field
  domain?: string; // Legacy field
  is_primary?: boolean;
  
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
  rate_limit_requests?: number; // Legacy field
  rate_limit_seconds?: number; // Legacy field
  
  // Custom Headers
  custom_headers?: CustomHeader[];
}

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

function getAuthHeaders() {
  // Try from env for server-side calls
  const envToken = process.env.NEXT_PUBLIC_JWT_TOKEN;
  let token = envToken;

  if (typeof window !== 'undefined') {
    // Client-side: prefer localStorage first
    token = localStorage.getItem('BACKEND_JWT_TOKEN') || envToken || '';
    // Fallback to cookie if present
    if (!token) {
      const match = document.cookie.match(/(?:^|; )BACKEND_JWT_TOKEN=([^;]*)/);
      token = match ? decodeURIComponent(match[1]) : '';
    }
  }

  return token ? { Authorization: `Bearer ${token}` } : {};
}

export const createTarget = async (formData: TargetFormData) => {
  // Send data directly as the backend schema now supports frontend field names
  const backendData: TargetCreateRequest = {
    // Basic target information
    id: crypto.randomUUID(),
    target: formData.target,
    domain: formData.domain,
    is_primary: formData.is_primary || false,
    
    // Bug Bounty Program Information
    platform: formData.platform,
    login_email: formData.login_email,
    researcher_email: formData.researcher_email,
    
    // Scope Configuration
    in_scope: Array.isArray(formData.in_scope) ? formData.in_scope : formData.in_scope ? [formData.in_scope] : [],
    out_of_scope: Array.isArray(formData.out_of_scope) ? formData.out_of_scope : formData.out_of_scope ? [formData.out_of_scope] : [],
    
    // Custom Headers
    custom_headers: Array.isArray(formData.custom_headers) ? formData.custom_headers : formData.custom_headers ? [formData.custom_headers] : [],
    
    // Additional Configuration
    additional_info: Array.isArray(formData.additional_info) ? formData.additional_info : formData.additional_info ? [formData.additional_info] : [],
    notes: Array.isArray(formData.notes) ? formData.notes : formData.notes ? [formData.notes] : [],
    
    // Rate Limiting Configuration
    rate_limit_requests: formData.rate_limit_requests,
    rate_limit_seconds: formData.rate_limit_seconds,
  };

  try {
    const response = await axios.post(`${API_URL}/api/targets/`, backendData, {
      headers: {
        'Content-Type': 'application/json',
        ...getAuthHeaders(),
      },
      withCredentials: true,
    });
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