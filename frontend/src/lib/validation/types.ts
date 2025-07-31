export interface ValidationError {
  field: string;
  message: string;
}

export interface ValidationResult {
  isValid: boolean;
  errors: ValidationError[];
}

export interface CustomHeader {
  name: string;
  value: string;
}

export interface TargetCreateRequest {
  target?: string;
  domain?: string;
  is_primary?: boolean;
  platform?: string;
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