export enum BugBountyPlatform {
  HACKERONE = "HACKERONE",
  BUGCROWD = "BUGCROWD",
  INTIGRITI = "INTIGRITI",
  YESWEHACK = "YESWEHACK",
  CUSTOM = "CUSTOM",
}

export enum TargetScope {
  TARGET = "TARGET",
  DOMAIN = "DOMAIN",
  IN_SCOPE = "IN_SCOPE",
  OUT_OF_SCOPE = "OUT_OF_SCOPE",
  RATE_LIMITS = "RATE_LIMITS",
  CUSTOM_HEADER = "CUSTOM_HEADER",
  ADDITIONAL_INFO = "ADDITIONAL_INFO",
  NOTES = "NOTES"
}

export enum TargetStatus {
  ACTIVE = "ACTIVE",
  INACTIVE = "INACTIVE",
  ARCHIVED = "ARCHIVED",
}

export interface RateLimitConfig {
  requests_per_second: number;
  requests_per_minute: number;
  requests_per_hour: number;
}

export interface CustomHeader {
  name: string;
  value: string;
}

export interface TargetProfile {
  name: string;
  scope: TargetScope;
  status: TargetStatus;
  platform: BugBountyPlatform;
  login_email?: string;
  researcher_email?: string;
  in_scope?: string[];
  out_of_scope?: string[];
  rate_limits?: RateLimitConfig;
  custom_headers?: CustomHeader[];
  additional_info?: string[];
  notes?: string[];
}

export interface TargetCreateRequest {
  target?: string;
  // Basic target information (legacy and new)
  name?: string;
  domain?: string;
  scope?: TargetScope;
  is_primary?: boolean;
  user_id?: string;
  status?: TargetStatus;

  // Bug Bounty Program Information
  platform?: BugBountyPlatform;
  login_email?: string;
  researcher_email?: string;

  // Scope Configuration
  in_scope?: string[];
  out_of_scope?: string[];
  
  // Rate Limiting Configuration
  rate_limits?: RateLimitConfig;
  rate_limit_requests?: number;
  rate_limit_seconds?: number;

  // Custom Headers
  custom_headers?: CustomHeader[];

  // Additional Configuration
  additional_info?: string[];
  notes?: string[];
}

export interface TargetUpdateRequest {
  target?: string;
  // Basic target information
  name?: string;
  domain?: string;
  scope?: TargetScope;
  status?: TargetStatus;
  is_primary?: boolean;
  
  // Bug Bounty Program Information
  platform?: BugBountyPlatform;
  login_email?: string;
  researcher_email?: string;

  // Scope Configuration
  in_scope?: string[];
  out_of_scope?: string[];

  // Rate Limiting Configuration
  rate_limits?: RateLimitConfig;
  rate_limit_requests?: number;
  rate_limit_seconds?: number;
  
  // Custom Headers
  custom_headers?: CustomHeader[];
  
  // Additional Configuration
  additional_info?: string[];
  notes?: string[];
}

export interface TargetResponse {
  target?: string;
  id: string;
  name: string;
  domain?: string;
  scope: TargetScope;
  status: TargetStatus;
  is_primary: boolean;
  user_id?: string;
  created_at: string;
  updated_at: string;
  is_active: boolean;
  display_name: string;
  
  // Bug Bounty Program Information
  platform?: BugBountyPlatform;
  login_email?: string;
  researcher_email?: string;
  
  // Scope Configuration
  in_scope?: string[];
  out_of_scope?: string[];
  
  // Rate Limiting Configuration
  rate_limits?: RateLimitConfig;
  rate_limit_requests?: number;
  rate_limit_seconds?: number;
  
  // Custom Headers
  custom_headers?: CustomHeader[];
  
  // Additional Configuration
  additional_info?: string[];
  notes?: string[];
  
}

export interface TargetListResponse {
  items: TargetResponse[];
  total: number;
  page: number;
  size: number;
  pages: number;
}

export interface TargetFilters {
  scope?: TargetScope;
  status?: TargetStatus;
  is_primary?: boolean;
  user_id?: string;
  search?: string;
}

export interface TargetStatistics {
  total_targets: number;
  active_targets: number;
  primary_targets: number;
  inactive_targets: number;
} 