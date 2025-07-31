export enum BugBountyPlatform {
  HACKERONE = "HACKERONE",
  BUGCROWD = "BUGCROWD",
  INTIGRITI = "INTIGRITI",
  YESWEHACK = "YESWEHACK",
  CUSTOM = "CUSTOM",
}

export enum TargetStatus {
  ACTIVE = "ACTIVE",
  INACTIVE = "INACTIVE",
  ARCHIVED = "ARCHIVED",
}

export interface CustomHeader {
  name: string;
  value: string;
}

export interface TargetProfile {
  id?: string;
  target: string;
  domain?: string;
  is_primary?: boolean;
  status: TargetStatus;
  platform: BugBountyPlatform;
  login_email?: string;
  researcher_email?: string;
  in_scope?: string[];
  out_of_scope?: string[];
  custom_headers?: CustomHeader[];
  additional_info?: string[];
  notes?: string[];
}

export interface TargetCreateRequest {
  // Basic target information
  id?: string;
  target?: string;
  domain?: string;
  is_primary?: boolean;
  status?: TargetStatus;

  // Bug Bounty Program Information
  platform?: BugBountyPlatform;
  login_email?: string;
  researcher_email?: string;

  // Scope Configuration
  in_scope?: string[];
  out_of_scope?: string[];
  
  // Rate Limiting Configuration
  rate_limit_requests?: number;
  rate_limit_seconds?: number;

  // Custom Headers
  custom_headers?: CustomHeader[];

  // Additional Configuration
  additional_info?: string[];
  notes?: string[];
}

export interface TargetUpdateRequest {
  // Basic target information
  id?: string;
  target?: string;
  domain?: string;
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
  rate_limit_requests?: number;
  rate_limit_seconds?: number;
  
  // Custom Headers
  custom_headers?: CustomHeader[];
  
  // Additional Configuration
  additional_info?: string[];
  notes?: string[];
}

export interface TargetResponse {
  id: string;
  target: string;
  domain?: string;
  status: TargetStatus;
  is_primary: boolean;
  created_at: string;
  updated_at: string;
  
  // Bug Bounty Program Information
  platform?: BugBountyPlatform;
  login_email?: string;
  researcher_email?: string;
  
  // Scope Configuration
  in_scope?: string[];
  out_of_scope?: string[];

  // Rate Limiting Configuration
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
  id?: string;
  status?: TargetStatus;
  is_primary?: boolean;
  search?: string;
}

export interface TargetStatistics {
  total_targets: number;
  active_targets: number;
  primary_targets: number;
  inactive_targets: number;
} 