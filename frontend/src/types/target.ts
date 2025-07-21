export enum BugBountyPlatform {
  HACKERONE = "hackerone",
  BUGCROWD = "bugcrowd",
  CUSTOM = "custom",
}

export interface TargetProfile {
  target: string;
  domain: string;
  is_primary: boolean;
  platform?: BugBountyPlatform;
  platform_email?: string;
  researcher_email?: string;
}

export interface TargetCreateRequest extends TargetProfile {
  in_scope: string[];
  out_of_scope: string[];
  rules_to_follow: string[];
  rules_to_avoid: string[];
  rate_limit_requests?: number;
  rate_limit_seconds?: number;
} 