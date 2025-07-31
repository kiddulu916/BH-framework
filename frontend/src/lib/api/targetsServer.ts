import 'server-only';

interface TargetSummary {
  id: string;
  target: string;
  domain: string;
  is_primary: boolean;
}

interface TargetsResponse {
  success: boolean;
  data: {
    items: TargetSummary[];
  };
}

// On the server we talk directly to the backend container via service name
const API_URL = process.env.INTERNAL_API_URL || process.env.NEXT_PUBLIC_API_URL || 'http://backend:8000';
const JWT = process.env.NEXT_PUBLIC_JWT_TOKEN || '';

export async function fetchTargetsServer(): Promise<TargetSummary[]> {
  const res = await fetch(`${API_URL}/api/targets/`, {
    headers: JWT ? { Authorization: `Bearer ${JWT}` } : {},
    cache: 'no-store',
  });
  if (!res.ok) return [];
  const json = (await res.json()) as TargetsResponse;
  return json?.data?.items ?? [];
} 