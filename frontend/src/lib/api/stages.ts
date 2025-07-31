import axios from 'axios';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

// Types for stage operations
export interface StageResult {
  id: string;
  target_id: string;
  stage_name: string;
  tool_name: string;
  data: any;
  raw_output?: string;
  created_at: string;
  updated_at: string;
}

export interface StageStatus {
  stage_name: string;
  target_id: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  progress: number;
  total_tools: number;
  completed_tools: number;
  failed_tools: number;
  start_time?: string;
  end_time?: string;
  error?: string;
}

export interface StageExecutionRequest {
  target_id: string;
  stage_name: string;
  tools?: string[];
  options?: Record<string, any>;
}

export interface RecursiveReconResult {
  success: boolean;
  main_target: string;
  target_id: string;
  total_subdomains: number;
  subtargets_created: number;
  passive_recon_successful: number;
  active_recon_successful: number;
  passive_recon_success_rate: number;
  active_recon_success_rate: number;
  subdomains: string[];
  subtarget_results: Array<{
    subdomain: string;
    subtarget_id: string;
    passive_recon_success: boolean;
    active_recon_success: boolean;
    error?: string;
  }>;
  timestamp: string;
}

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

// Passive Reconnaissance API functions
export const getPassiveReconResults = async (targetId: string): Promise<StageResult[]> => {
  try {
    const response = await axios.get(`${API_URL}/api/results/passive-recon/${targetId}`, {
      headers: getAuthHeaders(),
    });
    return response.data.data || [];
  } catch (error) {
    console.error('Failed to fetch passive recon results:', error);
    throw error;
  }
};

export const startPassiveRecon = async (request: StageExecutionRequest): Promise<any> => {
  try {
    const response = await axios.post(`${API_URL}/api/stages/passive-recon/start`, request, {
      headers: {
        'Content-Type': 'application/json',
        ...getAuthHeaders(),
      },
    });
    return response.data;
  } catch (error) {
    console.error('Failed to start passive recon:', error);
    throw error;
  }
};

export const getPassiveReconStatus = async (targetId: string): Promise<StageStatus> => {
  try {
    const response = await axios.get(`${API_URL}/api/stages/passive-recon/status/${targetId}`, {
      headers: getAuthHeaders(),
    });
    return response.data.data;
  } catch (error) {
    console.error('Failed to fetch passive recon status:', error);
    throw error;
  }
};

// Active Reconnaissance API functions
export const getActiveReconResults = async (targetId: string): Promise<StageResult[]> => {
  try {
    const response = await axios.get(`${API_URL}/api/results/active-recon/${targetId}`, {
      headers: getAuthHeaders(),
    });
    return response.data.data || [];
  } catch (error) {
    console.error('Failed to fetch active recon results:', error);
    throw error;
  }
};

export const startActiveRecon = async (request: StageExecutionRequest): Promise<any> => {
  try {
    const response = await axios.post(`${API_URL}/api/stages/active-recon/start`, request, {
      headers: {
        'Content-Type': 'application/json',
        ...getAuthHeaders(),
      },
    });
    return response.data;
  } catch (error) {
    console.error('Failed to start active recon:', error);
    throw error;
  }
};

export const getActiveReconStatus = async (targetId: string): Promise<StageStatus> => {
  try {
    const response = await axios.get(`${API_URL}/api/stages/active-recon/status/${targetId}`, {
      headers: getAuthHeaders(),
    });
    return response.data.data;
  } catch (error) {
    console.error('Failed to fetch active recon status:', error);
    throw error;
  }
};

// Recursive Reconnaissance API functions
export const getRecursiveReconResults = async (targetId: string): Promise<RecursiveReconResult | null> => {
  try {
    const response = await axios.get(`${API_URL}/api/results/recursive-recon/${targetId}`, {
      headers: getAuthHeaders(),
    });
    return response.data.data;
  } catch (error) {
    console.error('Failed to fetch recursive recon results:', error);
    return null;
  }
};

// Generic stage functions
export const getStageResults = async (targetId: string, stageName: string): Promise<StageResult[]> => {
  try {
    const response = await axios.get(`${API_URL}/api/results/${stageName}/${targetId}`, {
      headers: getAuthHeaders(),
    });
    return response.data.data || [];
  } catch (error) {
    console.error(`Failed to fetch ${stageName} results:`, error);
    throw error;
  }
};

export const getStageStatus = async (targetId: string, stageName: string): Promise<StageStatus> => {
  try {
    const response = await axios.get(`${API_URL}/api/stages/${stageName}/status/${targetId}`, {
      headers: getAuthHeaders(),
    });
    return response.data.data;
  } catch (error) {
    console.error(`Failed to fetch ${stageName} status:`, error);
    throw error;
  }
};

export const startStage = async (request: StageExecutionRequest): Promise<any> => {
  try {
    const response = await axios.post(`${API_URL}/api/stages/${request.stage_name}/start`, request, {
      headers: {
        'Content-Type': 'application/json',
        ...getAuthHeaders(),
      },
    });
    return response.data;
  } catch (error) {
    console.error(`Failed to start ${request.stage_name}:`, error);
    throw error;
  }
};

// Utility functions for stage management
export const getStageSummary = async (targetId: string) => {
  try {
    const [passiveResults, activeResults, recursiveResults] = await Promise.allSettled([
      getPassiveReconResults(targetId),
      getActiveReconResults(targetId),
      getRecursiveReconResults(targetId),
    ]);

    return {
      passive_recon: {
        results: passiveResults.status === 'fulfilled' ? passiveResults.value : [],
        count: passiveResults.status === 'fulfilled' ? passiveResults.value.length : 0,
      },
      active_recon: {
        results: activeResults.status === 'fulfilled' ? activeResults.value : [],
        count: activeResults.status === 'fulfilled' ? activeResults.value.length : 0,
      },
      recursive_recon: {
        results: recursiveResults.status === 'fulfilled' ? recursiveResults.value : null,
        has_data: recursiveResults.status === 'fulfilled' && recursiveResults.value !== null,
      },
    };
  } catch (error) {
    console.error('Failed to get stage summary:', error);
    throw error;
  }
};

// WebSocket connection for real-time updates
export const createStageWebSocket = (targetId: string, stageName: string) => {
  const wsUrl = `${API_URL.replace('http', 'ws')}/ws/stages/${stageName}/${targetId}`;
  return new WebSocket(wsUrl);
}; 