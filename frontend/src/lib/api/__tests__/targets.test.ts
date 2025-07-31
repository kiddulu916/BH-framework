import { describe, it, expect, vi, beforeEach } from 'vitest';
import axios from 'axios';
import { createTarget, getTargets, getTarget, updateTarget, deleteTarget } from '../targets';
import { BugBountyPlatform } from '@/types/target';

// Mock axios
vi.mock('axios');
const mockAxios = vi.mocked(axios);

describe('Targets API Client', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('createTarget', () => {
    it('successfully creates a target with new fields', async () => {
      const mockResponse = {
        data: {
          success: true,
          message: 'Target created successfully',
          data: { id: '123', target: 'Test Company' },
        },
      };
      mockAxios.post.mockResolvedValue(mockResponse);

      const formData = {
        target: 'Test Company',
        domain: 'example.com',
        is_primary: true,
        platform: BugBountyPlatform.HACKERONE,
        login_email: 'test@example.com',
        researcher_email: 'researcher@example.com',
        in_scope: ['https://example.com'],
        out_of_scope: ['https://excluded.example.com'],
        additional_info: ['Follow responsible disclosure'],
        notes: ['No DDoS attacks'],
        rate_limit_requests: 10,
        rate_limit_seconds: 60,
        custom_headers: [{ name: 'Authorization', value: 'Bearer token' }],
      };

      const result = await createTarget(formData);

      expect(mockAxios.post).toHaveBeenCalledWith(
        'http://localhost:8000/api/targets/',
        expect.objectContaining({
          target: 'Test Company',
          domain: 'example.com',
          is_primary: true,
          platform: BugBountyPlatform.HACKERONE,
          login_email: 'test@example.com',
          researcher_email: 'researcher@example.com',
          in_scope: ['https://example.com'],
          out_of_scope: ['https://excluded.example.com'],
          additional_info: ['Follow responsible disclosure'],
          notes: ['No DDoS attacks'],
          rate_limit_requests: 10,
          rate_limit_seconds: 60,
          custom_headers: [{ name: 'Authorization', value: 'Bearer token' }],
        })
      );

      expect(result).toEqual(mockResponse.data);
    });

    it('handles API errors correctly', async () => {
      const errorMessage = 'API Error';
      mockAxios.post.mockRejectedValue(new Error(errorMessage));

      const formData = {
        target: 'Test Company',
        domain: 'example.com',
      };

      await expect(createTarget(formData)).rejects.toThrow(errorMessage);
    });

    it('handles empty arrays correctly', async () => {
      const mockResponse = {
        data: {
          success: true,
          message: 'Target created successfully',
          data: { id: '123', target: 'Test Company' },
        },
      };
      mockAxios.post.mockResolvedValue(mockResponse);

      const formData = {
        target: 'Test Company',
        domain: 'example.com',
        in_scope: [],
        out_of_scope: [],
        additional_info: [],
        notes: [],
        custom_headers: [],
      };

      const result = await createTarget(formData);

      expect(mockAxios.post).toHaveBeenCalledWith(
        'http://localhost:8000/api/targets/',
        expect.objectContaining({
          target: 'Test Company',
          domain: 'example.com',
          in_scope: [],
          out_of_scope: [],
          additional_info: [],
          notes: [],
          custom_headers: [],
        })
      );

      expect(result).toEqual(mockResponse.data);
    });

    it('handles undefined values correctly', async () => {
      const mockResponse = {
        data: {
          success: true,
          message: 'Target created successfully',
          data: { id: '123', target: 'Test Company' },
        },
      };
      mockAxios.post.mockResolvedValue(mockResponse);

      const formData = {
        target: undefined,
        domain: 'example.com',
        additional_info: undefined,
        notes: undefined,
      };

      const result = await createTarget(formData);

      expect(mockAxios.post).toHaveBeenCalledWith(
        'http://localhost:8000/api/targets/',
        expect.objectContaining({
          target: undefined,
          domain: 'example.com',
          additional_info: [],
          notes: [],
        })
      );

      expect(result).toEqual(mockResponse.data);
    });

    it('handles missing rate limits correctly', async () => {
      const mockResponse = {
        data: {
          success: true,
          message: 'Target created successfully',
          data: { id: '123', target: 'Test Company' },
        },
      };
      mockAxios.post.mockResolvedValue(mockResponse);

      const formData = {
        target: 'Test Company',
        domain: 'example.com',
        // No rate limit fields
      };

      const result = await createTarget(formData);

      expect(mockAxios.post).toHaveBeenCalledWith(
        'http://localhost:8000/api/targets/',
        expect.objectContaining({
          target: 'Test Company',
          domain: 'example.com',
          rate_limit_requests: undefined,
          rate_limit_seconds: undefined,
        })
      );

      expect(result).toEqual(mockResponse.data);
    });
  });

  describe('getTargets', () => {
    it('successfully fetches targets with filters', async () => {
      const mockResponse = {
        data: {
          success: true,
          message: 'Targets retrieved successfully',
          data: {
            items: [
              { id: '1', target: 'Company A', domain: 'companya.com' },
              { id: '2', target: 'Company B', domain: 'companyb.com' },
            ],
            total: 2,
            page: 1,
            per_page: 10,
          },
        },
      };
      mockAxios.get.mockResolvedValue(mockResponse);

      const filters = {
        target: 'Company',
        domain: 'companya.com',
        platform: BugBountyPlatform.HACKERONE,
      };

      const result = await getTargets(filters);

      expect(mockAxios.get).toHaveBeenCalledWith(
        'http://localhost:8000/api/targets/',
        { params: filters }
      );

      expect(result).toEqual(mockResponse.data);
    });

    it('successfully fetches targets without filters', async () => {
      const mockResponse = {
        data: {
          success: true,
          message: 'Targets retrieved successfully',
          data: {
            items: [
              { id: '1', target: 'Company A', domain: 'companya.com' },
            ],
            total: 1,
            page: 1,
            per_page: 10,
          },
        },
      };
      mockAxios.get.mockResolvedValue(mockResponse);

      const result = await getTargets();

      expect(mockAxios.get).toHaveBeenCalledWith(
        'http://localhost:8000/api/targets/',
        { params: undefined }
      );

      expect(result).toEqual(mockResponse.data);
    });

    it('handles API errors correctly', async () => {
      const errorMessage = 'API Error';
      mockAxios.get.mockRejectedValue(new Error(errorMessage));

      await expect(getTargets()).rejects.toThrow(errorMessage);
    });
  });

  describe('getTarget', () => {
    it('successfully fetches a single target', async () => {
      const mockResponse = {
        data: {
          success: true,
          message: 'Target retrieved successfully',
          data: { id: '123', target: 'Test Company', domain: 'example.com' },
        },
      };
      mockAxios.get.mockResolvedValue(mockResponse);

      const result = await getTarget('123');

      expect(mockAxios.get).toHaveBeenCalledWith(
        'http://localhost:8000/api/targets/123'
      );

      expect(result).toEqual(mockResponse.data);
    });

    it('handles API errors correctly', async () => {
      const errorMessage = 'API Error';
      mockAxios.get.mockRejectedValue(new Error(errorMessage));

      await expect(getTarget('123')).rejects.toThrow(errorMessage);
    });
  });

  describe('updateTarget', () => {
    it('successfully updates a target', async () => {
      const mockResponse = {
        data: {
          success: true,
          message: 'Target updated successfully',
          data: { id: '123', target: 'Updated Company', domain: 'updated.com' },
        },
      };
      mockAxios.put.mockResolvedValue(mockResponse);

      const updateData = {
        target: 'Updated Company',
        domain: 'updated.com',
      };

      const result = await updateTarget('123', updateData);

      expect(mockAxios.put).toHaveBeenCalledWith(
        'http://localhost:8000/api/targets/123',
        updateData
      );

      expect(result).toEqual(mockResponse.data);
    });

    it('handles API errors correctly', async () => {
      const errorMessage = 'API Error';
      mockAxios.put.mockRejectedValue(new Error(errorMessage));

      await expect(updateTarget('123', { target: 'Test' })).rejects.toThrow(errorMessage);
    });
  });

  describe('deleteTarget', () => {
    it('successfully deletes a target', async () => {
      const mockResponse = {
        data: {
          success: true,
          message: 'Target deleted successfully',
        },
      };
      mockAxios.delete.mockResolvedValue(mockResponse);

      const result = await deleteTarget('123');

      expect(mockAxios.delete).toHaveBeenCalledWith(
        'http://localhost:8000/api/targets/123'
      );

      expect(result).toEqual(mockResponse.data);
    });

    it('handles API errors correctly', async () => {
      const errorMessage = 'API Error';
      mockAxios.delete.mockRejectedValue(new Error(errorMessage));

      await expect(deleteTarget('123')).rejects.toThrow(errorMessage);
    });
  });

  describe('Environment Configuration', () => {
    it('uses custom API URL when environment variable is set', async () => {
      const originalEnv = process.env.NEXT_PUBLIC_API_URL;
      process.env.NEXT_PUBLIC_API_URL = 'https://custom-api.com';

      // The API module reads the env var at import time, so we need to import it *after* we change the env.
      vi.resetModules();
      const { createTarget: createTargetFresh } = await import('../targets');

      const mockResponse = {
        data: {
          success: true,
          message: 'Target created successfully',
          data: { id: '123', target: 'Test Company' },
        },
      };
      mockAxios.post.mockResolvedValue(mockResponse);

      const formData = {
        target: 'Test Company',
        domain: 'example.com',
      };

      await createTargetFresh(formData);

      expect(mockAxios.post).toHaveBeenCalledWith(
        'https://custom-api.com/api/targets/',
        expect.any(Object)
      );

      // Restore original environment
      if (originalEnv) {
        process.env.NEXT_PUBLIC_API_URL = originalEnv;
      } else {
        delete process.env.NEXT_PUBLIC_API_URL;
      }
    });

    it('falls back to default API URL when environment variable is not set', async () => {
      const originalEnv = process.env.NEXT_PUBLIC_API_URL;
      delete process.env.NEXT_PUBLIC_API_URL;

      const mockResponse = {
        data: {
          success: true,
          message: 'Target created successfully',
          data: { id: '123', target: 'Test Company' },
        },
      };
      mockAxios.post.mockResolvedValue(mockResponse);

      const formData = {
        target: 'Test Company',
        domain: 'example.com',
      };

      await createTarget(formData);

      expect(mockAxios.post).toHaveBeenCalledWith(
        'http://localhost:8000/api/targets/',
        expect.any(Object)
      );

      // Restore original environment
      if (originalEnv) {
        process.env.NEXT_PUBLIC_API_URL = originalEnv;
      }
    });
  });
}); 