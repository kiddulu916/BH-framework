import { describe, it, expect, vi, beforeEach } from 'vitest';
import axios from 'axios';
import { createTarget, getTargets, getTarget, updateTarget, deleteTarget } from '../targets';
import { BugBountyPlatform, TargetScope } from '@/types/target';

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
          data: { id: '123', name: 'Test Company' },
        },
      };
      mockAxios.post.mockResolvedValue(mockResponse);

      const formData = {
        name: 'Test Company',
        domain: 'example.com',
        is_primary: true,
        platform: BugBountyPlatform.HACKERONE,
        login_email: 'test@example.com',
        researcher_email: 'researcher@example.com',
        in_scope: ['https://example.com'],
        out_of_scope: ['https://excluded.example.com'],
        additional_info: ['Follow responsible disclosure'],
        notes: ['No DDoS attacks'],
        rate_limits: {
          requests_per_minute: 10,
          requests_per_second: 0,
          requests_per_hour: 0,
        },
        custom_headers: [{ name: 'Authorization', value: 'Bearer token' }],
      };

      const result = await createTarget(formData);

      expect(mockAxios.post).toHaveBeenCalledWith(
        'http://localhost:8000/api/targets/',
        expect.objectContaining({
          name: 'Test Company',
          domain: 'example.com',
          is_primary: true,
          platform: BugBountyPlatform.HACKERONE,
          login_email: 'test@example.com',
          researcher_email: 'researcher@example.com',
          in_scope: ['https://example.com'],
          out_of_scope: ['https://excluded.example.com'],
          additional_info: ['Follow responsible disclosure'],
          notes: ['No DDoS attacks'],
          rate_limits: {
            requests_per_minute: 10,
            requests_per_second: 0,
            requests_per_hour: 0,
          },
          custom_headers: [{ name: 'Authorization', value: 'Bearer token' }],
        })
      );

      expect(result).toEqual(mockResponse.data);
    });

    it('handles API errors correctly', async () => {
      const errorMessage = 'API Error';
      mockAxios.post.mockRejectedValue(new Error(errorMessage));

      const formData = {
        name: 'Test Company',
        domain: 'example.com',
      };

      await expect(createTarget(formData)).rejects.toThrow(errorMessage);
    });

    it('handles empty arrays correctly', async () => {
      const mockResponse = {
        data: {
          success: true,
          message: 'Target created successfully',
          data: { id: '123', name: 'Test Company' },
        },
      };
      mockAxios.post.mockResolvedValue(mockResponse);

      const formData = {
        name: 'Test Company',
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
          data: { id: '123', name: 'Test Company' },
        },
      };
      mockAxios.post.mockResolvedValue(mockResponse);

      const formData = {
        name: 'Test Company',
        domain: 'example.com',
        additional_info: undefined,
        notes: undefined,
      };

      const result = await createTarget(formData);

      expect(mockAxios.post).toHaveBeenCalledWith(
        'http://localhost:8000/api/targets/',
        expect.objectContaining({
          additional_info: undefined,
          notes: undefined,
        })
      );

      expect(result).toEqual(mockResponse.data);
    });

    it('handles missing rate limits correctly', async () => {
      const mockResponse = {
        data: {
          success: true,
          message: 'Target created successfully',
          data: { id: '123', name: 'Test Company' },
        },
      };
      mockAxios.post.mockResolvedValue(mockResponse);

      const formData = {
        name: 'Test Company',
        domain: 'example.com',
        // No rate limit fields
      };

      const result = await createTarget(formData);

      expect(mockAxios.post).toHaveBeenCalledWith(
        'http://localhost:8000/api/targets/',
        expect.objectContaining({
          rate_limits: {
            requests_per_second: 0,
            requests_per_minute: 0,
            requests_per_hour: 0,
          },
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
              { id: '123', name: 'Test Company 1' },
              { id: '456', name: 'Test Company 2' },
            ],
            total: 2,
            page: 1,
            size: 10,
            pages: 1,
          },
        },
      };
      mockAxios.get.mockResolvedValue(mockResponse);

      const filters = {
        scope: TargetScope.DOMAIN,
        is_primary: true,
        search: 'test',
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
            items: [],
            total: 0,
            page: 1,
            size: 10,
            pages: 0,
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
          data: {
            id: '123',
            name: 'Test Company',
            value: 'example.com',
            scope: 'DOMAIN',
          },
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
          data: {
            id: '123',
            name: 'Updated Company',
            value: 'updated-example.com',
          },
        },
      };
      mockAxios.put.mockResolvedValue(mockResponse);

      const updateData = {
        name: 'Updated Company',
        value: 'updated-example.com',
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

      const updateData = {
        name: 'Updated Company',
      };

      await expect(updateTarget('123', updateData)).rejects.toThrow(errorMessage);
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

      const mockResponse = {
        data: {
          success: true,
          message: 'Target created successfully',
          data: { id: '123', name: 'Test Company' },
        },
      };
      mockAxios.post.mockResolvedValue(mockResponse);

      const formData = {
        name: 'Test Company',
        domain: 'example.com',
      };

      await createTarget(formData);

      expect(mockAxios.post).toHaveBeenCalledWith(
        'https://custom-api.com/api/targets/',
        expect.any(Object)
      );

      // Restore original environment
      process.env.NEXT_PUBLIC_API_URL = originalEnv;
    });

    it('falls back to default API URL when environment variable is not set', async () => {
      const originalEnv = process.env.NEXT_PUBLIC_API_URL;
      delete process.env.NEXT_PUBLIC_API_URL;

      const mockResponse = {
        data: {
          success: true,
          message: 'Target created successfully',
          data: { id: '123', name: 'Test Company' },
        },
      };
      mockAxios.post.mockResolvedValue(mockResponse);

      const formData = {
        name: 'Test Company',
        domain: 'example.com',
      };

      await createTarget(formData);

      expect(mockAxios.post).toHaveBeenCalledWith(
        'http://localhost:8000/api/targets/',
        expect.any(Object)
      );

      // Restore original environment
      process.env.NEXT_PUBLIC_API_URL = originalEnv;
    });
  });
}); 