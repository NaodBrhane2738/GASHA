/**
 * ==============================================================================
 * FILE: packages/contracts/api/index.ts
 * ROLE / OWNERSHIP: Cross-Team Shared Contracts
 * OBJECTIVE: Define standard HTTP request/response envelopes, errors, and pagination.
 * TOOLS & LIBRARIES: TypeScript 5.x
 * KEY FEATURES / FUNCTIONS TO IMPLEMENT:
 *   - ApiResponse<T>: Standard JSON response wrapper.
 *   - ApiError: Standardized error format with error codes.
 *   - PaginationParams & PaginatedResult<T>: List querying and pagination contracts.
 * EXPECTED RESULTS / BEHAVIOR:
 *   - Uniform API responses across all FastAPI endpoints consumed by Next.js frontend.
 * ==============================================================================
 */

export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: ApiError;
  timestamp: string;
}

export interface ApiError {
  code: string;
  message: string;
  details?: Record<string, unknown>;
}

export interface PaginationParams {
  page?: number;
  limit?: number;
}

export interface PaginatedResult<T> {
  items: T[];
  total: number;
  page: number;
  limit: number;
  totalPages: number;
}

export interface EnvironmentFilterParams extends PaginationParams {
  environmentId?: string;
  severity?: string;
  status?: string;
}
