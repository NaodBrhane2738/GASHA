"""
==============================================================================
FILE: apps/api/app/core/errors.py
ROLE / OWNERSHIP: Backend Engineers
OBJECTIVE: Custom exception classes and global error handlers for uniform API error responses.
TOOLS & LIBRARIES: FastAPI, HTTPException, RequestValidationError
KEY FEATURES / FUNCTIONS TO IMPLEMENT:
  - GashaException(message, code, status_code)
  - NotFoundException, ValidationException, UnauthorizedException, ResponseExecutionError
EXPECTED RESULTS / BEHAVIOR:
  - Ensures all errors returned to clients match the ApiResponse error envelope from @gasha/contracts.
==============================================================================
"""

from fastapi import HTTPException, status

class GashaException(HTTPException):
    def __init__(self, message: str, code: str = "INTERNAL_ERROR", status_code: int = 500):
        super().__init__(status_code=status_code, detail={"code": code, "message": message})
        self.code = code
        self.message = message

class EntityNotFoundException(GashaException):
    def __init__(self, entity_name: str, entity_id: str):
        super().__init__(
            message=f"{entity_name} with id '{entity_id}' not found",
            code="NOT_FOUND",
            status_code=status.HTTP_404_NOT_FOUND
        )
