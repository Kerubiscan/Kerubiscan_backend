from fastapi import Request
from fastapi.responses import JSONResponse

class KimiaException(Exception):
    def __init__(self, message: str, status_code: int = 400):
        self.message = message
        self.status_code = status_code

async def kimia_exception_handler(request: Request, exc: KimiaException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"message": exc.message},
    )
