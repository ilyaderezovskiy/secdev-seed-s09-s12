from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
from starlette.types import ASGIApp
from html import escape

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        
        # Security headers
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), location=()"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # Cache control for sensitive endpoints
        if request.url.path in ["/", "/echo", "/?q="]:
            response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
        
        return response

app = FastAPI()
templates = Jinja2Templates(directory="app/templates")

app.add_middleware(SecurityHeadersMiddleware)

@app.get("/", response_class=HTMLResponse)
def index(request: Request, q: str = ""):
    # намеренно простая страница, отражающая ввод
    # (для DAST это даст находки типа отражений/хедеров)
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "q": q}
    )

@app.get("/healthz")
def healthz():
    return PlainTextResponse("OK")

@app.get("/echo", response_class=HTMLResponse)
def echo(x: str = ""):
    safe_x = escape(x)  # Валидация и санитизация
    return HTMLResponse(f"<h1>ECHO</h1><div>you said: {safe_x}</div>")
