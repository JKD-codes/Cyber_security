from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import httpx

app = FastAPI(title="CyberShield Scanner API", docs_url="/api/docs", openapi_url="/api/openapi.json")

# Allow CORS for development and frontend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrict this in production to your Vercel domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/health")
async def health_check():
    return {"status": "ok", "message": "FastAPI security backend is active!"}

@app.get("/api/scan/headers")
async def scan_headers(url: str):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            response = await client.get(url)
            
            headers = dict(response.headers)
            security_headers = {
                "Strict-Transport-Security": headers.get("Strict-Transport-Security"),
                "Content-Security-Policy": headers.get("Content-Security-Policy"),
                "X-Frame-Options": headers.get("X-Frame-Options"),
                "X-Content-Type-Options": headers.get("X-Content-Type-Options"),
                "Server": headers.get("Server"),
                "X-Powered-By": headers.get("X-Powered-By")
            }
            
            return {
                "target": url,
                "status_code": response.status_code,
                "security_headers": security_headers
            }
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Scan timed out. Target might be offline or blocking requests.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to scan target: {str(e)}")
