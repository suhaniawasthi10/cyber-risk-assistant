import json
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app.pipeline import RESULTS_PATH, run as run_pipeline


@asynccontextmanager
async def lifespan(app):
    if RESULTS_PATH.exists():
        print(f"[startup] serving cached results.json from {RESULTS_PATH}", flush=True)
    else:
        print(f"[startup] results.json not found; running pipeline once", flush=True)
        run_pipeline(verbose=True)
    yield


app = FastAPI(title="TawasolPay Cyber Risk Assistant", lifespan=lifespan)

# CORS: permissive for now (no frontend deployed yet). Tighten via FRONTEND_URL
# env var once the Vercel URL is known.
_origins_env = os.environ.get("FRONTEND_URL", "*")
if _origins_env == "*":
    allow_origins = ["*"]
else:
    allow_origins = [o.strip() for o in _origins_env.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.get("/api/risks")
def get_risks():
    if not RESULTS_PATH.exists():
        raise HTTPException(status_code=503, detail="pipeline output not yet generated")
    return json.loads(RESULTS_PATH.read_text())


@app.post("/api/refresh")
def refresh():
    result = run_pipeline(verbose=False)
    return {
        "refreshed_at": result["generated_at"],
        "risk_count": len(result["risks"]),
    }
