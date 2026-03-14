"""
ThreatLens – FastAPI Application Entry Point
"""

import asyncio
import hashlib
import json
import logging
import secrets
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Dict, List, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import os

# ── Logging ────────────────────────────────────────────────────────────────
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("threatlens")

from ..engine import DPIEngine, RuleManager
from ..ml import MLClassifier
from ..ml.auto_train import AutoTrainEngine

# ── Singletons ─────────────────────────────────────────────────────────────
rule_manager  = RuleManager()
classifier    = MLClassifier()
engine        = DPIEngine(rule_manager=rule_manager, classifier=classifier)
auto_trainer  = AutoTrainEngine()

# Reference to the main asyncio event loop (set during lifespan startup)
_loop: Optional[asyncio.AbstractEventLoop] = None

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active: List[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)

    async def broadcast(self, message: dict):
        dead = []
        for ws in self.active:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

ws_manager = ConnectionManager()


# ── Engine callbacks → WebSocket broadcast ──────────────────────────────────
# These callbacks are invoked from a background threading.Thread (DPIEngine's
# capture loop), so we must use run_coroutine_threadsafe() instead of
# asyncio.create_task() which only works from within the event loop thread.

def _on_packet(pkt: dict):
    if _loop and _loop.is_running():
        asyncio.run_coroutine_threadsafe(_broadcast({"type": "packet", "data": pkt}), _loop)

def _on_alert(alert: dict):
    if _loop and _loop.is_running():
        asyncio.run_coroutine_threadsafe(_broadcast({"type": "alert", "data": alert}), _loop)

def _on_flow(flow):
    if _loop and _loop.is_running():
        asyncio.run_coroutine_threadsafe(_broadcast({
            "type": "flow",
            "data": {
                "src_ip":   flow.five_tuple.src_ip,
                "dst_ip":   flow.five_tuple.dst_ip,
                "app":      flow.app_type.value,
                "pkts":     flow.pkt_count,
                "bytes":    flow.byte_count,
                "label":    flow.ml_label.value,
            }
        }), _loop)

async def _broadcast(msg: dict):
    await ws_manager.broadcast(msg)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _loop
    _loop = asyncio.get_running_loop()

    # Register callbacks
    engine.on_packet(_on_packet)
    engine.on_alert(_on_alert)
    engine.on_flow(_on_flow)

    # Wire auto-trainer: every completed flow is fed for learning
    engine.on_flow(auto_trainer.on_flow_completed)

    # Start capture in background (demo mode if no interface/pcap)
    pcap  = os.environ.get("PCAP_FILE")
    iface = os.environ.get("CAPTURE_INTERFACE")
    engine.start_capture(interface=iface, pcap_file=pcap)

    # Start auto-train background scheduler
    auto_trainer.start()

    yield  # App is running

    engine.stop_capture()
    auto_trainer.stop()
    _loop = None


# ── FastAPI app ───────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

app = FastAPI(
    title       = "ThreatLens API",
    description = "AI Network Threat Detection Platform",
    version     = "1.0.0",
    lifespan    = lifespan,
)

# ── CORS Middleware ───────────────────────────────────────────────────────────
CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "frontend", "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "frontend", "templates"))


# ── Authentication ───────────────────────────────────────────────────────────
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "threatlens123")

# In-memory session store: token -> username
_sessions: Dict[str, str] = {}


def _hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def _is_authenticated(request: Request) -> bool:
    token = request.cookies.get("tl_session")
    return token is not None and token in _sessions


# Public paths that don't require auth
_PUBLIC_PATHS = {"/login", "/api/health", "/docs", "/openapi.json", "/redoc"}


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path

    # Allow static files, public paths, and WebSocket upgrades
    if (path.startswith("/static") or
        path in _PUBLIC_PATHS or
        request.scope.get("type") == "websocket"):
        return await call_next(request)

    # Check authentication
    if not _is_authenticated(request):
        if path.startswith("/api/"):
            return JSONResponse({"error": "Unauthorized"}, status_code=401)
        return RedirectResponse("/login", status_code=302)

    return await call_next(request)


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if _is_authenticated(request):
        return RedirectResponse("/", status_code=302)
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@app.post("/login", response_class=HTMLResponse)
async def login_submit(request: Request, username: str = Form(...), password: str = Form(...)):
    if username == ADMIN_USER and password == ADMIN_PASS:
        token = secrets.token_hex(32)
        _sessions[token] = username
        response = RedirectResponse("/", status_code=302)
        response.set_cookie(
            key="tl_session", value=token,
            httponly=True, samesite="lax", max_age=86400,  # 24h
        )
        logger.info(f"User '{username}' logged in")
        return response
    else:
        logger.warning(f"Failed login attempt for user '{username}'")
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Invalid username or password",
        })


@app.get("/logout")
async def logout(request: Request):
    token = request.cookies.get("tl_session")
    if token and token in _sessions:
        del _sessions[token]
    response = RedirectResponse("/login", status_code=302)
    response.delete_cookie("tl_session")
    return response


# ── Health Check ──────────────────────────────────────────────────────────────
@app.get("/api/health")
async def health_check():
    """Liveness / readiness probe for Docker and load balancers."""
    stats = engine.get_stats()
    return {
        "status":       "healthy",
        "version":      "1.0.0",
        "engine":       "running" if engine._running else "stopped",
        "total_packets": stats.get("total_packets", 0),
        "active_flows":  stats.get("active_flows", 0),
        "model_loaded":  classifier._model is not None,
    }


# ── Page routes ───────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})

@app.get("/alerts", response_class=HTMLResponse)
async def alerts_page(request: Request):
    return templates.TemplateResponse("alerts.html", {"request": request})

@app.get("/rules", response_class=HTMLResponse)
async def rules_page(request: Request):
    return templates.TemplateResponse("rules.html", {"request": request})

@app.get("/reports", response_class=HTMLResponse)
async def reports_page(request: Request):
    return templates.TemplateResponse("reports.html", {"request": request})

@app.get("/ml-training", response_class=HTMLResponse)
async def ml_training_page(request: Request):
    return templates.TemplateResponse("ml_training.html", {"request": request})

@app.get("/traffic", response_class=HTMLResponse)
async def traffic_page(request: Request):
    return templates.TemplateResponse("traffic.html", {"request": request})


# ── REST API ──────────────────────────────────────────────────────────────────
@app.get("/api/stats")
async def get_stats():
    return engine.get_stats()

@app.get("/api/packets")
async def get_packets(limit: int = 100):
    return engine.get_recent_packets(limit)

@app.get("/api/alerts")
async def get_alerts(limit: int = 50):
    return engine.get_recent_alerts(limit)

@app.get("/api/flows")
async def get_flows():
    return engine.get_active_flows_summary()

@app.get("/api/rules")
async def get_rules():
    rules = rule_manager.get_all_rules()
    return [
        {
            "id":         r.id,
            "type":       r.rule_type,
            "value":      r.value,
            "enabled":    r.enabled,
            "notes":      r.notes,
            "created_at": r.created_at.isoformat(),
        }
        for r in rules
    ]

class RuleCreate(BaseModel):
    rule_type: str
    value: str
    notes: str = ""

@app.post("/api/rules")
async def add_rule(body: RuleCreate):
    rule = rule_manager.add_rule(body.rule_type, body.value, body.notes)
    return {"id": rule.id, "type": rule.rule_type, "value": rule.value, "enabled": rule.enabled}

@app.delete("/api/rules/{rule_id}")
async def delete_rule(rule_id: int):
    ok = rule_manager.remove_rule(rule_id)
    return {"deleted": ok}

@app.patch("/api/rules/{rule_id}/toggle")
async def toggle_rule(rule_id: int):
    enabled = rule_manager.toggle_rule(rule_id)
    return {"enabled": enabled}


# ── CSV / PDF export ──────────────────────────────────────────────────────────
@app.get("/api/reports/csv")
async def export_csv():
    from fastapi.responses import StreamingResponse
    import csv, io
    packets = engine.get_recent_packets(10000)
    output  = io.StringIO()
    writer  = csv.DictWriter(output, fieldnames=["ts","src_ip","dst_ip","src_port","dst_port","protocol","length","app_type","sni","blocked"])
    writer.writeheader()
    writer.writerows(packets)
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type = "text/csv",
        headers    = {"Content-Disposition": f"attachment; filename=threatlens_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"},
    )

@app.get("/api/reports/pdf")
async def export_pdf():
    from fastapi.responses import StreamingResponse
    import io
    stats   = engine.get_stats()
    alerts  = engine.get_recent_alerts(20)
    packets = engine.get_recent_packets(20)

    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle, Spacer
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.units import inch

        buf    = io.BytesIO()
        doc    = SimpleDocTemplate(buf, pagesize=letter, title="ThreatLens Report")
        styles = getSampleStyleSheet()
        elems  = []

        elems.append(Paragraph("ThreatLens – Security Report", styles["Title"]))
        elems.append(Paragraph(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}", styles["Normal"]))
        elems.append(Spacer(1, 0.3 * inch))

        # KPI table
        elems.append(Paragraph("Summary", styles["Heading2"]))
        kpi_data = [
            ["Metric", "Value"],
            ["Total Packets",    str(stats["total_packets"])],
            ["Total Bytes",      f"{stats['total_bytes']:,}"],
            ["Blocked Packets",  str(stats["blocked_count"])],
            ["Active Flows",     str(stats["active_flows"])],
            ["Alerts Generated", str(stats["alerts_count"])],
        ]
        kpi_tbl = Table(kpi_data, colWidths=[3*inch, 3*inch])
        kpi_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#1E40AF")),
            ("TEXTCOLOR",  (0,0), (-1,0), colors.white),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.HexColor("#EFF6FF"), colors.white]),
            ("GRID", (0,0), (-1,-1), 0.5, colors.HexColor("#BFDBFE")),
            ("FONTNAME", (0,0), (-1,-1), "Helvetica"),
        ]))
        elems.append(kpi_tbl)
        elems.append(Spacer(1, 0.3 * inch))

        # Recent alerts
        elems.append(Paragraph("Recent Alerts", styles["Heading2"]))
        alert_data = [["Time", "Type", "Severity", "Source IP", "Description"]]
        for a in alerts[:10]:
            alert_data.append([a["ts"][:19], a["type"], a["severity"], a["src_ip"], a["description"][:60]])
        if len(alert_data) > 1:
            a_tbl = Table(alert_data, colWidths=[1.5*inch, 1.2*inch, 1*inch, 1.3*inch, 3*inch])
            a_tbl.setStyle(TableStyle([
                ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#1E40AF")),
                ("TEXTCOLOR",  (0,0), (-1,0), colors.white),
                ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.HexColor("#FFF7ED"), colors.white]),
                ("GRID", (0,0), (-1,-1), 0.5, colors.HexColor("#BFDBFE")),
                ("FONTSIZE", (0,0), (-1,-1), 8),
                ("FONTNAME", (0,0), (-1,-1), "Helvetica"),
            ]))
            elems.append(a_tbl)

        doc.build(elems)
        buf.seek(0)
        return StreamingResponse(
            buf,
            media_type = "application/pdf",
            headers    = {"Content-Disposition": f"attachment; filename=threatlens_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"},
        )
    except ImportError:
        return JSONResponse({"error": "reportlab not installed. Run: pip install reportlab"}, status_code=500)

@app.get("/api/autotrain/stats")
async def autotrain_stats():
    return auto_trainer.get_stats()

@app.post("/api/autotrain/retrain")
async def force_retrain():
    auto_trainer.force_retrain()
    return {"status": "retrain started"}

@app.post("/api/autotrain/confirm")
async def confirm_threat_endpoint(src_ip: str, label: str):
    """Analyst endpoint: confirm a flow as a specific threat label."""
    # We don't have the flow object here — store as a synthetic feedback row
    import csv
    from pathlib import Path
    from ..ml.auto_train import FEEDBACK_CSV, ALL_COLS, FEATURE_COLS
    import random, datetime
    row = {c: random.uniform(0,1) for c in FEATURE_COLS}
    row.update({
        "avg_pkt_size": 400, "pkt_count": 20, "flow_duration_sec": 5,
        "bytes_per_sec": 8000, "dst_port": 443,
        "protocol_tcp": 1, "protocol_udp": 0, "has_sni": 1,
        "inter_arrival_mean": 100, "inter_arrival_std": 20, "pkt_size_std": 50,
        "label": label, "weight": 5.0,
        "source": f"analyst:{src_ip}", "ts": datetime.datetime.utcnow().isoformat()
    })
    FEEDBACK_CSV.parent.mkdir(parents=True, exist_ok=True)
    write_header = not FEEDBACK_CSV.exists()
    with open(FEEDBACK_CSV, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(row.keys()))
        if write_header:
            w.writeheader()
        w.writerow(row)
    return {"status": "feedback stored", "label": label}


# ── WebSocket ─────────────────────────────────────────────────────────────────
@app.websocket("/ws/live")
async def websocket_endpoint(ws: WebSocket):
    # Verify authentication
    token = ws.cookies.get("tl_session")
    if token is None or token not in _sessions:
        await ws.close(code=1008, reason="Unauthorized")
        return

    await ws_manager.connect(ws)

    async def _sender():
        """Push stats every 2 seconds."""
        try:
            await ws.send_json({"type": "init", "data": engine.get_stats()})
            while True:
                await asyncio.sleep(2)
                await ws.send_json({"type": "stats", "data": engine.get_stats()})
        except Exception:
            pass

    async def _receiver():
        """Listen for incoming messages / detect disconnect."""
        try:
            while True:
                await ws.receive_text()
        except Exception:
            pass

    # Run sender and receiver concurrently; when either finishes, cancel the other
    sender_task   = asyncio.create_task(_sender())
    receiver_task = asyncio.create_task(_receiver())
    try:
        done, pending = await asyncio.wait(
            [sender_task, receiver_task],
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()
    finally:
        ws_manager.disconnect(ws)
