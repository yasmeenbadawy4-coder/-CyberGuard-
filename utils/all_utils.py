"""CyberGuard IDS — Backend Utilities
FIXES:
  1. Email: Gmail App Password support with step-by-step error messages
  4. PDF: Dark readable text colors (no more light-on-light)
"""
import os, json, uuid, hashlib, hmac, logging, threading, collections
import smtplib, io, urllib.request
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

log = logging.getLogger("cyberguard")
DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
os.makedirs(DATA_DIR, exist_ok=True)

try:
    import jwt as _jwt; _PJ = True
except ImportError:
    _PJ = False


# ─────────────────────────────────────────────────────────────────────────────
# JWT Auth
# ─────────────────────────────────────────────────────────────────────────────
class JWTAuth:
    def __init__(self, secret="cg-secret", hours=8):
        self._s = secret; self._h = hours; self._stubs = {}

    def generate(self, payload):
        if _PJ:
            payload["exp"] = datetime.utcnow() + timedelta(hours=self._h)
            return _jwt.encode(payload, self._s, algorithm="HS256")
        tok = str(uuid.uuid4())
        self._stubs[tok] = {**payload, "_exp": datetime.utcnow().timestamp() + self._h * 3600}
        return tok

    def verify(self, token):
        if not token: return None
        if _PJ:
            try: return _jwt.decode(token, self._s, algorithms=["HS256"])
            except: return None
        p = self._stubs.get(token)
        return p if p and p.get("_exp", 0) > datetime.utcnow().timestamp() else None


# ─────────────────────────────────────────────────────────────────────────────
# Threat Logger
# ─────────────────────────────────────────────────────────────────────────────
class ThreatLogger:
    def __init__(self):
        self._lock = threading.Lock()
        self._events = collections.deque(maxlen=20000)
        self._by_id = {}
        self._path = os.path.join(DATA_DIR, "threat_log.jsonl")
        self._load()

    def log(self, req, result):
        eid = result.get("scan_id") or str(uuid.uuid4())
        e = {
            "id": eid, "timestamp": datetime.utcnow().isoformat(),
            "target": req.get("target","?"), "src_ip": req.get("src_ip","?"),
            "label": result.get("label","NORMAL"), "severity": result.get("severity","LOW"),
            "confidence": result.get("confidence",0),
            "mitre_tactic": result.get("mitre_tactic",""),
            "attack_family": result.get("attack_family",""),
            "acknowledged": False, "request_data": req, "result": result,
        }
        with self._lock:
            self._events.append(e); self._by_id[eid] = e
        try:
            with open(self._path, "a") as f: f.write(json.dumps(e) + "\n")
        except: pass
        return eid

    def get_recent(self, limit=50, offset=0, severity=None):
        with self._lock: evs = list(self._events)
        evs.sort(key=lambda x: x["timestamp"], reverse=True)
        if severity: evs = [e for e in evs if e["severity"].lower() == severity.lower()]
        return evs[offset:offset+limit]

    def get_by_id(self, eid):
        with self._lock: return self._by_id.get(eid)

    def acknowledge(self, eid):
        with self._lock:
            e = self._by_id.get(eid)
            if not e: return False
            e["acknowledged"] = True; return True

    def get_stats(self):
        with self._lock: evs = list(self._events)
        now = datetime.utcnow(); h24 = now - timedelta(hours=24)
        recent = [e for e in evs if datetime.fromisoformat(e["timestamp"]) > h24]
        sc = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}; dist = {}
        for e in recent:
            sc[e.get("severity","LOW")] = sc.get(e.get("severity","LOW"),0) + 1
            lbl = e.get("label","?"); dist[lbl] = dist.get(lbl,0) + 1
        return {"total_events_24h":len(recent),"critical_threats_24h":sc["CRITICAL"]+sc["HIGH"],
                "severity_counts":sc,"attack_distribution":dist,"total_logged":len(evs)}

    def _load(self):
        if not os.path.exists(self._path): return
        try:
            with open(self._path) as f:
                for line in f:
                    if line.strip():
                        try:
                            e = json.loads(line)
                            self._events.append(e); self._by_id[e["id"]] = e
                        except: pass
        except: pass


# ─────────────────────────────────────────────────────────────────────────────
# Alert Manager
# ─────────────────────────────────────────────────────────────────────────────
class AlertManager:
    def __init__(self):
        self._lock = threading.Lock(); self._alerts = []
        self._path = os.path.join(DATA_DIR, "alerts.json"); self._load()

    def add(self, result):
        a = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "title": f"{result.get('severity','?')}: {result.get('label','?')} Detected",
            "body": f"Target: {result.get('target','?')} — Confidence: {result.get('confidence',0)}% — Family: {result.get('attack_family','?')}",
            "severity": result.get("severity","LOW").lower(),
            "label": result.get("label","?"),
            "mitre": result.get("mitre_tactic","?"),
            "target": result.get("target","?"),
            "actions": result.get("recommendations",[])[:3],
            "acknowledged": False,
        }
        with self._lock:
            self._alerts.insert(0, a); self._alerts = self._alerts[:500]; self._save()
        return a

    def get_all(self, severity=None):
        with self._lock: items = list(self._alerts)
        if severity: items = [a for a in items if a["severity"] == severity.lower()]
        return items

    def acknowledge(self, aid):
        with self._lock:
            for a in self._alerts:
                if a["id"] == aid:
                    a["acknowledged"] = not a["acknowledged"]; self._save(); return True
        return False

    def _save(self):
        try:
            with open(self._path, "w") as f: json.dump(self._alerts, f)
        except: pass

    def _load(self):
        if not os.path.exists(self._path): return
        try:
            with open(self._path) as f: self._alerts = json.load(f)
        except: pass


# ─────────────────────────────────────────────────────────────────────────────
# RBAC
# ─────────────────────────────────────────────────────────────────────────────
ROLES = {
    "admin":   {"label":"Administrator","level":3,"can_scan":True,"can_export_siem":True,"can_retrain":True,"can_manage_users":True,"can_slack":True,"can_view_alerts":True,"can_pdf":True,"can_email":True,"can_shap":True,"can_live_monitor":True},
    "analyst": {"label":"Analyst","level":2,"can_scan":True,"can_export_siem":True,"can_retrain":False,"can_manage_users":False,"can_slack":False,"can_view_alerts":True,"can_pdf":True,"can_email":True,"can_shap":True,"can_live_monitor":True},
    "viewer":  {"label":"Viewer","level":1,"can_scan":False,"can_export_siem":False,"can_retrain":False,"can_manage_users":False,"can_slack":False,"can_view_alerts":True,"can_pdf":False,"can_email":False,"can_shap":False,"can_live_monitor":False},
}

USERS_FILE = os.path.join(DATA_DIR, "users.json")
DEFAULTS = [
    {"username":"admin",   "password":"CyberGuard2024!", "role":"admin",   "email":"admin@cyberguard.local"},
    {"username":"analyst", "password":"Analyst2024!",    "role":"analyst", "email":"analyst@cyberguard.local"},
    {"username":"viewer",  "password":"Viewer2024!",     "role":"viewer",  "email":"viewer@cyberguard.local"},
]

def _hash(pw, salt=None):
    if salt is None: salt = uuid.uuid4().hex
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 260000)
    return dk.hex(), salt

def _verify(pw, stored, salt):
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 260000)
    return hmac.compare_digest(dk.hex(), stored)


class AuthStore:
    def __init__(self):
        self._lock = threading.Lock(); self._users = {}; self._load(); self._seed()

    def _load(self):
        if not os.path.exists(USERS_FILE): return
        try:
            with open(USERS_FILE) as f:
                data = json.load(f); self._users = {u["username"]: u for u in data}
        except: pass

    def _save(self):
        try:
            with open(USERS_FILE, "w") as f: json.dump(list(self._users.values()), f, indent=2)
        except: pass

    def _seed(self):
        changed = False
        for u in DEFAULTS:
            if u["username"] not in self._users:
                h, s = _hash(u["password"])
                self._users[u["username"]] = {
                    "id": str(uuid.uuid4()), "username": u["username"],
                    "hash": h, "salt": s, "role": u["role"], "email": u["email"],
                    "created": datetime.utcnow().isoformat(), "active": True,
                }
                changed = True
        if changed: self._save()

    def register(self, username, password, email, role="viewer", admin_key=""):
        username = (username or "").strip().lower()
        if len(username) < 3: return {"ok":False,"error":"Username ≥ 3 characters."}
        if len(password or "") < 8: return {"ok":False,"error":"Password ≥ 8 characters."}
        if "@" not in (email or ""): return {"ok":False,"error":"Valid email required."}
        if role not in ROLES: return {"ok":False,"error":f"Role must be: {', '.join(ROLES)}"}
        if role in ("admin","analyst"):
            if admin_key != os.getenv("ADMIN_REGISTRATION_KEY","cg-admin-secret"):
                return {"ok":False,"error":"Admin registration key required."}
        with self._lock:
            if username in self._users: return {"ok":False,"error":"Username already taken."}
            h, s = _hash(password)
            self._users[username] = {
                "id": str(uuid.uuid4()), "username": username,
                "hash": h, "salt": s, "role": role,
                "email": (email or "").strip(),
                "created": datetime.utcnow().isoformat(), "active": True,
            }
            self._save()
        return {"ok":True,"username":username,"role":role}

    def login(self, username, password):
        username = (username or "").strip().lower()
        with self._lock: u = self._users.get(username)
        if not u: return {"ok":False,"error":"Invalid credentials."}
        if not u.get("active",True): return {"ok":False,"error":"Account is disabled."}
        if not _verify(password or "", u["hash"], u["salt"]): return {"ok":False,"error":"Invalid credentials."}
        return {"ok":True,"username":u["username"],"role":u["role"],"email":u.get("email",""),"id":u["id"]}

    def get_all_users(self):
        return [{"id":u["id"],"username":u["username"],"role":u["role"],
                 "email":u.get("email",""),"created":u.get("created",""),"active":u.get("active",True)}
                for u in self._users.values()]

    def update_role(self, username, new_role):
        if new_role not in ROLES: return {"ok":False,"error":"Invalid role."}
        with self._lock:
            if username not in self._users: return {"ok":False,"error":"User not found."}
            self._users[username]["role"] = new_role; self._save()
        return {"ok":True}

    def deactivate(self, username):
        with self._lock:
            if username not in self._users: return {"ok":False,"error":"User not found."}
            if username == "admin": return {"ok":False,"error":"Cannot deactivate admin."}
            self._users[username]["active"] = False; self._save()
        return {"ok":True}

    def role_permissions(self, role): return ROLES.get(role, ROLES["viewer"])


# ─────────────────────────────────────────────────────────────────────────────
# PDF Report — FIX 4: ALL dark/readable colors, white background
# ─────────────────────────────────────────────────────────────────────────────
def build_pdf(data, requester={}):
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.lib import colors
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                        Table, TableStyle, HRFlowable)
        res  = data.get("results", {})
        meta = data.get("scan_meta", {})
        buf  = io.BytesIO()
        doc  = SimpleDocTemplate(buf, pagesize=A4,
                                 leftMargin=18*mm, rightMargin=18*mm,
                                 topMargin=20*mm, bottomMargin=20*mm)

        # ── Color palette — all dark, print-safe ──────────────────────────
        C_BLACK    = colors.HexColor("#111111")   # near-black body text
        C_DARK     = colors.HexColor("#1a2a3a")   # dark navy headings
        C_LABEL    = colors.HexColor("#2c4a5e")   # dark blue-grey table labels
        C_TEAL     = colors.HexColor("#005f58")   # dark teal accents
        C_AMBER    = colors.HexColor("#7a5200")   # dark amber
        C_RED      = colors.HexColor("#990000")   # dark red
        C_PURPLE   = colors.HexColor("#4a2a7a")   # dark purple
        C_HDR_BG   = colors.HexColor("#0a1520")   # dark navy header band bg
        C_HDR_TEXT = colors.HexColor("#e0f0ee")   # very light text on dark bg
        C_ROW_ODD  = colors.HexColor("#f5f8fa")   # light grey alternating row
        C_ROW_EVN  = colors.HexColor("#ffffff")   # white alternating row
        C_BORDER   = colors.HexColor("#b0c4d0")   # visible border

        sev = res.get("severity","LOW")
        sev_col = {"CRITICAL":C_RED,"HIGH":C_AMBER,"MEDIUM":C_PURPLE,"LOW":C_TEAL}.get(sev, C_TEAL)

        def P(txt, bold=False, color=None, size=10, align="LEFT"):
            al = {"LEFT":0,"CENTER":1,"RIGHT":2}.get(align,0)
            return Paragraph(str(txt), ParagraphStyle("_",
                fontName="Helvetica-Bold" if bold else "Helvetica",
                fontSize=size, textColor=color or C_BLACK,
                leading=size*1.6, alignment=al))

        def make_table(rows, widths):
            t = Table(rows, colWidths=widths)
            t.setStyle(TableStyle([
                # Header row (row 0)
                ("BACKGROUND",    (0,0), (-1,0), C_HDR_BG),
                ("TEXTCOLOR",     (0,0), (-1,0), C_HDR_TEXT),
                ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
                ("FONTSIZE",      (0,0), (-1,0), 9),
                # Data rows alternating
                ("ROWBACKGROUNDS",(0,1), (-1,-1), [C_ROW_EVN, C_ROW_ODD]),
                # Left column: labels
                ("TEXTCOLOR",     (0,1), (0,-1), C_LABEL),
                ("FONTNAME",      (0,1), (0,-1), "Helvetica-Bold"),
                ("FONTSIZE",      (0,1), (0,-1), 9),
                # Right column: values
                ("TEXTCOLOR",     (1,1), (1,-1), C_BLACK),
                ("FONTNAME",      (1,1), (1,-1), "Helvetica"),
                ("FONTSIZE",      (1,1), (1,-1), 9),
                # Spacing
                ("TOPPADDING",    (0,0), (-1,-1), 6),
                ("BOTTOMPADDING", (0,0), (-1,-1), 6),
                ("LEFTPADDING",   (0,0), (-1,-1), 10),
                ("RIGHTPADDING",  (0,0), (-1,-1), 10),
                # Borders
                ("BOX",           (0,0), (-1,-1), 0.75, C_BORDER),
                ("INNERGRID",     (0,0), (-1,-1), 0.5,  C_BORDER),
                ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
            ]))
            return t

        story = []

        # ── Title banner ──────────────────────────────────────────────────
        banner = Table([[
            P("⚡  CYBERGUARD IDS v1.0", bold=True, color=C_HDR_TEXT, size=19),
            P("AI Network Intrusion Detection", color=colors.HexColor("#90b8c8"), size=10, align="RIGHT"),
        ]], colWidths=[120*mm, 55*mm])
        banner.setStyle(TableStyle([
            ("BACKGROUND",    (0,0),(-1,-1), C_HDR_BG),
            ("TOPPADDING",    (0,0),(-1,-1), 16),
            ("BOTTOMPADDING", (0,0),(-1,-1), 16),
            ("LEFTPADDING",   (0,0),(-1,-1), 14),
            ("RIGHTPADDING",  (0,0),(-1,-1), 14),
            ("VALIGN",        (0,0),(-1,-1), "MIDDLE"),
        ]))
        story.append(banner)
        story.append(Spacer(1, 5*mm))

        story.append(P("SECURITY ASSESSMENT REPORT", bold=True, color=C_DARK, size=15))
        story.append(Spacer(1, 2*mm))
        story.append(HRFlowable(width="100%", thickness=1.5, color=C_TEAL, spaceBefore=1, spaceAfter=5))

        # ── Report metadata ───────────────────────────────────────────────
        story.append(P("REPORT DETAILS", bold=True, color=C_TEAL, size=11))
        story.append(Spacer(1, 2*mm))
        story.append(make_table([
            ["Field",        "Value"],
            ["Generated",    datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")],
            ["Analyst",      requester.get("username","System")],
            ["Target",       meta.get("target", res.get("target","—"))],
            ["Scan ID",      (res.get("scan_id","—")[:36])],
            ["Datasets",     "NSL-KDD + UNSW-NB15  ·  6 Real ML Models"],
        ], [55*mm, 115*mm]))
        story.append(Spacer(1, 7*mm))

        # ── Threat classification ─────────────────────────────────────────
        story.append(P("THREAT CLASSIFICATION", bold=True, color=C_TEAL, size=11))
        story.append(Spacer(1, 2*mm))
        story.append(make_table([
            ["Field",           "Value"],
            ["Threat Label",    res.get("label","NORMAL")],
            ["Severity",        sev],
            ["Confidence",      f"{res.get('confidence',0)}%"],
            ["Attack Family",   res.get("attack_family","—")],
            ["MITRE ATT&CK",    res.get("mitre_tactic","N/A")],
            ["CVE References",  "  |  ".join(res.get("cve_refs",[])) or "None identified"],
        ], [55*mm, 115*mm]))
        story.append(Spacer(1, 7*mm))

        # ── Model outputs ─────────────────────────────────────────────────
        mo = res.get("model_outputs", {})
        if mo:
            story.append(P("MODEL OUTPUTS  (6 Real Trained Models)", bold=True, color=C_TEAL, size=11))
            story.append(Spacer(1, 2*mm))
            rows = [["Model", "Result  ·  Classification"]]
            for k, v in mo.items():
                name = k.replace("_"," ").title()
                if "label" in v:
                    val = f"{v['label']} — {v.get('confidence',0)}% confidence  [{v.get('classification','')}]"
                else:
                    anom = "YES ⚠" if v.get("anomaly") else "NO ✓"
                    val  = f"Anomaly: {anom}  (score: {v.get('score','?')} / threshold: {v.get('threshold','?')})  [binary]"
                rows.append([name, val])
            story.append(make_table(rows, [55*mm, 115*mm]))
            story.append(Spacer(1, 7*mm))

        # ── Recommended actions ───────────────────────────────────────────
        recs = res.get("recommendations", [])
        if recs:
            story.append(P("RECOMMENDED ACTIONS", bold=True, color=C_TEAL, size=11))
            story.append(Spacer(1, 2*mm))
            for i, rec in enumerate(recs, 1):
                story.append(P(f"{i}.  {rec}", color=C_BLACK, size=9))
                story.append(Spacer(1, 2*mm))
            story.append(Spacer(1, 3*mm))

        # ── Footer ────────────────────────────────────────────────────────
        story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceBefore=4, spaceAfter=4))
        story.append(P(
            "CyberGuard IDS v1.0  ·  NSL-KDD + UNSW-NB15  ·  "
            "RF · XGBoost · DT · ANN · Autoencoder · Hybrid AE+XGB  ·  CONFIDENTIAL",
            color=colors.HexColor("#556677"), size=7, align="CENTER"
        ))

        doc.build(story)
        return buf.getvalue()

    except ImportError:
        return (
            f"CyberGuard IDS Report\n{datetime.utcnow().isoformat()}\n"
            f"Threat: {data.get('results',{}).get('label','?')}\n"
            f"Install reportlab: pip install reportlab\n"
        ).encode()


# ─────────────────────────────────────────────────────────────────────────────
# Email — FIX 1: Gmail App Password + clear step-by-step error messages
# ─────────────────────────────────────────────────────────────────────────────
def send_email(to, subject, results, name="Analyst"):
    """
    Send HTML email report via SMTP.
    Gmail REQUIRES an App Password — your regular login password will fail (Error 535).

    Setup (2 minutes):
      1. myaccount.google.com → Security → 2-Step Verification (must be ON)
      2. Search 'App passwords' → Generate → copy the 16-char code
      3. backend/.env → SMTP_PASS=abcdefghijklmnop  (no spaces)
      4. Restart: python app.py
    """
    host = os.getenv("SMTP_HOST", "smtp.gmail.com")
    port = int(os.getenv("SMTP_PORT", 587))
    user = os.getenv("SMTP_USER", "").strip()
    pwd  = os.getenv("SMTP_PASS", "").strip()
    frm  = os.getenv("SMTP_FROM", user) or "cyberguard@ids.local"

    # ── Pre-flight config check ───────────────────────────────────────────
    if not user or not pwd:
        raise ValueError(
            "Email not configured.\n\n"
            "Add to backend/.env:\n"
            "  SMTP_USER=your@gmail.com\n"
            "  SMTP_PASS=abcdefghijklmnop   ← 16-char Gmail App Password\n\n"
            "Get an App Password:\n"
            "  myaccount.google.com → Security → App passwords"
        )

    lbl = results.get("label","NORMAL")
    sev = results.get("severity","LOW")
    col = {"CRITICAL":"#990000","HIGH":"#7a5200","MEDIUM":"#4a2a7a","LOW":"#005f58"}.get(sev,"#333")

    recs_html = "".join(
        f"<li style='margin-bottom:8px;font-family:monospace;font-size:13px;color:#111'>{r}</li>"
        for r in results.get("recommendations",[])
    )
    cves_html = "".join(
        f"<li style='color:#333;font-family:monospace;font-size:13px'>{c}</li>"
        for c in results.get("cve_refs",[])
    )
    mo = results.get("model_outputs",{})
    model_rows = ""
    for k, v in mo.items():
        nm  = k.replace("_"," ").title()
        val = (f"{v['label']} ({v.get('confidence',0)}%)"
               if "label" in v else
               f"{'⚠ Anomaly' if v.get('anomaly') else '✓ Normal'}  score={v.get('score','?')}")
        model_rows += (
            f"<tr><td style='padding:7px 10px;background:#f0f5f8;color:#1a2a3a;"
            f"font-weight:bold;border-bottom:1px solid #c8d8e0;font-size:13px'>{nm}</td>"
            f"<td style='padding:7px 10px;color:#111;border-bottom:1px solid #c8d8e0;"
            f"font-family:monospace;font-size:13px'>{val}</td></tr>"
        )

    html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"></head>
<body style="font-family:Arial,sans-serif;background:#e8eef4;padding:24px;margin:0">
<div style="max-width:660px;margin:0 auto;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 2px 16px rgba(0,0,0,.15)">

  <div style="background:#0a1520;padding:24px 28px">
    <h1 style="color:#e0f0ee;margin:0;font-size:20px;letter-spacing:1px">⚡ CyberGuard IDS — Security Report</h1>
    <p style="color:#88aabb;margin:6px 0 0;font-size:13px">6-Model AI Network Intrusion Detection System v1.0</p>
  </div>

  <div style="padding:28px">
    <p style="color:#111;font-size:14px;margin-bottom:18px">Dear <strong>{name}</strong>,</p>
    <p style="color:#333;font-size:13px;margin-bottom:20px">Your CyberGuard IDS scan has completed. The threat assessment is below.</p>

    <h3 style="color:#005f58;font-size:13px;text-transform:uppercase;letter-spacing:1px;margin-bottom:10px;border-bottom:2px solid #005f58;padding-bottom:4px">Threat Classification</h3>
    <table style="width:100%;border-collapse:collapse;margin-bottom:24px;font-size:13px">
      <tr><td style="padding:8px 10px;background:#f0f5f8;color:#1a2a3a;font-weight:bold;border-bottom:1px solid #c8d8e0;width:36%">Classification</td><td style="padding:8px 10px;color:{col};font-weight:bold;font-size:15px;border-bottom:1px solid #c8d8e0">{lbl}</td></tr>
      <tr><td style="padding:8px 10px;background:#f0f5f8;color:#1a2a3a;font-weight:bold;border-bottom:1px solid #c8d8e0">Severity</td><td style="padding:8px 10px;color:{col};font-weight:bold;border-bottom:1px solid #c8d8e0">{sev}</td></tr>
      <tr><td style="padding:8px 10px;background:#f0f5f8;color:#1a2a3a;font-weight:bold;border-bottom:1px solid #c8d8e0">Confidence</td><td style="padding:8px 10px;color:#111;border-bottom:1px solid #c8d8e0">{results.get('confidence',0)}%</td></tr>
      <tr><td style="padding:8px 10px;background:#f0f5f8;color:#1a2a3a;font-weight:bold;border-bottom:1px solid #c8d8e0">Attack Family</td><td style="padding:8px 10px;color:#111;border-bottom:1px solid #c8d8e0">{results.get('attack_family','—')}</td></tr>
      <tr><td style="padding:8px 10px;background:#f0f5f8;color:#1a2a3a;font-weight:bold">MITRE ATT&amp;CK</td><td style="padding:8px 10px;color:#111;font-family:monospace;font-size:12px">{results.get('mitre_tactic','N/A')}</td></tr>
    </table>

    {"<h3 style='color:#005f58;font-size:13px;text-transform:uppercase;letter-spacing:1px;margin-bottom:10px;border-bottom:2px solid #005f58;padding-bottom:4px'>Model Outputs</h3><table style='width:100%;border-collapse:collapse;margin-bottom:24px'>"+model_rows+"</table>" if model_rows else ""}

    <h3 style="color:#005f58;font-size:13px;text-transform:uppercase;letter-spacing:1px;margin-bottom:10px;border-bottom:2px solid #005f58;padding-bottom:4px">Recommended Actions</h3>
    <ol style="color:#111;line-height:2.2;margin-bottom:24px;padding-left:18px">{recs_html}</ol>

    {"<h3 style='color:#7a5200;font-size:13px;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px'>CVE References</h3><ul style='margin-bottom:24px;padding-left:18px;line-height:2'>"+cves_html+"</ul>" if cves_html else ""}

    <hr style="border:none;border-top:1px solid #c8d8e0;margin:24px 0">
    <p style="font-size:11px;color:#556677;margin:0">CyberGuard IDS v1.0 &nbsp;·&nbsp; {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} &nbsp;·&nbsp; CONFIDENTIAL</p>
  </div>
</div>
</body></html>"""

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = frm
    msg["To"]      = to
    msg.attach(MIMEText(html, "html", "utf-8"))

    try:
        with smtplib.SMTP(host, port) as s:
            s.ehlo()
            s.starttls()
            s.ehlo()
            s.login(user, pwd)
            s.sendmail(frm, [to], msg.as_string())
        log.info(f"Email sent successfully to {to}")

    except smtplib.SMTPAuthenticationError:
        raise ValueError(
            "Gmail rejected the password (Error 535).\n\n"
            "CAUSE: You used your regular Gmail password — Gmail blocks this for security.\n\n"
            "SOLUTION — Use a Gmail App Password instead:\n"
            "  1. Go to: myaccount.google.com/security\n"
            "  2. Enable 2-Step Verification (must be ON first)\n"
            "  3. Search 'App passwords' at the top of that page\n"
            "  4. Click 'Create' → name it 'CyberGuard' → click Create\n"
            "  5. Copy the 16-character code shown (e.g. abcd efgh ijkl mnop)\n"
            "  6. In backend/.env, set:  SMTP_PASS=abcdefghijklmnop  (no spaces)\n"
            "  7. Restart backend:  python app.py\n\n"
            "Your regular Gmail login password will NEVER work for SMTP."
        )
    except smtplib.SMTPException as e:
        raise ValueError(f"SMTP error sending email: {str(e)}")
    except OSError as e:
        raise ValueError(
            f"Cannot connect to {host}:{port}. "
            "Check your internet connection and SMTP_HOST/SMTP_PORT settings."
        )


# ─────────────────────────────────────────────────────────────────────────────
# Slack & SIEM
# ─────────────────────────────────────────────────────────────────────────────
def send_slack(message, severity="info"):
    webhook = os.getenv("SLACK_WEBHOOK_URL","")
    if not webhook:
        log.info(f"[Slack stub] {severity}: {message}"); return
    emoji  = {"critical":"🔴","high":"🟠","medium":"🟡","low":"🟢"}.get(severity,"⚡")
    colour = {"critical":"danger","high":"warning","medium":"#4a2a7a","low":"good"}.get(severity,"#005f58")
    payload = {"attachments":[{
        "color": colour,
        "text":  f"{emoji} *CyberGuard IDS* — {message}",
        "footer":f"v1.0 · {datetime.utcnow().strftime('%H:%M UTC')}",
    }]}
    req = urllib.request.Request(webhook, data=json.dumps(payload).encode(),
                                 headers={"Content-Type":"application/json"})
    urllib.request.urlopen(req, timeout=5)

def to_cef(e):
    sn = {"CRITICAL":10,"HIGH":8,"MEDIUM":5,"LOW":2}.get(e.get("severity","LOW"),2)
    return (f"CEF:0|CyberGuard|IDSv1|1.0|{e.get('label','?')}|"
            f"{e.get('attack_family','?')}|{sn}|"
            f"src={e.get('src_ip','?')} dst={e.get('target','?')} "
            f"cs1={e.get('mitre_tactic','?')} rt={e.get('timestamp','?')}")

def to_leef(e):
    return (f"LEEF:2.0|CyberGuard|IDSv1|1.0|{e.get('label','?')}|"
            f"sev={e.get('severity','?')}\tsrc={e.get('src_ip','?')}\t"
            f"dst={e.get('target','?')}\tmitre={e.get('mitre_tactic','?')}\t"
            f"devTime={e.get('timestamp','?')}")
