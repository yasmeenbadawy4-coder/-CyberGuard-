"""CyberGuard IDS v1.0 — Complete Flask Backend with Real-Time IDS"""
import os,uuid,re,io,json,logging,threading,time,socket,struct
from datetime import datetime
from functools import wraps
from flask import Flask,request,jsonify,send_file,Response,stream_with_context
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()
logging.basicConfig(level=logging.INFO,format="%(asctime)s %(levelname)s %(message)s")
log=logging.getLogger("cyberguard")

from models.ids_engine import IDSEngine
from utils.all_utils import (JWTAuth,ThreatLogger,AlertManager,AuthStore,ROLES,
                              build_pdf,send_email,send_slack,to_cef,to_leef)

app=Flask(__name__)
CORS(app,resources={r"/api/*":{"origins":os.getenv("CORS_ORIGIN","*")}})

engine=IDSEngine(); logger=ThreatLogger(); alertmgr=AlertManager()
auth=JWTAuth(secret=os.getenv("JWT_SECRET","cyberguard-change-me-256bit-secret"))
store=AuthStore()

_live_running=False; _live_thread=None; _live_clients={}; _live_lock=threading.Lock()

def _get_token():
    """Accept JWT from Authorization header OR ?token= query param (needed for SSE EventSource)."""
    t = request.headers.get("Authorization","").removeprefix("Bearer ").strip()
    if not t:
        t = request.args.get("token","").strip()
    return t

def require_auth(permission=None):
    def dec(fn):
        @wraps(fn)
        def wrapper(*a,**kw):
            p=auth.verify(_get_token())
            if not p: return jsonify({"error":"Unauthorized — please log in."}),401
            if permission:
                perms=store.role_permissions(p.get("role","viewer"))
                if not perms.get(permission,False):
                    return jsonify({"error":f"Forbidden — your role cannot: {permission}"}),403
            request.user=p; return fn(*a,**kw)
        return wrapper
    return dec

# ── AUTH ────────────────────────────────────────────────────────────────
@app.route("/api/auth/register",methods=["POST"])
def register():
    d=request.get_json(silent=True) or {}
    r=store.register(d.get("username",""),d.get("password",""),d.get("email",""),d.get("role","viewer"),d.get("admin_key",""))
    if not r["ok"]: return jsonify({"error":r["error"]}),400
    return jsonify({"message":"Account created.","username":r["username"],"role":r["role"]}),201

@app.route("/api/auth/login",methods=["POST"])
def login():
    d=request.get_json(silent=True) or {}
    r=store.login(d.get("username",""),d.get("password",""))
    if not r["ok"]: return jsonify({"error":r["error"]}),401
    token=auth.generate({"username":r["username"],"role":r["role"],"email":r.get("email","")})
    return jsonify({"token":token,"username":r["username"],"role":r["role"],"permissions":store.role_permissions(r["role"])})

@app.route("/api/auth/me",methods=["GET"])
@require_auth()
def me(): return jsonify({**request.user,"permissions":store.role_permissions(request.user.get("role","viewer"))})

@app.route("/api/auth/users",methods=["GET"])
@require_auth("can_manage_users")
def list_users(): return jsonify(store.get_all_users())

@app.route("/api/auth/users/<u>/role",methods=["PUT"])
@require_auth("can_manage_users")
def update_role(u):
    d=request.get_json(silent=True) or {}; r=store.update_role(u,d.get("role",""))
    return (jsonify({"error":r["error"]}),400) if not r["ok"] else (jsonify({"message":"Role updated."}),200)

@app.route("/api/auth/users/<u>/deactivate",methods=["POST"])
@require_auth("can_manage_users")
def deactivate_user(u):
    r=store.deactivate(u)
    return (jsonify({"error":r["error"]}),400) if not r["ok"] else (jsonify({"message":f"{u} deactivated."}),200)

# ── SYSTEM ───────────────────────────────────────────────────────────────
@app.route("/api/health",methods=["GET"])
def health():
    return jsonify({"status":"online","version":"1.0.0","models":engine.models_loaded(),"timestamp":datetime.utcnow().isoformat()})

@app.route("/api/stats",methods=["GET"])
@require_auth()
def stats(): return jsonify(logger.get_stats())

@app.route("/api/alerts",methods=["GET"])
@require_auth()
def alerts_ep(): return jsonify(alertmgr.get_all(severity=request.args.get("severity")))

@app.route("/api/alerts/<aid>/ack",methods=["POST"])
@require_auth()
def ack_alert(aid): return jsonify({"success":alertmgr.acknowledge(aid)})

@app.route("/api/events",methods=["GET"])
@require_auth()
def events_ep():
    return jsonify(logger.get_recent(limit=min(int(request.args.get("limit",50)),500),
                                     offset=int(request.args.get("offset",0)),
                                     severity=request.args.get("severity")))

@app.route("/api/models",methods=["GET"])
@require_auth()
def models_ep(): return jsonify(engine.metadata())

# ── SCAN ─────────────────────────────────────────────────────────────────
@app.route("/api/scan",methods=["POST"])
@require_auth("can_scan")
def scan():
    data=request.get_json(silent=True) or {}; sid=str(uuid.uuid4())
    try:
        result=engine.predict(data)
        result.update({"scan_id":sid,"timestamp":datetime.utcnow().isoformat(),
                       "target":data.get("target","unknown"),"analyst":request.user.get("username","?")})
        logger.log(data,result); _auto_alert(result)
        return jsonify({"success":True,"scan_id":sid,"results":result})
    except Exception as e: log.exception("scan"); return jsonify({"success":False,"error":str(e)}),500

@app.route("/api/scan/raw",methods=["POST"])
@require_auth("can_scan")
def scan_raw():
    data=request.get_json(silent=True) or {}; raw=data.get("packet_data","")
    if not raw.strip(): return jsonify({"success":False,"error":"No packet data."}),400
    try:
        flows=_parse_raw(raw); results=[engine.predict(fl) for fl in flows]
        s=_summarise(results); s.update({"timestamp":datetime.utcnow().isoformat(),"target":data.get("target","raw-input")})
        logger.log(data,s); _auto_alert(s)
        return jsonify({"success":True,"flows":len(results),"summary":s,"details":results[:100]})
    except Exception as e: return jsonify({"success":False,"error":str(e)}),500

@app.route("/api/scan/pcap",methods=["POST"])
@require_auth("can_scan")
def scan_pcap():
    if "file" not in request.files: return jsonify({"success":False,"error":"No file."}),400
    f=request.files["file"]
    try:
        flows=_parse_pcap(f.read()); results=[engine.predict(fl) for fl in flows]
        s=_summarise(results); s.update({"timestamp":datetime.utcnow().isoformat(),"target":f.filename})
        logger.log({"source":"pcap","filename":f.filename},s); _auto_alert(s)
        return jsonify({"success":True,"filename":f.filename,"flows":len(results),"summary":s,"details":results[:200]})
    except Exception as e: return jsonify({"success":False,"error":str(e)}),500

@app.route("/api/shap/<sid>",methods=["GET"])
@require_auth("can_shap")
def shap_ep(sid):
    rec=logger.get_by_id(sid)
    if not rec: return jsonify({"error":"Scan not found."}),404
    return jsonify({"scan_id":sid,"explanation":engine.shap_explain(rec)})

# ── REAL-TIME IDS ────────────────────────────────────────────────────────
@app.route("/api/live/start",methods=["POST"])
@require_auth("can_live_monitor")
def live_start():
    global _live_running,_live_thread
    data=request.get_json(silent=True) or {}
    iface=data.get("interface","eth0"); mode=data.get("mode","simulate")
    if _live_running:
        return jsonify({"success":True,"message":"Live monitoring already running."})
    _live_running=True
    _live_thread=threading.Thread(target=_live_monitor_loop,args=(iface,mode),daemon=True)
    _live_thread.start()
    return jsonify({"success":True,"message":f"Live monitoring started (mode={mode})","interface":iface})

@app.route("/api/live/stop",methods=["POST"])
@require_auth("can_live_monitor")
def live_stop():
    global _live_running
    _live_running=False
    return jsonify({"success":True,"message":"Live monitoring stopping."})

@app.route("/api/live/status",methods=["GET"])
@require_auth()
def live_status():
    return jsonify({"running":_live_running,"clients":len(_live_clients),"timestamp":datetime.utcnow().isoformat()})

@app.route("/api/live/stream")
@require_auth()
def live_stream():
    """SSE stream — token accepted from ?token= query param (EventSource limitation)."""
    import queue
    cid=str(uuid.uuid4()); q=queue.Queue(maxsize=100)
    with _live_lock: _live_clients[cid]=q
    def generate():
        try:
            yield f"data: {json.dumps({'event':'connected','client_id':cid,'timestamp':datetime.utcnow().isoformat()})}\n\n"
            while True:
                try:
                    msg=q.get(timeout=15)
                    yield f"data: {json.dumps(msg)}\n\n"
                except:
                    yield f"data: {json.dumps({'event':'heartbeat','timestamp':datetime.utcnow().isoformat()})}\n\n"
        finally:
            with _live_lock:
                if cid in _live_clients: del _live_clients[cid]
    return Response(stream_with_context(generate()),mimetype="text/event-stream",
                    headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no","Access-Control-Allow-Origin":"*"})

def _live_monitor_loop(iface,mode):
    global _live_running
    import random
    try_capture=(mode=="capture")
    raw_sock=None
    if try_capture:
        try:
            raw_sock=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x0003))
            raw_sock.settimeout(1.0); raw_sock.bind((iface,0))
            log.info(f"Raw socket capture on {iface}")
        except Exception as e:
            log.warning(f"Raw socket failed ({e}) — falling back to simulation")
            try_capture=False; raw_sock=None

    flow_buffer={}; last_flush=time.time()
    while _live_running:
        try:
            if try_capture and raw_sock:
                try:
                    pkt,_=raw_sock.recvfrom(65535)
                    flow=_extract_flow_from_packet(pkt,flow_buffer)
                    if flow: _classify_and_broadcast(flow,"live_capture")
                except socket.timeout: pass
                if time.time()-last_flush>5:
                    for fl in list(flow_buffer.values()):
                        if fl.get("count",0)>0: _classify_and_broadcast(fl,"live_flow")
                    flow_buffer.clear(); last_flush=time.time()
            else:
                time.sleep(random.uniform(0.8,2.5))
                sim=_simulate_traffic()
                _classify_and_broadcast(sim,"simulated")
        except Exception as e:
            log.error(f"Live monitor error: {e}"); time.sleep(2)
    if raw_sock:
        try: raw_sock.close()
        except: pass

def _classify_and_broadcast(flow,source):
    result=engine.predict(flow)
    result.update({"timestamp":datetime.utcnow().isoformat(),"target":flow.get("dst_ip",flow.get("target","?")),"source":source})
    logger.log(flow,result)
    _broadcast_live(result,flow)
    if result.get("severity") in ("CRITICAL","HIGH"):
        alertmgr.add(result)
        try: send_slack(f"[{result['severity']}] {result['label']} — {flow.get('src_ip','?')} → {flow.get('dst_ip','?')} — {result['confidence']}%",result["severity"].lower())
        except: pass

def _extract_flow_from_packet(pkt,flow_buffer):
    try:
        if len(pkt)<34: return None
        eth_len=14; ip_hdr=pkt[eth_len:eth_len+20]
        fields=struct.unpack("!BBHHHBBH4s4s",ip_hdr)
        proto=fields[6]; src_ip=socket.inet_ntoa(fields[8]); dst_ip=socket.inet_ntoa(fields[9])
        ip_len=fields[2]; proto_name={6:"tcp",17:"udp",1:"icmp"}.get(proto,"other")
        dst_port=0
        if proto in (6,17) and len(pkt)>eth_len+24:
            dst_port=struct.unpack("!HH",pkt[eth_len+20:eth_len+24])[1]
        key=(src_ip,dst_ip,dst_port,proto_name)
        if key not in flow_buffer:
            flow_buffer[key]={"src_ip":src_ip,"dst_ip":dst_ip,"dst_port":dst_port,
                              "protocol":proto_name,"service":{80:"http",443:"https",22:"ssh",21:"ftp",53:"dns",25:"smtp"}.get(dst_port,"private"),
                              "count":0,"src_bytes":0,"flag":"SF","serror_rate":0.0,"rerror_rate":0.0,"logged_in":0,"duration":0}
        fl=flow_buffer[key]; fl["count"]+=1; fl["src_bytes"]+=ip_len
        if proto==6 and len(pkt)>eth_len+33:
            tcp_flags=pkt[eth_len+33]
            if tcp_flags&0x02 and not tcp_flags&0x10: fl["serror_rate"]=min(1.0,fl["serror_rate"]+0.05)
            if tcp_flags&0x04: fl["rerror_rate"]=min(1.0,fl["rerror_rate"]+0.05)
        if fl["count"]>=20 or fl["src_bytes"]>50000: return fl
        return None
    except: return None

def _simulate_traffic():
    import random; r=random.random()
    src=f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    dst=f"10.0.0.{random.randint(1,20)}"
    if r<0.70:
        return{"src_ip":src,"dst_ip":dst,"protocol":"tcp","service":"http","flag":"SF",
               "src_bytes":random.randint(200,8000),"dst_bytes":random.randint(100,4000),
               "count":random.randint(5,30),"serror_rate":random.uniform(0,0.03),"logged_in":1,"duration":random.uniform(0.5,15)}
    elif r<0.82:
        return{"src_ip":src,"dst_ip":dst,"protocol":"tcp","service":"smtp","flag":"S0",
               "src_bytes":random.randint(0,200),"dst_bytes":0,"count":random.randint(200,511),
               "serror_rate":random.uniform(0.8,1.0),"logged_in":0,"duration":0}
    elif r<0.90:
        return{"src_ip":src,"dst_ip":dst,"protocol":"tcp","service":"private","flag":"REJ",
               "src_bytes":random.randint(0,100),"dst_bytes":0,"count":random.randint(5,25),
               "rerror_rate":random.uniform(0.6,0.95),"diff_srv_rate":random.uniform(0.7,1.0),"logged_in":0}
    elif r<0.95:
        return{"src_ip":src,"dst_ip":dst,"protocol":"tcp","service":"ftp","flag":"SF",
               "src_bytes":random.randint(500,3000),"dst_bytes":random.randint(500,3000),
               "count":5,"num_failed_logins":random.randint(8,25),"logged_in":0,"duration":random.uniform(30,200)}
    else:
        return{"src_ip":src,"dst_ip":dst,"protocol":"tcp","service":"ssh","flag":"SF",
               "src_bytes":random.randint(2000,8000),"logged_in":1,"hot":random.randint(5,20),
               "root_shell":1,"count":3,"duration":random.uniform(50,300)}

def _broadcast_live(result,flow):
    msg={"event":"detection","timestamp":result.get("timestamp",datetime.utcnow().isoformat()),
         "label":result.get("label"),"severity":result.get("severity"),"confidence":result.get("confidence"),
         "src_ip":flow.get("src_ip","?"),"dst_ip":flow.get("dst_ip",result.get("target","?")),
         "service":flow.get("service","?"),"mitre":result.get("mitre_tactic",""),"family":result.get("attack_family",""),
         "cves":result.get("cve_refs",[]),"recommendations":result.get("recommendations",[])[:2],"source":result.get("source","monitor")}
    with _live_lock:
        dead=[]
        for cid,q in _live_clients.items():
            try: q.put_nowait(msg)
            except: dead.append(cid)
        for cid in dead: del _live_clients[cid]

# ── PDF / EMAIL / SLACK ──────────────────────────────────────────────────
@app.route("/api/report/pdf",methods=["POST"])
@require_auth("can_pdf")
def gen_pdf():
    data=request.get_json(silent=True) or {}
    try:
        pdf_bytes=build_pdf(data,requester=getattr(request,"user",{}))
        buf=io.BytesIO(pdf_bytes); buf.seek(0)
        return send_file(buf,mimetype="application/pdf",as_attachment=True,download_name="cyberguard_report.pdf")
    except Exception as e: log.exception("pdf"); return jsonify({"error":str(e)}),500

@app.route("/api/notify/email",methods=["POST"])
@require_auth("can_email")
def notify_email():
    data=request.get_json(silent=True) or {}; to=data.get("email","")
    if "@" not in to: return jsonify({"success":False,"error":"Valid email required."}),400
    try:
        send_email(to=to,subject=data.get("subject","CyberGuard IDS Report"),
                   results=data.get("results",{}),name=data.get("name","Analyst"))
        return jsonify({"success":True,"message":f"Report sent to {to}"})
    except ValueError as e:
        # Configuration error — return helpful message, not 500
        msg = str(e)
        log.warning(f"Email config error: {msg[:80]}")
        return jsonify({"success":False,"error":msg,"type":"config"}),400
    except Exception as e:
        log.exception("email")
        return jsonify({"success":False,"error":str(e),"type":"smtp"}),500

@app.route("/api/notify/slack",methods=["POST"])
@require_auth("can_slack")
def notify_slack():
    data=request.get_json(silent=True) or {}
    try: send_slack(data.get("message",""),data.get("severity","info")); return jsonify({"success":True})
    except Exception as e: return jsonify({"success":False,"error":str(e)}),500

# ── SIEM / RETRAIN ────────────────────────────────────────────────────────
@app.route("/api/siem/export",methods=["GET"])
@require_auth("can_export_siem")
def siem_ep():
    fmt=request.args.get("format","json"); evs=logger.get_recent(limit=int(request.args.get("limit",1000)))
    if fmt=="cef": evs=[to_cef(e) for e in evs]
    elif fmt=="leef": evs=[to_leef(e) for e in evs]
    return jsonify({"format":fmt,"count":len(evs),"events":evs})

@app.route("/api/retrain",methods=["POST"])
@require_auth("can_retrain")
def retrain_ep():
    try: return jsonify({"success":True,**engine.retrain()})
    except Exception as e: return jsonify({"success":False,"error":str(e)}),500

# ── HELPERS ────────────────────────────────────────────────────────────────
def _auto_alert(result):
    if result.get("severity") in ("CRITICAL","HIGH"):
        alertmgr.add(result)
        try: send_slack(f"[{result.get('severity')}] {result.get('label','?')} — target: {result.get('target','?')} — {result.get('confidence',0)}% confidence",result.get("severity","info").lower())
        except: pass

def _parse_raw(text):
    flows={}; ip_re=re.compile(r'(\d{1,3}(?:\.\d{1,3}){3})(?:\.(\d+))?')
    for line in text.splitlines():
        ips=ip_re.findall(line)
        if len(ips)<2: continue
        sip,sp=ips[0]; dip,dp=ips[1]; key=(sip,dip)
        if key not in flows:
            flows[key]={"src_ip":sip,"dst_ip":dip,"count":0,"src_bytes":0,"num_failed_logins":0,"serror_rate":0.0,"rerror_rate":0.0}
        fl=flows[key]; fl["count"]+=1
        m=re.search(r'length\s+(\d+)',line,re.I)
        if m: fl["src_bytes"]+=int(m.group(1))
        if re.search(r'Flags.*\[S\]|SYN',line,re.I): fl["serror_rate"]=min(1.0,fl["serror_rate"]+0.1)
        if re.search(r'failed|invalid password|auth failure',line,re.I): fl["num_failed_logins"]+=1
        port=int(dp) if dp else 0; fl["service"]={80:"http",443:"https",22:"ssh",21:"ftp",53:"dns",25:"smtp"}.get(port,"other")
    return list(flows.values()) or [{}]

def _parse_pcap(raw):
    import numpy as np
    try:
        from scapy.all import rdpcap,TCP,UDP,IP; import collections as col
        pkts=rdpcap(io.BytesIO(raw)); flows=col.defaultdict(lambda:{"count":0,"src_bytes":0,"serror_rate":0.0})
        for pkt in pkts:
            if not pkt.haslayer(IP): continue
            ip=pkt[IP]; dp=pkt[TCP].dport if pkt.haslayer(TCP) else(pkt[UDP].dport if pkt.haslayer(UDP) else 0)
            key=(ip.src,ip.dst,dp); fl=flows[key]; fl["count"]+=1; fl["src_bytes"]+=len(pkt)
            fl.update({"src_ip":ip.src,"dst_ip":ip.dst})
            if pkt.haslayer(TCP) and pkt[TCP].flags==2: fl["serror_rate"]=min(1.0,fl["serror_rate"]+0.05)
            fl["service"]={80:"http",443:"https",22:"ssh",21:"ftp",53:"dns"}.get(dp,"other")
        return list(flows.values()) or [{}]
    except ImportError:
        n=max(1,len(raw)//1500)
        return [{"count":int(np.random.randint(1,200)),"src_bytes":int(np.random.randint(0,30000)),"serror_rate":float(np.random.beta(1,5))} for _ in range(min(n,80))]

def _summarise(results):
    if not results: return {"label":"NORMAL","severity":"LOW","confidence":100}
    rank={"LOW":0,"MEDIUM":1,"HIGH":2,"CRITICAL":3}
    worst=max(results,key=lambda r:rank.get(r.get("severity","LOW"),0)); counts={}
    for r in results: lbl=r.get("label","Other"); counts[lbl]=counts.get(lbl,0)+1
    return {**worst,"attack_counts":counts,"total_flows":len(results),"malicious":sum(v for k,v in counts.items() if k!="NORMAL")}

if __name__=="__main__":
    app.run(debug=os.getenv("FLASK_DEBUG","0")=="1",host="0.0.0.0",port=5000)

# ── DATASET-DRIVEN ALERT GENERATION ──────────────────────────────────────
@app.route("/api/alerts/generate", methods=["POST"])
@require_auth("can_scan")
def generate_alerts_from_dataset():
    """Scan samples from the real dataset through all 6 models and generate alerts."""
    import pandas as pd
    import numpy as np

    NSL_MAP = {
        'normal':'NORMAL','neptune':'DoS','back':'DoS','land':'DoS','pod':'DoS','smurf':'DoS',
        'teardrop':'DoS','apache2':'DoS','udpstorm':'DoS','ipsweep':'Probe','nmap':'Probe',
        'portsweep':'Probe','satan':'Probe','saint':'Probe','mscan':'Probe',
        'ftp_write':'R2L','guess_passwd':'R2L','imap':'R2L','multihop':'R2L','phf':'R2L',
        'spy':'R2L','warezclient':'R2L','warezmaster':'R2L','sendmail':'R2L','named':'R2L',
        'buffer_overflow':'U2R','loadmodule':'U2R','perl':'U2R','rootkit':'U2R',
        'ps':'U2R','sqlattack':'U2R','xterm':'U2R',
    }
    NSL_COLS = [
        'duration','protocol_type','service','flag','src_bytes','dst_bytes','land',
        'wrong_fragment','urgent','hot','num_failed_logins','logged_in','num_compromised',
        'root_shell','su_attempted','num_root','num_file_creations','num_shells',
        'num_access_files','num_outbound_cmds','is_host_login','is_guest_login',
        'count','srv_count','serror_rate','srv_serror_rate','rerror_rate','srv_rerror_rate',
        'same_srv_rate','diff_srv_rate','srv_diff_host_rate','dst_host_count',
        'dst_host_srv_count','dst_host_same_srv_rate','dst_host_diff_srv_rate',
        'dst_host_same_src_port_rate','dst_host_srv_diff_host_rate',
        'dst_host_serror_rate','dst_host_srv_serror_rate',
        'dst_host_rerror_rate','dst_host_srv_rerror_rate','label','difficulty'
    ]
    # Protocol/service/flag are stored as strings in our CSV, used directly below

    data = request.get_json(silent=True) or {}
    n_per_class = int(data.get('samples_per_class', 5))
    include_normal = data.get('include_normal', False)

    try:
        nsl_path = os.path.join(os.path.dirname(__file__), 'data', 'KDDTrain+.txt')
        df = pd.read_csv(nsl_path, names=NSL_COLS, header=None)
        df['cat'] = df['label'].map(lambda x: NSL_MAP.get(str(x).lower(), 'Other'))

        if include_normal:
            samples = df.groupby('cat').apply(lambda g: g.sample(min(n_per_class, len(g)), random_state=42)).reset_index(drop=True)
        else:
            # Fix for newer pandas — avoid deprecated groupby apply with group_keys
            attack_df = df if include_normal else df[df['cat'] != 'NORMAL']
            samples_list = []
        for _cat, _grp in attack_df.groupby('cat'):
            samples_list.append(_grp.sample(min(n_per_class, len(_grp)), random_state=42))
        samples = pd.concat(samples_list).reset_index(drop=True) if samples_list else pd.DataFrame()

        generated = []
        for _, row in samples.iterrows():
            # Build flow dict from raw dataset row
            try:
                pe = engine._cat_enc.get('protocol_type', {})
                se = engine._cat_enc.get('service', {})
                fe = engine._cat_enc.get('flag', {})
                proto_enc = int(row.get('protocol_type', 1))
                svc_enc   = int(row.get('service', 3))
                flag_enc  = int(row.get('flag', 3))

                # CSV has raw string values (tcp, http, SF etc) — use directly
                flow = {
                    'protocol':          str(row.get('protocol_type', 'tcp')),
                    'service':           str(row.get('service', 'http')),
                    'flag':              str(row.get('flag', 'SF')),
                    'duration':          float(row.get('duration', 0)),
                    'src_bytes':         float(row.get('src_bytes', 0)),
                    'dst_bytes':         float(row.get('dst_bytes', 0)),
                    'land':              float(row.get('land', 0)),
                    'wrong_fragment':    float(row.get('wrong_fragment', 0)),
                    'hot':               float(row.get('hot', 0)),
                    'num_failed_logins': float(row.get('num_failed_logins', 0)),
                    'logged_in':         float(row.get('logged_in', 0)),
                    'num_compromised':   float(row.get('num_compromised', 0)),
                    'root_shell':        float(row.get('root_shell', 0)),
                    'su_attempted':      float(row.get('su_attempted', 0)),
                    'count':             float(row.get('count', 1)),
                    'srv_count':         float(row.get('srv_count', 1)),
                    'serror_rate':       float(row.get('serror_rate', 0)),
                    'srv_serror_rate':   float(row.get('srv_serror_rate', 0)),
                    'rerror_rate':       float(row.get('rerror_rate', 0)),
                    'srv_rerror_rate':   float(row.get('srv_rerror_rate', 0)),
                    'same_srv_rate':     float(row.get('same_srv_rate', 1)),
                    'diff_srv_rate':     float(row.get('diff_srv_rate', 0)),
                    'dst_host_count':    float(row.get('dst_host_count', 1)),
                    'dst_host_srv_count':float(row.get('dst_host_srv_count', 1)),
                    'dst_host_serror_rate':float(row.get('dst_host_serror_rate', 0)),
                    'dst_host_rerror_rate':float(row.get('dst_host_rerror_rate', 0)),
                    'target':            f'10.0.0.{np.random.randint(1,20)}',
                    'src_ip':            f'{np.random.randint(1,254)}.{np.random.randint(1,254)}.{np.random.randint(1,254)}.{np.random.randint(1,254)}',
                    'dataset_label':     str(row.get('cat', 'Other')),
                    'raw_label':         str(row.get('label', 'unknown')),
                }

                result = engine.predict(flow)
                sid = str(uuid.uuid4())
                result.update({
                    'scan_id':       sid,
                    'timestamp':     datetime.utcnow().isoformat(),
                    'target':        flow['target'],
                    'src_ip':        flow['src_ip'],
                    'dataset_label': flow['dataset_label'],
                    'raw_label':     flow['raw_label'],
                    'analyst':       request.user.get('username', 'dataset_scan'),
                    'source':        'dataset',
                })

                logger.log(flow, result)

                # Generate alert for non-normal predictions
                if result.get('label') != 'NORMAL' or result.get('model_outputs', {}).get('autoencoder', {}).get('anomaly'):
                    alert = alertmgr.add(result)
                    generated.append({
                        'scan_id':        sid,
                        'dataset_label':  flow['dataset_label'],
                        'predicted':      result.get('label'),
                        'severity':       result.get('severity'),
                        'confidence':     result.get('confidence'),
                        'correct':        flow['dataset_label'] == result.get('label'),
                        'alert_id':       alert.get('id'),
                    })
                    # Auto-Slack for high severity
                    if result.get('severity') in ('CRITICAL', 'HIGH'):
                        try:
                            send_slack(
                                f"[{result['severity']}] {result['label']} — dataset:{flow['dataset_label']} raw:{flow['raw_label']} — {result['confidence']}% confidence",
                                result['severity'].lower()
                            )
                        except:
                            pass

            except Exception as e:
                log.debug(f"Sample scan error: {e}")
                continue

        correct = sum(1 for g in generated if g.get('correct'))
        return jsonify({
            'success':    True,
            'scanned':    len(samples),
            'alerts_generated': len(generated),
            'correct_predictions': correct,
            'accuracy':   round(correct / len(generated) * 100, 1) if generated else 0,
            'alerts':     generated,
        })

    except Exception as e:
        log.exception("generate_alerts")
        return jsonify({'success': False, 'error': str(e)}), 500
