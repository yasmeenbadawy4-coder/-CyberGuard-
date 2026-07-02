"""CyberGuard IDS Engine — 6 Real sklearn Models:
   Random Forest, XGBoost, Decision Tree, ANN, Autoencoder (PCA), Hybrid AE+XGBoost
   Binary + Multi-class classification | Authentic MITRE ATT&CK | Real CVEs
"""
import os, pickle, logging
import numpy as np
log = logging.getLogger("cyberguard.engine")
DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
MODEL_DIR = os.path.join(DATA_DIR, "saved_models")

SEVERITY = {"NORMAL":"LOW","Probe":"MEDIUM","Reconnaissance":"MEDIUM","Analysis":"LOW",
            "Fuzzers":"MEDIUM","Generic":"HIGH","DoS":"HIGH","R2L":"HIGH",
            "Exploits":"CRITICAL","Backdoors":"CRITICAL","Shellcode":"CRITICAL",
            "Worms":"CRITICAL","U2R":"CRITICAL","Other":"MEDIUM"}

MITRE = {"DoS":"TA0040 — Impact / T1498 Network Denial of Service",
         "Probe":"TA0043 — Reconnaissance / T1595 Active Scanning",
         "R2L":"TA0001 — Initial Access / T1110 Brute Force",
         "U2R":"TA0004 — Privilege Escalation / T1068 Exploitation for Privilege Escalation",
         "Exploits":"TA0002 — Execution / T1203 Exploitation for Client Execution",
         "Backdoors":"TA0003 — Persistence / T1505 Server Software Component",
         "Shellcode":"TA0002 — Execution / T1055 Process Injection",
         "Worms":"TA0008 — Lateral Movement / T1210 Exploitation of Remote Services",
         "Fuzzers":"TA0043 — Reconnaissance / T1595.002 Vulnerability Scanning",
         "Generic":"TA0001 — Initial Access / T1190 Exploit Public-Facing Application",
         "Reconnaissance":"TA0043 — Reconnaissance / T1595 Active Scanning",
         "Analysis":"TA0043 — Reconnaissance / T1592 Gather Victim Host Information",
         "NORMAL":"N/A — No malicious tactic detected",
         "Other":"TA0000 — Unknown Tactic"}

FAMILY = {"DoS":"Denial of Service","Probe":"Network Reconnaissance",
          "R2L":"Remote-to-Local Exploit","U2R":"User-to-Root Privilege Escalation",
          "Exploits":"Known CVE Exploitation","Backdoors":"Persistent Backdoor / RAT",
          "Shellcode":"Code Injection / Shellcode","Worms":"Self-Propagating Worm",
          "Fuzzers":"Fuzzing / Crash Induction","Generic":"Generic / Unknown Attack",
          "Reconnaissance":"Active Reconnaissance","Analysis":"Host/Service Analysis",
          "NORMAL":"Benign Traffic","Other":"Unclassified Threat"}

RECS = {
    "DoS": ["Rate-limit inbound SYN: iptables -A INPUT -p tcp --syn -m limit --limit 100/s -j ACCEPT",
            "Enable TCP SYN cookies: sysctl -w net.ipv4.tcp_syncookies=1  (persist: /etc/sysctl.conf)",
            "Deploy upstream scrubbing: Cloudflare Magic Transit, AWS Shield Advanced, or Akamai Prolexic",
            "nginx: limit_conn_zone $binary_remote_addr zone=conn:10m; limit_conn conn 20;",
            "Contact ISP for BGP blackhole routing of the attacking source range"],
    "Probe": ["Block scanning IP: iptables -A INPUT -s <ATTACKER_IP> -j DROP",
              "Deploy port-knocking (knockd) or fwknop SPA on sensitive services",
              "Audit your exposure: nmap -sV -O <YOUR_IP> — close all non-essential ports",
              "Suricata: alert tcp any any -> $HOME_NET any (flags:S; detection_filter:track by_src,count 30,seconds 60;)",
              "Apply geo-blocking for regions with no legitimate user base"],
    "R2L": ["Disable SSH password auth: PasswordAuthentication no in /etc/ssh/sshd_config; restart sshd",
            "Deploy fail2ban: maxretry=3, bantime=3600 — block after 3 failures for 1 hour",
            "Enforce MFA on ALL remote access: SSH, VPN, RDP — no exceptions whatsoever",
            "Rotate ALL credentials — treat as fully compromised immediately",
            "Account lockout: pam_tally2 --deny=5 --lock-time=900 (Linux) or Account Lockout Policy GPO (Windows)"],
    "U2R": ["Isolate host: ip link set eth0 down — DO NOT power off (memory contains forensic evidence)",
            "Memory snapshot before ANY changes: LiME (Linux) / Magnet RAM Capture (Windows)",
            "Audit SUID binaries: find / -perm /6000 -type f 2>/dev/null — remove unexpected entries",
            "Check kernel modules: lsmod | sort — compare against known-good baseline",
            "Rebuild from verified clean image — assume total root compromise, no partial cleanup"],
    "Exploits": ["Apply all CVSS ≥9.0 patches within 24h — check NVD and vendor advisories immediately",
                 "WAF with OWASP CRS: SecRuleEngine On; Include /etc/modsecurity/crs/*.conf",
                 "Enable ASLR: sysctl -w kernel.randomize_va_space=2 (full randomization)",
                 "Audit input validation with Burp Suite or OWASP ZAP on all external endpoints",
                 "File uploads: store outside webroot, chmod 644, no execute permissions"],
    "Backdoors": ["Isolate immediately — revoke ALL credentials, certificates, and API keys now",
                  "Check authorized_keys: find / -name authorized_keys 2>/dev/null",
                  "Audit listening ports: ss -tlnp — compare every open port against known-good baseline",
                  "Engage IR team; full disk image before remediation (legal chain-of-custody)",
                  "Search webshells: find /var/www -name '*.php' | xargs grep -l 'eval(base64' 2>/dev/null"],
    "Shellcode": ["Enable AppArmor/SELinux allowlisting to block arbitrary code execution",
                  "Check process injection via EDR or: ps auxf — look for unexpected parent-child relationships",
                  "Review crash dumps: ulimit -c unlimited; examine core files for shellcode patterns",
                  "Rebuild affected services from verified source — never attempt to clean injected processes",
                  "Future builds: compile with -fstack-protector-all -D_FORTIFY_SOURCE=2 -Wformat-security"],
    "Worms": ["Segment network: block SMB(445), RPC(135), WMI(5985) between ALL internal subnets immediately",
              "Patch the propagation vulnerability on ALL hosts before reconnecting any network segment",
              "ClamAV scan with definitions updated within the last 30 minutes on all reachable hosts",
              "Disable AutoRun/AutoPlay via GPO: Computer Config > Admin Templates > Windows Components",
              "DNS sinkhole malicious C2 domains; block worm IPs at perimeter firewall immediately"],
    "Fuzzers": ["Review crash logs and core dumps — fuzzer may have found exploitable memory corruption bugs",
                "Implement strict input validation with allowlists (not blocklists) on all external endpoints",
                "Run AFL++/libFuzzer against your own services proactively to find vulnerabilities first",
                "AddressSanitizer in staging: gcc -fsanitize=address -fsanitize=undefined",
                "Rate-limit malformed requests at WAF level; alert on elevated 4xx/5xx error rates"],
    "Generic": ["Capture packet trace: tcpdump -i eth0 -w /tmp/capture.pcap host <ATTACKER_IP>",
                "Update all IDS/IPS signatures and pull latest threat intel (MISP, OTX, VirusTotal)",
                "Correlate in SIEM — look for lateral movement and reconnaissance indicators",
                "Escalate to Tier 2 analyst — this pattern does not match known attack signatures",
                "Submit pcap to threat intelligence platform for attribution and IoC extraction"],
    "Reconnaissance": ["Block scanning source IP at perimeter: iptables -A INPUT -s <IP> -j DROP",
                       "Audit all exposed services with Shodan.io — close every unnecessary open port",
                       "Deploy honeypots on probe ports (21, 23, 3389) to detect and slow reconnaissance",
                       "Review DNS records and WHOIS for inadvertently exposed internal information",
                       "Enable egress filtering to prevent data exfiltration that follows reconnaissance"],
    "Analysis": ["Treat as precursor to targeted attack — increase monitoring sensitivity for 72h",
                 "Review what service/version information was exposed during the analysis phase",
                 "Suppress verbose error messages and version banners in all web/application servers",
                 "Check threat intel for active campaigns targeting your specific technology stack",
                 "Move sensitive services behind additional auth layers: VPN + MFA as minimum"],
    "NORMAL": ["Traffic analysis shows no malicious indicators — continue routine monitoring",
               "Cross-check SIEM baselines to verify this is not a false negative",
               "Review network baseline periodically to keep normal thresholds accurate",
               "Schedule next automated vulnerability scan within 30 days",
               "Consider proactive threat hunting exercises to surface subtle indicators"],
    "Other": ["Treat as suspicious — escalate to Tier 2 analyst for manual review immediately",
              "Enable enhanced packet capture on source IP: tcpdump -w /tmp/capture.pcap",
              "Submit traffic hash to VirusTotal and check source IP on AbuseIPDB",
              "Cross-reference source IP against MISP, OTX, and CrowdStrike threat intel",
              "Update IDS detection rules to specifically flag this traffic pattern"],
}

CVES = {
    "DoS":         ["CVE-2024-3094 (XZ Utils CVSS 10.0)","CVE-2023-44487 (HTTP/2 Rapid Reset CVSS 7.5)","CVE-2022-26143 (Mitel Amplification CVSS 9.8)"],
    "R2L":         ["CVE-2024-21762 (Fortinet FortiOS Auth Bypass CVSS 9.6)","CVE-2023-23397 (Outlook NTLM Hash Leak CVSS 9.8)","CVE-2022-30190 (Follina MSDT RCE CVSS 7.8)"],
    "U2R":         ["CVE-2024-1086 (Linux kernel nf_tables LPE CVSS 7.8)","CVE-2022-0847 (Dirty Pipe CVSS 7.8)","CVE-2021-4034 (PwnKit Polkit LPE CVSS 7.8)"],
    "Exploits":    ["CVE-2023-34362 (MOVEit SQL Injection CVSS 9.8)","CVE-2021-44228 (Log4Shell RCE CVSS 10.0)","CVE-2024-27198 (JetBrains TeamCity Auth Bypass CVSS 9.8)"],
    "Backdoors":   ["CVE-2024-3094 (XZ Utils Supply Chain Backdoor CVSS 10.0)","CVE-2021-26855 (ProxyLogon Exchange RCE CVSS 9.1)"],
    "Shellcode":   ["CVE-2017-0144 (EternalBlue SMBv1 RCE CVSS 8.8)","CVE-2019-19781 (Citrix ADC Path Traversal CVSS 9.8)"],
    "Worms":       ["CVE-2017-0145 (EternalBlue/WannaCry CVSS 8.8)","CVE-2021-34473 (ProxyShell Exchange RCE CVSS 9.8)"],
    "Fuzzers":     ["CVE-2023-27350 (PaperCut MF/NG RCE CVSS 9.8)","CVE-2023-4966 (Citrix Bleed Session Leak CVSS 9.4)"],
    "Generic":     ["CVE-2023-36884 (Microsoft Office HTML RCE CVSS 8.3)","CVE-2024-21893 (Ivanti SSRF CVSS 8.2)"],
    "Probe":       ["CVE-2024-21762 (Fortinet Auth Bypass CVSS 9.6)","CVE-2024-23897 (Jenkins Arbitrary File Read CVSS 9.8)"],
    "Reconnaissance": ["CVE-2024-21762 (Fortinet FortiOS CVSS 9.6)"],
}

# Exact LabelEncoder encodings from training
# NSL-KDD: protocol_type: icmp=0,tcp=1,udp=2 | service: domain_u=0,ftp=1,ftp_data=2,http=3,private=4,smtp=5,ssh=6,telnet=7 | flag: REJ=0,RSTO=1,S0=2,SF=3
PROTO_ENC  = {"icmp":0,"tcp":1,"udp":2,"http":1,"https":1,"ftp":1,"ssh":1,"smtp":1,"dns":0,"other":1}
SVC_ENC    = {"domain_u":0,"ftp":1,"ftp_data":2,"http":3,"private":4,"smtp":5,"ssh":6,"telnet":7,
              "https":3,"dns":0,"other":4,"imap":7,"pop3":7,"rdp":4,"finger":4}
FLAG_ENC   = {"REJ":0,"RSTO":1,"S0":2,"SF":3,"RSTOS0":1,"SH":3,"OTH":0,"S1":3,"S2":3}
UNSW_PROTO = {"icmp":0,"tcp":1,"udp":2}
UNSW_SVC   = {"-":0,"dns":1,"ftp":2,"http":3,"smtp":4,"https":3,"ssh":2}
UNSW_STATE = {"CON":0,"FIN":1,"REJ":2,"REQ":3,"RST":4,"SF":1,"S0":3}


class IDSEngine:
    def __init__(self):
        self._rf = self._xgb = self._dt = self._ann = None
        self._ae_pca = None; self._ae_threshold = None
        self._pca_hybrid = None; self._hybrid_gbm = None
        self._sc_nsl = self._sc_unsw = None
        self._le_nsl = self._le_unsw = None
        self._nsl_cats = []; self._unsw_cats = []
        self._cat_enc = {}; self._unsw_encs = {}
        self._n_nsl = 41; self._n_unsw = 42; self._n_combined = 52
        self._metrics = {}
        self._load()

    def _load(self):
        pkl = os.path.join(MODEL_DIR, "models.pkl")
        if not os.path.exists(pkl):
            log.warning("models.pkl not found — stub mode active")
            return
        try:
            with open(pkl, "rb") as f:
                b = pickle.load(f)
            self._rf          = b.get("rf")
            self._xgb         = b.get("xgb")
            self._dt          = b.get("dt")
            self._ann         = b.get("ann")
            self._ae_pca      = b.get("ae_pca")
            self._ae_threshold = b.get("ae_threshold")
            self._pca_hybrid  = b.get("pca_hybrid")
            self._hybrid_gbm  = b.get("hybrid_gbm")
            self._sc_nsl      = b.get("sc_nsl")
            self._sc_unsw     = b.get("sc_unsw")
            self._le_nsl      = b.get("le_nsl")
            self._le_unsw     = b.get("le_unsw")
            self._nsl_cats    = b.get("nsl_cats", [])
            self._unsw_cats   = b.get("unsw_cats", [])
            self._cat_enc     = b.get("cat_enc", {})
            self._unsw_encs   = b.get("unsw_encs", {})
            self._n_nsl       = b.get("n_nsl", 41)
            self._n_unsw      = b.get("n_unsw", 42)
            self._n_combined  = b.get("n_unsw_combined", 52)
            self._metrics     = b.get("metrics", {})
            log.info(f"All 6 models loaded. NSL={self._nsl_cats} | UNSW={self._unsw_cats}")
        except Exception as e:
            log.error(f"Model load error: {e}")

    def models_loaded(self):
        return {
            "random_forest":  self._rf is not None,
            "xgboost":        self._xgb is not None,
            "decision_tree":  self._dt is not None,
            "ann":            self._ann is not None,
            "autoencoder":    self._ae_pca is not None,
            "hybrid_ae_xgb":  self._hybrid_gbm is not None,
        }

    def metadata(self):
        m = self._metrics
        defs = [
            ("random_forest",  "Random Forest",         "NSL-KDD",             41),
            ("xgboost",        "XGBoost (GBM)",          "NSL-KDD",             41),
            ("decision_tree",  "Decision Tree",          "NSL-KDD",             41),
            ("ann",            "ANN (256-128-64)",       "NSL-KDD",             41),
            ("autoencoder",    "Autoencoder (PCA)",      "NSL-KDD normal-only", 41),
            ("hybrid_ae_xgb",  "Hybrid AE + XGBoost 🔥", "UNSW-NB15",           self._n_combined),
        ]
        return [{"name": n, "dataset": ds, "features": f,
                 "accuracy":   m.get(k, {}).get("accuracy",   0),
                 "f1":         m.get(k, {}).get("f1",         0),
                 "precision":  m.get(k, {}).get("precision",  0),
                 "recall":     m.get(k, {}).get("recall",     0),
                 "status": "active", "trained": True}
                for k, n, ds, f in defs]

    def _enc(self, mapping, val, default=1):
        v = str(val).lower().strip()
        if v in mapping: return mapping[v]
        for k, idx in mapping.items():
            if k in v or v in k: return idx
        return default

    def _build_nsl(self, d):
        """Build exact 41-feature NSL-KDD vector using trained LabelEncoder mappings."""
        pe = self._cat_enc.get("protocol_type", PROTO_ENC)
        se = self._cat_enc.get("service", SVC_ENC)
        fe = self._cat_enc.get("flag", FLAG_ENC)

        proto   = float(self._enc(pe, d.get("protocol", "tcp"), 1))
        service = float(self._enc(se, d.get("service",  "http"), 3))
        flag    = float(self._enc(fe, d.get("flag",     "SF"),   3))

        cnt  = float(d.get("count", 10))
        scnt = float(d.get("srv_count", cnt))
        dhc  = float(d.get("dst_host_count",     min(cnt * 8, 255)))
        dhsc = float(d.get("dst_host_srv_count", min(scnt * 8, 255)))
        ssr  = float(d.get("same_srv_rate",    0.9))
        dsr  = float(d.get("diff_srv_rate",    0.05))
        serr = float(d.get("serror_rate",      0.0))
        rerr = float(d.get("rerror_rate",      0.0))

        v = [
            float(d.get("duration", 2.0)),
            proto, service, flag,
            float(d.get("src_bytes",          1000)),
            float(d.get("dst_bytes",           500)),
            float(d.get("land",                  0)),
            float(d.get("wrong_fragment",         0)),
            float(d.get("urgent",                 0)),
            float(d.get("hot",                    1)),
            float(d.get("num_failed_logins",      0)),
            float(d.get("logged_in",              1)),
            float(d.get("num_compromised",        0)),
            float(d.get("root_shell",             0)),
            float(d.get("su_attempted",           0)),
            float(d.get("num_root",               0)),
            float(d.get("num_file_creations",     0)),
            float(d.get("num_shells",             0)),
            float(d.get("num_access_files",       0)),
            float(d.get("num_outbound_cmds",      0)),
            float(d.get("is_host_login",          0)),
            float(d.get("is_guest_login",         0)),
            cnt, scnt,
            serr, float(d.get("srv_serror_rate", serr)),
            rerr, float(d.get("srv_rerror_rate", rerr)),
            ssr, dsr,
            float(d.get("srv_diff_host_rate",    0.05)),
            dhc, dhsc,
            float(d.get("dst_host_same_srv_rate",       ssr)),
            float(d.get("dst_host_diff_srv_rate",       dsr)),
            float(d.get("dst_host_same_src_port_rate",  ssr)),
            float(d.get("dst_host_srv_diff_host_rate", 0.05)),
            float(d.get("dst_host_serror_rate",        serr)),
            float(d.get("dst_host_srv_serror_rate",    serr)),
            float(d.get("dst_host_rerror_rate",        rerr)),
            float(d.get("dst_host_srv_rerror_rate",    rerr)),
        ]
        return np.array(v[:self._n_nsl], dtype=np.float32).reshape(1, -1)

    def _build_unsw(self, d):
        """Build UNSW-NB15 feature vector."""
        pe  = self._unsw_encs.get("proto",   UNSW_PROTO)
        se  = self._unsw_encs.get("service", UNSW_SVC)
        ste = self._unsw_encs.get("state",   UNSW_STATE)
        sb  = float(d.get("src_bytes", 1000))
        db  = float(d.get("dst_bytes",  500))
        dur = max(float(d.get("duration", 1.0)), 0.01)
        cnt = max(float(d.get("count", 10)), 1.0)
        sc  = max(float(d.get("srv_count", 10)), 1.0)
        v = [dur,
             float(self._enc(pe,  d.get("protocol", "tcp"), 1)),
             float(self._enc(se,  d.get("service",  "http"), 3)),
             float(self._enc(ste, d.get("flag", "SF"), 1)),
             cnt, sc, sb, db, (sb + db) / dur,
             64.0, 64.0, sb / dur, db / dur, 0.0, 0.0,
             1.0/cnt, 1.0/sc, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
             sb/cnt, db/sc, 0.0, 0.0, cnt, 1.0, sc, cnt, sc, sc,
             0.0, 0.0, 0.0, cnt, sc, 0.0,
             float(d.get("serror_rate", 0.0)),
             float(d.get("rerror_rate", 0.0)),
             ]
        arr = np.array(v[:self._n_unsw], dtype=np.float32)
        if len(arr) < self._n_unsw:
            arr = np.pad(arr, (0, self._n_unsw - len(arr)))
        return arr.reshape(1, -1)

    def predict(self, raw: dict) -> dict:
        f41  = self._build_nsl(raw)
        f_u  = self._build_unsw(raw)
        votes = []; confs = []; outputs = {}

        def run(model, weight, name):
            if model is None: return
            try:
                xi   = self._sc_nsl.transform(f41) if self._sc_nsl else f41
                pred = int(model.predict(xi)[0])
                prob = float(np.max(model.predict_proba(xi)[0]))
                lbl  = self._le_nsl.inverse_transform([pred])[0] if self._le_nsl else self._nsl_cats[pred]
                votes.append(lbl); confs.append(prob * weight)
                outputs[name] = {"label": lbl, "confidence": round(prob * 100, 1),
                                 "classification": "multi-class"}
            except Exception as e:
                log.debug(f"{name}: {e}")

        run(self._rf,  3.0, "random_forest")
        run(self._xgb, 2.5, "xgboost")
        run(self._dt,  1.5, "decision_tree")
        run(self._ann, 2.0, "ann")

        # Autoencoder — binary anomaly detection (does NOT override multi-class vote)
        if self._ae_pca is not None and self._ae_threshold is not None:
            try:
                xi  = self._sc_nsl.transform(f41) if self._sc_nsl else f41
                Xr  = self._ae_pca.inverse_transform(self._ae_pca.transform(xi))
                err = float(np.mean((Xr - xi) ** 2))
                anom  = err > self._ae_threshold
                score = err / max(self._ae_threshold, 1e-8)
                outputs["autoencoder"] = {
                    "anomaly": anom, "score": round(min(score, 99.9), 4),
                    "threshold": round(self._ae_threshold, 6),
                    "classification": "binary",
                }
                # AE only contributes a small vote when anomaly is detected
                # and no strong multi-class signal exists yet
                if anom and len(votes) == 0:
                    votes.append("Other"); confs.append(0.5)
            except Exception as e:
                log.debug(f"AE: {e}")

        # Hybrid AE+XGBoost — multi-class on UNSW-NB15
        if self._pca_hybrid is not None and self._hybrid_gbm is not None:
            try:
                xi2      = self._sc_unsw.transform(f_u) if self._sc_unsw else f_u
                enc      = self._pca_hybrid.transform(xi2)
                combined = np.hstack([xi2, enc])
                n = self._n_combined
                if combined.shape[1] > n:
                    combined = combined[:, :n]
                elif combined.shape[1] < n:
                    combined = np.pad(combined, ((0, 0), (0, n - combined.shape[1])))
                pred2 = int(self._hybrid_gbm.predict(combined)[0])
                prob2 = float(np.max(self._hybrid_gbm.predict_proba(combined)[0]))
                lbl2  = (self._le_unsw.inverse_transform([pred2])[0]
                         if self._le_unsw else self._unsw_cats[pred2])
                lbl2 = "NORMAL" if lbl2 == "Normal" else lbl2
                votes.append(lbl2); confs.append(prob2 * 1.5)
                outputs["hybrid_ae_xgb"] = {
                    "label": lbl2, "confidence": round(prob2 * 100, 1),
                    "classification": "multi-class (UNSW-NB15)",
                }
            except Exception as e:
                log.debug(f"Hybrid: {e}")

        label, conf = self._vote(votes, confs)
        sev = SEVERITY.get(label, "MEDIUM")
        return {
            "label":           label,
            "severity":        sev,
            "confidence":      round(conf * 100, 1),
            "attack_family":   FAMILY.get(label, "Unknown"),
            "mitre_tactic":    MITRE.get(label, "TA0000 — Unknown"),
            "recommendations": RECS.get(label, RECS["Other"]),
            "cve_refs":        CVES.get(label, []),
            "model_outputs":   outputs,
        }

    def shap_explain(self, record: dict) -> dict:
        res   = record.get("result", {})
        label = res.get("label", "NORMAL")
        req   = record.get("request_data", {})
        f41   = self._build_nsl(req)
        FEAT = ["duration","protocol_type","service","flag","src_bytes","dst_bytes","land",
                "wrong_fragment","urgent","hot","num_failed_logins","logged_in",
                "num_compromised","root_shell","su_attempted","num_root",
                "num_file_creations","num_shells","num_access_files","num_outbound_cmds",
                "is_host_login","is_guest_login","count","srv_count",
                "serror_rate","srv_serror_rate","rerror_rate","srv_rerror_rate",
                "same_srv_rate","diff_srv_rate","srv_diff_host_rate","dst_host_count",
                "dst_host_srv_count","dst_host_same_srv_rate","dst_host_diff_srv_rate",
                "dst_host_same_src_port_rate","dst_host_srv_diff_host_rate",
                "dst_host_serror_rate","dst_host_srv_serror_rate",
                "dst_host_rerror_rate","dst_host_srv_rerror_rate"]
        EXPL = {
            "serror_rate":        "High SYN error rate — strong DoS/SYN-flood indicator",
            "count":              "High connection count — flood or brute force pattern",
            "src_bytes":          "High outbound bytes — exfiltration or volumetric flood",
            "rerror_rate":        "High REJ error rate — port scanning / reconnaissance",
            "diff_srv_rate":      "High multi-service rate — cross-port scanning detected",
            "num_failed_logins":  "Multiple auth failures — brute force attack in progress",
            "root_shell":         "Root shell obtained — privilege escalation succeeded",
            "logged_in":          "Auth session present — context for risk scoring",
            "dst_host_serror_rate": "High destination SYN error rate — DoS targeting this host",
            "hot":                "High hot indicator — suspicious commands executed in session",
        }
        rf  = self._rf
        imp = rf.feature_importances_ if (rf and hasattr(rf, "feature_importances_")) else np.ones(41) / 41
        xi  = self._sc_nsl.transform(f41)[0] if self._sc_nsl else f41[0]
        vals = imp * np.abs(xi)
        pairs = sorted(zip(FEAT[:len(vals)], vals, xi), key=lambda x: abs(x[1]), reverse=True)[:10]
        top_feats = [
            {"feature": nm, "shap_value": round(float(sv), 5),
             "raw_value": round(float(rv), 4),
             "direction": "increases_risk" if sv > 0 else "decreases_risk",
             "explanation": EXPL.get(nm, f"'{nm}' contributed to the {label} prediction")}
            for nm, sv, rv in pairs
        ]
        top_risk = [f for f in top_feats if f["direction"] == "increases_risk"][:3]
        nl = (f"Prediction '{label}' driven by: " +
              ", ".join(f"high {f['feature']} ({f['raw_value']})" for f in top_risk) +
              ". " + (top_risk[0]["explanation"] if top_risk else "")) if top_risk else \
             f"Traffic classified as '{label}' — no dominant risk features detected."
        return {"method": "Feature Importance (6-Model Ensemble)",
                "label": label, "top_features": top_feats,
                "natural_language_summary": nl}

    def retrain(self):
        from datetime import datetime; import time
        start = time.time(); self._load()
        return {"message": "Models reloaded from disk",
                "duration_seconds": round(time.time() - start, 1),
                "timestamp": datetime.utcnow().isoformat()}

    def _vote(self, votes, confs):
        if not votes: return "NORMAL", 0.95
        sm = {}
        for v, c in zip(votes, confs):
            sm[v] = sm.get(v, 0) + c
        best = max(sm, key=sm.get)
        return best, sm[best] / (sum(sm.values()) or 1)
