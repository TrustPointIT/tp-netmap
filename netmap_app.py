#!/usr/bin/env python3
"""
TrustPoint Network Map render service (detailed).

POST /render (JSON): { "client": "...", "date": "YYYY-MM-DD" (optional),
  "logo_url": "https://.../logo.png" (optional),
  "devices": [ {"name","class","ip","gw","dns","dhcp","mac","os",
                "site" (optional N-central site name)}, ... ] }
-> 200 image/png  (branded, detailed logical network map)
GET /healthz -> 200 "ok"
Requires: graphviz (dot) + Pillow + Flask + DejaVu fonts (see Dockerfile).

Detailed mode: every device is drawn individually with name, IP, role, OS and
MAC, grouped into network segments (by /24 subnet) that show the segment
gateway, DNS and DHCP. Firewalls and domain controllers are highlighted.
VLAN data is not available from N-central and is layered in later from
Network Detective (Phase 2).
"""
import io, re, ipaddress, datetime, subprocess, os, urllib.request, base64
from flask import Flask, request, send_file, jsonify
from PIL import Image, ImageDraw, ImageFont

app = Flask(__name__)

NAVY = (18, 49, 94)
CONF = ("CONFIDENTIAL  -  Property of TrustPoint IT Solutions Inc.  -  "
        "Contains proprietary network information; for authorized internal use only, do not distribute.")
FONT_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
PUBLIC_DNS = ("8.8", "8.4", "1.1", "4.4", "9.9", "208.67", "209.18")

ROLE_COLOR = {
    "firewall": ("#b3261e", "white"), "switch": ("#1c7293", "white"),
    "network": ("#1c7293", "white"), "accesspoint": ("#2c5f8a", "white"),
    "nas": ("#6d2e46", "white"), "hyperv": ("#2c5f2d", "white"),
    "server": ("#1E2761", "white"), "printer": ("#8d6e8f", "white"),
    "endpoint": ("#cfe0f5", "#1E2761"), "laptop": ("#e2ecf9", "#1E2761"),
    # Network Glue port-fingerprinted roles
    "oracle": ("#8a3b00", "white"), "sql": ("#7a1f2b", "white"),
    "dns": ("#155e63", "white"), "linux": ("#33475b", "white"),
    "web": ("#3a4a2f", "white"),
    "other": ("#b8b8b8", "#222222"),
}
ROLE_NAMES = {
    "firewall": "FIREWALL", "switch": "SWITCH", "network": "ROUTER / SWITCH",
    "accesspoint": "ACCESS POINT", "nas": "NAS / STORAGE", "hyperv": "HYPER-V HOST",
    "server": "SERVER", "printer": "PRINTER", "endpoint": "WORKSTATION",
    "laptop": "LAPTOP", "oracle": "ORACLE DB", "sql": "SQL SERVER",
    "dns": "DNS / GATEWAY", "linux": "LINUX / SSH HOST", "web": "WEB / HTTPS",
    "other": "DEVICE",
}

# Port -> role (Network Glue "listening-ports"). First match wins.
PORT_ROLE = [(1521, "oracle"), (1433, "sql"), (53, "dns"),
             (9100, "printer"), (515, "printer"), (631, "printer"),
             (22, "linux"), (443, "web"), (8080, "web"), (80, "web")]

def parse_ports(v):
    """Accept [22,80] or 'SSH (22/TCP),HTTP (8080/TCP)' -> set of ints."""
    if isinstance(v, (list, tuple)):
        return {int(x) for x in v if str(x).isdigit()}
    return {int(m) for m in re.findall(r"\((\d+)/", v or "")}

def _valid_ip(ip):
    ip = (ip or "").strip()
    try:
        ipaddress.ip_address(ip)
        return ip not in ("0.0.0.0",)
    except Exception:
        return False

def _parse_date(s):
    for fmt in ("%Y-%m-%d", "%Y-%m", "%m/%d/%Y", "%Y/%m/%d"):
        try:
            return datetime.datetime.strptime(str(s)[:10], fmt).date()
        except Exception:
            continue
    return None

EXPOSURE_PORTS = {22, 23, 21, 3389, 5900}

def assemble(body):
    """
    Merge the three IT Glue / N-central sources into one device list plus a
    findings summary and a decommission (stale-AD) list. Join key is the IP:
    an N-central agent IP == a Network Glue discovered IP means the same device
    (so it's managed and we can promote the real hostname).

    Accepts:
      ncentral: [{name,class,ip,gw,dns,dhcp,mac,os}, ...]  (agent-managed)
      nonad:    [{ip,ports}, ...]                          (Network Glue scan)
      ad:       [{name,enabled,last}, ...]                 (Network Glue AD)
    Falls back to body['devices'] (flat, unmanaged-agnostic) when no ncentral.
    """
    ncentral = body.get("ncentral") or body.get("devices") or []
    nonad = body.get("nonad") or []
    ad = body.get("ad") or []
    stale_days = int(body.get("stale_days", 365))
    today = datetime.date.today()

    managed_ips, host_by_ip = set(), {}
    for d in ncentral:
        ip = (d.get("ip") or "").strip()
        if _valid_ip(ip):
            managed_ips.add(ip)
            host_by_ip.setdefault(ip, d.get("name"))

    devices, nonad_ips = [], set()
    for d in nonad:
        ip = (d.get("ip") or "").strip()
        if not _valid_ip(ip):
            continue
        nonad_ips.add(ip)
        devices.append({
            "name": host_by_ip.get(ip) or ip,
            "ip": ip,
            "class": "",
            "ports": d.get("ports"),
            "managed": ip in managed_ips,
        })
    for d in ncentral:
        ip = (d.get("ip") or "").strip()
        if not _valid_ip(ip) or ip in nonad_ips:
            continue
        dd = dict(d)
        dd["managed"] = True
        devices.append(dd)

    # Stale AD (enabled, no login for >= stale_days).
    # Make can't emit the domain backslash safely in JSON, so it sends the
    # AD name base64-encoded (name_b64); decode + strip the DOMAIN\ prefix here.
    stale = []
    for a in ad:
        en = a.get("enabled")
        if str(en).lower() != "true":
            continue
        dt = _parse_date(a.get("last"))
        if not (dt and (today - dt).days >= stale_days):
            continue
        raw = a.get("name")
        if not raw and a.get("name_b64"):
            try:
                raw = base64.b64decode(a["name_b64"]).decode("utf-8", "ignore")
            except Exception:
                raw = ""
        host = (raw or "").replace("/", "\\").split("\\")[-1]
        stale.append((host, str(a.get("last"))))
    stale.sort(key=lambda x: x[1])

    # Findings
    managed_ct = sum(1 for d in devices if d.get("managed"))
    disc = len(devices) - managed_ct
    exposed = sum(1 for d in nonad
                  if EXPOSURE_PORTS & parse_ports(d.get("ports")))
    findings = []
    if devices:
        findings.append("Coverage: %d managed / %d discovered-unmanaged"
                        % (managed_ct, disc))
    if stale:
        findings.append("Stale AD (>%dd): %d decommission candidates"
                        % (stale_days, len(stale)))
    if exposed:
        findings.append("Legacy exposure: %d hosts on SSH/Telnet/FTP/RDP" % exposed)
    return devices, findings, stale

def classify(name, cls, ports=None):
    n = (name or "").upper(); c = cls or ""
    if "FW" in n or "FIREWALL" in n: return "firewall"
    if "-AP" in n or "ACCESSPOINT" in n or "ACCESS POINT" in n or "-WAP" in n: return "accesspoint"
    if c == "Switch/Router" and "SW" in n: return "switch"
    if c == "Switch/Router": return "network"
    if c == "Printer" or "PRINT" in n or n.startswith("RNP"): return "printer"
    if c == "Storage": return "nas"
    if c.startswith("Servers"): return "hyperv" if "HV" in n else "server"
    if c.startswith("Laptop"): return "laptop"
    if c.startswith("Workstations"): return "endpoint"
    # No N-central class (discovered-only device): fingerprint by listening ports
    ps = ports or set()
    for port, role in PORT_ROLE:
        if port in ps:
            return role
    return "other"

def subnet_of(ip):
    try:
        return str(ipaddress.ip_network(ip + "/24", strict=False).network_address)[:-1] + "0/24"
    except Exception:
        return None

def nid(s): return "n_" + re.sub(r"\W", "_", s or "")
def esc(s): return (s or "").replace("\\", "").replace('"', "'")

def _dns_ips(devs):
    out = set()
    for d in devs:
        for x in (d.get("dns") or "").split(","):
            x = x.strip()
            if x and not x.startswith(PUBLIC_DNS):
                out.add(x)
    return out

def _seg_meta(ds):
    gws = [d.get("gw") for d in ds if d.get("gw")]
    gw = max(set(gws), key=gws.count) if gws else ""
    dnss = []
    for d in ds:
        for x in (d.get("dns") or "").split(","):
            x = x.strip()
            if x and not x.startswith(PUBLIC_DNS) and x not in dnss:
                dnss.append(x)
    dhcp = [x for x in {d.get("dhcp") for d in ds if d.get("dhcp")} if x]
    return gw, ", ".join(dnss[:3]), ", ".join(sorted(dhcp))

def _role_label(d, dns_ips):
    if d["role"] == "server" and d.get("ip") and d.get("ip") in dns_ips:
        return "DOMAIN CONTROLLER / DNS"
    return ROLE_NAMES.get(d["role"], "DEVICE")

def _node(d, dns_ips, suffix):
    col, fc = ROLE_COLOR.get(d["role"], ROLE_COLOR["other"])
    lines = [esc(d["name"])]
    if d.get("ip"): lines.append(d["ip"])
    lines.append(_role_label(d, dns_ips))
    os_s = esc((d.get("os") or "").replace("Microsoft ", ""))
    if os_s: lines.append(os_s)
    if d.get("mac"): lines.append(esc(d["mac"]))
    # Managed-vs-discovered is the coverage signal from IT Glue/N-central.
    # Discovered-but-unmanaged devices get a dashed border + a tag line.
    managed = d.get("managed", True)
    style = "filled,rounded" if managed else "filled,rounded,dashed"
    if not managed:
        lines.append("(DISCOVERED - unmanaged)")
    nidn = nid(d["name"] + "_" + suffix)
    return nidn, ('  %s [label="%s", fillcolor="%s", fontcolor="%s", style="%s"];'
                  % (nidn, "\\n".join(lines), col, fc, style))

def build_dot(client, devices, date, findings=None, stale=None):
    for d in devices:
        d["_ports"] = parse_ports(d.get("ports") or d.get("listening_ports"))
        d["role"] = classify(d.get("name"), d.get("class"), d["_ports"])
        d["ip"] = (d.get("ip") or "").strip()
        d["sub"] = subnet_of(d["ip"]) if d["ip"] else None
    dns_ips = _dns_ips(devices)
    fws = [d for d in devices if d["role"] == "firewall"]

    groups = {}
    for d in devices:
        groups.setdefault(d["sub"], []).append(d)
    real = {s: ds for s, ds in groups.items() if s}
    noip = groups.get(None, [])

    L = ["digraph G {",
         '  rankdir=TB; bgcolor="white"; fontname="Helvetica"; compound=true; nodesep=0.22; ranksep=0.7;',
         '  node [fontname="Helvetica", fontsize=9, style="filled,rounded", shape=box];',
         '  edge [color="#8a8a8a", arrowhead=none];',
         '  internet [label="INTERNET", shape=ellipse, fillcolor="#dddddd", fontcolor="#000000"];']

    # Findings panel (coverage gap / stale AD / exposure) from Network Glue data.
    if findings:
        ftext = "\\l".join(esc(x) for x in findings) + "\\l"
        L.append('  findings [label="NETWORK FINDINGS\\l%s", shape=note, '
                 'fillcolor="#fff6e6", fontcolor="#5a3b00", fontsize=10, '
                 'style="filled"];' % ftext)
        L.append('  {rank=source; internet; findings}')

    fw_anchor = "internet"
    for i, fw in enumerate(fws):
        fid = "fw%d" % i
        L.append('  %s [label="%s\\nFIREWALL / GATEWAY", fillcolor="#b3261e", fontcolor="white"];' % (fid, esc(fw["name"])))
        L.append('  internet -> %s;' % fid)
    if fws:
        fw_anchor = "fw0"

    order = {"firewall":0,"network":1,"switch":1,"accesspoint":2,"nas":3,"hyperv":4,"server":4,"printer":6,"endpoint":7,"laptop":8,"other":9}
    for idx, sub in enumerate(sorted(real.keys())):
        ds = real[sub]
        gw, dns, dhcp = _seg_meta(ds)
        meta = "Gateway %s" % (gw or "n/a")
        if dns: meta += "   DNS %s" % dns
        if dhcp: meta += "   DHCP %s" % dhcp
        anchor = "seg%d" % idx
        L.append('  subgraph cluster_seg%d {' % idx)
        L.append('    label="NETWORK SEGMENT  %s\\n%s"; style="rounded"; color="#1c7293"; penwidth=2; fontsize=12; fontcolor="#12315e";' % (sub, meta))
        L.append('    %s [label="%s\\nSEGMENT GATEWAY", shape=box, style="filled", fillcolor="#1c7293", fontcolor="white"];' % (anchor, gw or sub))
        devs = [d for d in sorted(ds, key=lambda x: order.get(x["role"], 9)) if d["role"] != "firewall"]
        ids = []
        for d in devs:
            nidn, line = _node(d, dns_ips, "s%d" % idx)
            L.append("  " + line)
            ids.append(nidn)
        rows = [ids[i:i + 6] for i in range(0, len(ids), 6)]
        for row in rows:
            L.append("    {rank=same; " + " ".join(row) + "}")
            for j in range(len(row) - 1):
                L.append('    %s -> %s [style=invis];' % (row[j], row[j + 1]))
        for r in range(len(rows) - 1):
            L.append('    %s -> %s [style=invis];' % (rows[r][0], rows[r + 1][0]))
        if rows:
            L.append('    %s -> %s;' % (anchor, rows[0][0]))
        L.append('  }')
        L.append('  %s -> %s [lhead=cluster_seg%d, color="#b3261e", penwidth=1.4];' % (fw_anchor, anchor, idx))

    if stale:
        L.append('  subgraph cluster_stale {')
        L.append('    label="DECOMMISSION CANDIDATES  -  enabled in AD, no login >1yr"; '
                 'style="dashed"; color="#b3261e"; fontsize=11; fontcolor="#b3261e";')
        sids = []
        for i, (nm, last) in enumerate(stale):
            sid = "stale%d" % i
            L.append('    %s [label="%s\\n%s", fillcolor="#f3d9d6", fontcolor="#7a1f2b", shape=box];'
                     % (sid, esc(nm), esc(last)))
            sids.append(sid)
        srows = [sids[i:i + 8] for i in range(0, len(sids), 8)]
        for row in srows:
            L.append("    {rank=same; " + " ".join(row) + "}")
            for j in range(len(row) - 1):
                L.append('    %s -> %s [style=invis];' % (row[j], row[j + 1]))
        for r in range(len(srows) - 1):
            L.append('    %s -> %s [style=invis];' % (srows[r][0], srows[r + 1][0]))
        L.append('  }')

    if noip:
        L.append('  subgraph cluster_noip {')
        L.append('    label="DISCOVERED DEVICES WITHOUT AN IP (SNMP / agent-only)"; style="dashed"; color="#999999"; fontsize=11;')
        nids = []
        for d in noip:
            nidn, line = _node(d, dns_ips, "noip")
            L.append("  " + line)
            nids.append(nidn)
        nrows = [nids[i:i + 8] for i in range(0, len(nids), 8)]
        for row in nrows:
            L.append("    {rank=same; " + " ".join(row) + "}")
            for j in range(len(row) - 1):
                L.append('    %s -> %s [style=invis];' % (row[j], row[j + 1]))
        for r in range(len(nrows) - 1):
            L.append('    %s -> %s [style=invis];' % (nrows[r][0], nrows[r + 1][0]))
        L.append('  }')

    L.append("}")
    return "\n".join(L)

def brand(png_bytes, logo_url, client, date):
    diag = Image.open(io.BytesIO(png_bytes)).convert("RGBA")
    W, H = diag.size
    MAXW = 11000
    if W > MAXW:
        diag = diag.resize((MAXW, int(H * (MAXW / W))), Image.LANCZOS)
        W, H = diag.size
    head, foot = 100, 62
    f_foot = ImageFont.truetype(FONT_BOLD, 15)
    f_t1 = ImageFont.truetype(FONT_BOLD, 26)
    f_t2 = ImageFont.truetype(FONT_BOLD, 16)
    meas = ImageDraw.Draw(Image.new("RGB", (1, 1)))
    foot_tw = meas.textlength(CONF, font=f_foot)
    logo = None
    if logo_url:
        try:
            raw = urllib.request.urlopen(logo_url, timeout=15).read()
            logo = Image.open(io.BytesIO(raw)).convert("RGBA"); logo.thumbnail((84, 84))
        except Exception as e:
            app.logger.warning("logo fetch failed: %s", e)
    logo_w = logo.width if logo else 84
    title_x = 28 + logo_w + 28
    t1 = "%s  -  Network Map (logical)" % client
    t2 = "auto-generated from N-central, %s" % date
    t1w = meas.textlength(t1, font=f_t1); t2w = meas.textlength(t2, font=f_t2)
    CW = int(max(W, foot_tw + 160, title_x + max(t1w, t2w) + 40))
    canvas = Image.new("RGBA", (CW, head + H + foot), (255, 255, 255, 255))
    canvas.paste(diag, ((CW - W) // 2, head))
    if logo:
        canvas.paste(logo, (28, (head - logo.height) // 2), logo)
    d = ImageDraw.Draw(canvas)
    d.text((title_x, head / 2 - 30), t1, font=f_t1, fill=NAVY)
    d.text((title_x, head / 2 + 6), t2, font=f_t2, fill=(90, 90, 90))
    d.rectangle([0, head + H, CW, head + H + foot], fill=NAVY)
    d.text((CW / 2 - foot_tw / 2, head + H + foot / 2 - 10), CONF, font=f_foot, fill=(255, 255, 255))
    out = io.BytesIO(); canvas.convert("RGB").save(out, "PNG"); out.seek(0)
    return out

@app.route("/healthz")
def healthz(): return "ok", 200

@app.route("/render", methods=["POST"])
def render():
    key = os.environ.get("RENDER_KEY")
    if key and request.headers.get("X-Api-Key") != key:
        return jsonify(error="unauthorized"), 401
    body = request.get_json(force=True)
    client = body.get("client", "Client")
    date = body.get("date") or datetime.datetime.now().strftime("%Y-%m-%d")
    # Enriched mode: merge ncentral + Network Glue nonad + ad server-side.
    devices, findings, stale = assemble(body)
    if not devices:
        return jsonify(error="no devices provided"), 400
    if body.get("findings"):          # allow caller-supplied override lines
        findings = list(body["findings"])
    dot = build_dot(client, devices, date, findings, stale)
    p = subprocess.run(["dot", "-Tpng", "-Gdpi=110"], input=dot.encode(),
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if p.returncode != 0:
        return jsonify(error="graphviz failed", detail=p.stderr.decode()[:500]), 500
    out = brand(p.stdout, body.get("logo_url"), client, date)
    return send_file(out, mimetype="image/png",
                     download_name=re.sub(r"\W+", "_", client) + "_network_map.png")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
