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
import io, re, ipaddress, datetime, subprocess, os, urllib.request
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
    "other": ("#b8b8b8", "#222222"),
}
ROLE_NAMES = {
    "firewall": "FIREWALL", "switch": "SWITCH", "network": "ROUTER / SWITCH",
    "accesspoint": "ACCESS POINT", "nas": "NAS / STORAGE", "hyperv": "HYPER-V HOST",
    "server": "SERVER", "printer": "PRINTER", "endpoint": "WORKSTATION",
    "laptop": "LAPTOP", "other": "DEVICE",
}

def classify(name, cls):
    n = (name or "").upper(); c = cls or ""
    if "FW" in n or "FIREWALL" in n: return "firewall"
    if "-AP" in n or "ACCESSPOINT" in n or "ACCESS POINT" in n or "-WAP" in n: return "accesspoint"
    if c == "Switch/Router" and "SW" in n: return "switch"
    if c == "Switch/Router": return "network"
    if c == "Printer" or "PRINT" in n: return "printer"
    if c == "Storage": return "nas"
    if c.startswith("Servers"): return "hyperv" if "HV" in n else "server"
    if c.startswith("Laptop"): return "laptop"
    if c.startswith("Workstations"): return "endpoint"
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
    nidn = nid(d["name"] + "_" + suffix)
    return nidn, '  %s [label="%s", fillcolor="%s", fontcolor="%s"];' % (nidn, "\\n".join(lines), col, fc)

def build_dot(client, devices, date):
    for d in devices:
        d["role"] = classify(d.get("name"), d.get("class"))
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
    devices = body.get("devices", [])
    if not devices:
        return jsonify(error="no devices provided"), 400
    dot = build_dot(client, devices, date)
    p = subprocess.run(["dot", "-Tpng", "-Gdpi=110"], input=dot.encode(),
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if p.returncode != 0:
        return jsonify(error="graphviz failed", detail=p.stderr.decode()[:500]), 500
    out = brand(p.stdout, body.get("logo_url"), client, date)
    return send_file(out, mimetype="image/png",
                     download_name=re.sub(r"\W+", "_", client) + "_network_map.png")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
