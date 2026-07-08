#!/usr/bin/env python3
"""
TrustPoint Network Map render service.

POST /render (JSON): { "client": "...", "date": "YYYY-MM-DD" (optional),
  "logo_url": "https://.../logo.png" (optional),
  "devices": [ {"name","class","ip","gw","dns","dhcp","mac","os","cpu",
                "site" (optional N-central site name)}, ... ] }
-> 200 image/png  (branded logical network map)
GET /healthz -> 200 "ok"
Requires: graphviz (dot) + Pillow + Flask + DejaVu fonts (see Dockerfile).
"""
import io, re, ipaddress, datetime, subprocess, os, urllib.request
from flask import Flask, request, send_file, jsonify
from PIL import Image, ImageDraw, ImageFont

app = Flask(__name__)

NAVY = (18, 49, 94)
CONF = ("CONFIDENTIAL  ·  Property of TrustPoint IT Solutions Inc.  ·  "
        "Contains proprietary network information — for authorized internal use only; do not distribute.")
FONT_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
PUBLIC_DNS = ("8.8", "8.4", "1.1", "4.4", "9.9", "208.67", "209.18")

ROLE_COLOR = {
    "firewall": ("#b3261e", "white"), "switch": ("#1c7293", "white"),
    "network": ("#1c7293", "white"), "nas": ("#6d2e46", "white"),
    "hyperv": ("#2c5f2d", "white"), "server": ("#1E2761", "white"),
    "endpoint": ("#cfe0f5", "#1E2761"), "other": ("#888888", "white"),
}

def classify(name, cls):
    n = (name or "").upper(); c = cls or ""
    if "FW" in n or "FIREWALL" in n: return "firewall"
    if c == "Switch/Router" and "SW" in n: return "switch"
    if c == "Switch/Router": return "network"
    if c == "Storage": return "nas"
    if c.startswith("Servers"): return "hyperv" if "HV" in n else "server"
    if c.startswith("Laptop") or c.startswith("Workstations"): return "endpoint"
    return "other"

def subnet_of(ip):
    try:
        return str(ipaddress.ip_network(ip + "/24", strict=False).network_address)[:-1] + "0/24"
    except Exception:
        return None

def nid(s): return "n_" + re.sub(r"\W", "_", s or "")
def esc(s): return (s or "").replace("\\", "").replace('"', "'")
def two(s): return (s or "")[:2].upper()

def _dns_ips(devs):
    out = set()
    for d in devs:
        for x in (d.get("dns") or "").split(","):
            x = x.strip()
            if x and not x.startswith(PUBLIC_DNS):
                out.add(x)
    return out

def build_dot(client, devices, date):
    for d in devices:
        d["role"] = classify(d.get("name"), d.get("class"))
        d["grp"] = d.get("site") or (subnet_of(d.get("ip", "")) if d.get("ip") else None)
    groups = {}
    for d in devices:
        groups.setdefault(d["grp"], []).append(d)
    noip = groups.get(None, [])
    sites = {g: ds for g, ds in groups.items() if g and len(ds) >= 2}
    singles = {g: ds for g, ds in groups.items() if g and len(ds) == 1}
    if not sites:                                  # tiny client fallback: largest real group is the site
        real = {g: ds for g, ds in groups.items() if g}
        if real:
            big = max(real, key=lambda g: len(real[g]))
            sites = {big: real[big]}
            singles = {g: ds for g, ds in real.items() if g != big}
    ordered = sorted(sites.items(), key=lambda kv: -len(kv[1]))

    # SNMP-discovered infra (no agent IP): firewalls/switches/NAS
    fws = [d for d in noip if d["role"] == "firewall"]
    sws = [d for d in noip if d["role"] in ("switch", "network")]
    nass = [d for d in noip if d["role"] == "nas"]
    prefixes = {g: set(two(x["name"]) for x in ds) for g, ds in sites.items()}
    fw_by_site = {}
    for fw in fws:                                 # attach a firewall to the site sharing its name prefix
        tgt = next((g for g, pr in prefixes.items() if two(fw["name"]) in pr), None)
        fw_by_site.setdefault(tgt if tgt else (ordered[0][0] if ordered else None), []).append(fw)

    L = ["digraph G {",
         '  rankdir=TB; bgcolor="white"; fontname="Helvetica"; compound=true;',
         '  node [fontname="Helvetica", fontsize=10, style="filled,rounded", shape=box];',
         '  edge [color="#555555", arrowhead=none];',
         '  internet [label="Internet", fillcolor="#dddddd", fontcolor="#000000"];']

    for idx, (g, ds) in enumerate(ordered):
        is_primary = (idx == 0)
        gws = [d.get("gw") for d in ds if d.get("gw")]
        gw = max(set(gws), key=gws.count) if gws else ""
        dns_ips = _dns_ips(ds)
        dhcp_ips = set(d.get("dhcp") for d in ds if d.get("dhcp"))
        sfws = fw_by_site.get(g, [])
        edge = "edge%d" % idx
        if sfws:
            lbl = "%s\\nFirewall / Gateway %s" % (esc(sfws[0]["name"]), gw)
        else:
            lbl = "Site gateway\\n%s" % gw if not is_primary else ("Firewall / Gateway\\n%s" % gw)
        if gw and gw in dhcp_ips:
            lbl += "\\n(also DHCP)"
        L.append('  %s [label="%s", fillcolor="#b3261e", fontcolor="white"];' % (edge, lbl))
        L.append('  internet -> %s;' % edge)
        parent = edge
        if is_primary:
            for i, sw in enumerate(sws):
                s = "psw%d" % i
                L.append('  %s [label="%s\\nSwitch", fillcolor="#1c7293", fontcolor="white"];' % (s, esc(sw["name"])))
                L.append('  %s -> %s;' % (parent, s)); parent = s
        for d in [x for x in ds if x["role"] in ("server", "hyperv")]:
            extra = "\\nDomain Controller / DNS" if d.get("ip") in dns_ips else ("\\nHyper-V Host" if d["role"] == "hyperv" else "")
            col, fc = ROLE_COLOR[d["role"]]
            L.append('  %s [label="%s\\n%s%s\\n%s", fillcolor="%s", fontcolor="%s"];' % (
                nid(d["name"]), esc(d["name"]), d.get("ip", ""), extra,
                esc(d.get("os", "").replace("Microsoft ", "")), col, fc))
            L.append('  %s -> %s;' % (parent, nid(d["name"])))
        if is_primary:
            for d in nass:
                L.append('  %s [label="%s\\nNAS / Storage", fillcolor="#6d2e46", fontcolor="white"];' % (nid(d["name"]), esc(d["name"])))
                L.append('  %s -> %s;' % (parent, nid(d["name"])))
        eps = [x for x in ds if x["role"] == "endpoint"]
        if eps:
            if len(eps) <= 6:
                lab = "Workstations / Laptops on %s\\n%s" % (g, ", ".join(esc(x["name"]) for x in eps))
            else:
                lab = "Workstations & Laptops on %s\\n(%d devices)" % (g, len(eps))
            L.append('  eps%d [label="%s", fillcolor="#cfe0f5", fontcolor="#1E2761"];' % (idx, lab))
            L.append('  %s -> eps%d;' % (parent, idx))

    if singles:
        L.append('  subgraph cluster_remote {')
        L.append('    label="Remote / off-LAN devices (single agents on other networks)"; style="dashed"; color="#999999"; fontsize=11;')
        for i, (g, ds) in enumerate(sorted(singles.items())):
            L.append('    rem%d [label="%s\\n%s", fillcolor="#f0f0f0", fontcolor="#333333"];' % (
                i, g, ", ".join(esc(d["name"]) for d in ds)))
        L.append('  }')
    L.append("}")
    return "\n".join(L)

def brand(png_bytes, logo_url, client, date):
    diag = Image.open(io.BytesIO(png_bytes)).convert("RGBA")
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
    p = subprocess.run(["dot", "-Tpng", "-Gdpi=120"], input=dot.encode(),
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if p.returncode != 0:
        return jsonify(error="graphviz failed", detail=p.stderr.decode()[:500]), 500
    out = brand(p.stdout, body.get("logo_url"), client, date)
    return send_file(out, mimetype="image/png",
                     download_name=re.sub(r"\W+", "_", client) + "_network_map.png")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
