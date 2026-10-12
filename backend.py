"""
CYBER SHIELD - Backend + Frontend (Windows)
============================================
يراقب الشبكة ويكشف الهجمات، ويقدّم الواجهة كمان من نفس السيرفر (Flask)
مفيش حاجة اسمها Node/npm هنا — كل حاجة بايثون.

تثبيت المتطلبات:
  pip install flask flask-cors scapy psutil

تشغيل (لازم كـ مسؤول/Administrator عشان مراقبة الشبكة تشتغل):
  python backend.py

بعدها افتح المتصفح على:
  http://localhost:5000
"""

from flask import Flask, jsonify, Response, request, send_from_directory
from flask_cors import CORS
from scapy.all import sniff, srp, ARP, Ether, IP, TCP, ICMP
import ipaddress
import os
import psutil
import threading
import json
import time
import socket
from datetime import datetime
from collections import defaultdict

TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")

app = Flask(__name__)
CORS(app)

# ─── البيانات ────────────────────────────────────────────
attacks = []
stats = {"total": 0, "critical": 0, "warnings": 0, "blocked": 0}
arp_table = {}
discovered_devices = {}  # ip -> {"ip","mac","last_seen"}
port_scan_tracker = defaultdict(lambda: {"ports": set(), "first_time": 0})
flood_tracker = defaultdict(list)
syn_tracker = defaultdict(list)
lock = threading.Lock()
sse_listeners = []
sniff_error = None
scan_error = None

# ─── تخمين نوع الجهاز من أول 3 بايتات في الـ MAC (OUI) ────
# ملحوظة: تخمين تقريبي بناءً على الشركة المصنّعة لكرت الشبكة،
# مش دقيق 100% خصوصًا مع خاصية MAC randomization في الموبايلات الحديثة
OUI_VENDORS = {
    # هواتف / أجهزة محمولة
    "F42E7F": ("Apple", "phone", "📱"), "3C0754": ("Apple", "phone", "📱"),
    "A4C361": ("Apple", "phone", "📱"), "DC415F": ("Apple", "phone", "📱"),
    "F4F951": ("Apple", "phone", "📱"), "8863DF": ("Apple", "phone", "📱"),
    "D0817A": ("Samsung", "phone", "📱"), "5C0A5B": ("Samsung", "phone", "📱"),
    "8425DB": ("Samsung", "phone", "📱"), "A00798": ("Samsung", "phone", "📱"),
    "34145F": ("Samsung", "phone", "📱"), "9C02CE": ("Samsung", "phone", "📱"),
    "286FB9": ("Xiaomi", "phone", "📱"), "F8A45F": ("Xiaomi", "phone", "📱"),
    "64B473": ("Xiaomi", "phone", "📱"), "34CE00": ("Xiaomi", "phone", "📱"),
    "4CEDDE": ("Huawei", "phone", "📱"), "00E0FC": ("Huawei", "phone", "📱"),
    "F07959": ("Huawei", "phone", "📱"), "18C58A": ("Oppo", "phone", "📱"),
    "C0EEFB": ("OnePlus", "phone", "📱"),
    # لابتوبات / أجهزة مكتبية (كروت شبكة شائعة)
    "001A11": ("Intel", "laptop", "💻"), "3C970E": ("Intel", "laptop", "💻"),
    "A0C589": ("Intel", "laptop", "💻"), "F8B156": ("Dell", "laptop", "💻"),
    "18DBF2": ("Dell", "laptop", "💻"), "D067E5": ("HP", "laptop", "💻"),
    "3417EB": ("HP", "laptop", "💻"), "A44CC8": ("Lenovo", "laptop", "💻"),
    "5CE0C5": ("Lenovo", "laptop", "💻"), "1C872C": ("ASUS", "laptop", "💻"),
    "049226": ("ASUS", "laptop", "💻"),
    "000C29": ("VMware", "computer", "🖥️"), "080027": ("VirtualBox", "computer", "🖥️"),
    # راوترات / أجهزة شبكة
    "F4F26D": ("TP-Link", "router", "📡"), "50C7BF": ("TP-Link", "router", "📡"),
    "AC84C6": ("D-Link", "router", "📡"), "1C7EE5": ("D-Link", "router", "📡"),
    "C0A00D": ("Netgear", "router", "📡"), "A02195": ("Netgear", "router", "📡"),
    "6C3B6B": ("MikroTik", "router", "📡"), "48A472": ("MikroTik", "router", "📡"),
    "24A43C": ("Ubiquiti", "router", "📡"), "FCECDA": ("Huawei", "router", "📡"),
    "00E04C": ("Realtek", "router", "📡"),
    # أجهزة IoT / منزلية ذكية
    "B827EB": ("Raspberry Pi", "iot", "🔌"), "DCA632": ("Raspberry Pi", "iot", "🔌"),
    "E45F01": ("Raspberry Pi", "iot", "🔌"), "2462AB": ("Espressif (ESP32/ESP8266)", "iot", "🔌"),
    "3C71BF": ("Espressif (ESP32/ESP8266)", "iot", "🔌"), "AC670C": ("Amazon (Echo/Kindle)", "iot", "🔌"),
    "F0272D": ("Amazon (Echo/Kindle)", "iot", "🔌"), "F4F5D8": ("Google (Chromecast/Nest)", "iot", "🔌"),
    "1CFE2B": ("Sony", "tv", "📺"), "A0BE49": ("Sony", "tv", "📺"),
    "7C1E52": ("LG", "tv", "📺"),
    "7CD1C3": ("Microsoft (Surface/Xbox)", "computer", "🎮"),
    "0050F2": ("Microsoft", "computer", "💻"),
}

def lookup_device_type(mac):
    if not mac:
        return {"vendor": "غير معروف", "device_type": "unknown", "icon": "❓"}
    oui = mac.upper().replace(":", "").replace("-", "")[:6]
    vendor, dtype, icon = OUI_VENDORS.get(oui, ("غير معروف", "unknown", "❓"))
    return {"vendor": vendor, "device_type": dtype, "icon": icon}

TYPE_EN = {
    "ARP Spoofing": "ARP Spoofing / MITM",
    "Port Scan": "Port Scanning",
    "ICMP Flood": "ICMP Flood",
    "SYN Flood": "SYN Flood",
    "ARP Flood": "ARP Flood (Disconnect Attack)",
}

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def get_local_mac_and_subnet(local_ip):
    """يلاقي الـ MAC وقناع الشبكة (netmask) بتوع الكارت اللي عليه الـ IP المحلي"""
    for iface, addrs in psutil.net_if_addrs().items():
        ip_ok, mac, netmask = False, None, None
        for a in addrs:
            if a.family == socket.AF_INET and a.address == local_ip:
                ip_ok = True
                netmask = a.netmask
            if a.family == psutil.AF_LINK:
                mac = a.address
        if ip_ok:
            return mac, netmask
    return None, None

LOCAL_IP = get_local_ip()
LOCAL_MAC, LOCAL_NETMASK = get_local_mac_and_subnet(LOCAL_IP)

def get_subnet_cidr():
    try:
        if LOCAL_NETMASK:
            net = ipaddress.IPv4Network(f"{LOCAL_IP}/{LOCAL_NETMASK}", strict=False)
            return str(net)
    except Exception:
        pass
    return f"{'.'.join(LOCAL_IP.split('.')[:3])}.0/24"  # افتراضي: شبكة منزلية عادية

# ─── تتبّع الأجهزة المكتشفة (لعمل خريطة الشبكة) ──────────
def note_device(ip, mac):
    if not ip or not mac or ip == "0.0.0.0":
        return
    with lock:
        discovered_devices[ip] = {"ip": ip, "mac": mac, "last_seen": time.time()}

def active_scan():
    """مسح فعّال: يبعت ARP request لكل الشبكة المحلية عشان يلاقي كل الأجهزة فورًا
    بدل ما ينتظر لحد ما جهاز يبعت حزمة ARP لوحده"""
    global scan_error
    cidr = get_subnet_cidr()
    try:
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr),
            timeout=3, retry=1, verbose=False
        )
        for _, rcv in ans:
            note_device(rcv[ARP].psrc, rcv[ARP].hwsrc)
        scan_error = None
        print(f"[*] مسح الشبكة ({cidr}): {len(ans)} جهاز")
    except Exception as e:
        scan_error = str(e)
        print(f"[!] فشل مسح الشبكة: {e}")

def scan_loop():
    while True:
        active_scan()
        time.sleep(60)

# ─── إضافة هجوم ──────────────────────────────────────────
def add_attack(attack_type, src_ip, target, severity, description, status="محظور"):
    with lock:
        attack = {
            "id": int(time.time() * 1000) + len(attacks),
            "type": attack_type,
            "type_en": TYPE_EN.get(attack_type, attack_type),
            "ip": src_ip,
            "target": target,
            "severity": severity,
            "status": status,
            "description": description,
            "time": datetime.now().strftime("%H:%M:%S"),
            "timestamp": time.time()
        }
        attacks.append(attack)
        attacks[:] = attacks[-500:]
        stats["total"] += 1
        if severity == "حرج":
            stats["critical"] += 1
        else:
            stats["warnings"] += 1
        if status == "محظور":
            stats["blocked"] += 1

        data = json.dumps(attack, ensure_ascii=False)
        dead = []
        for q in sse_listeners:
            try:
                q.append(data)
            except Exception:
                dead.append(q)
        for q in dead:
            sse_listeners.remove(q)

        print(f"[{attack['time']}] {severity} | {attack_type} | {src_ip} -> {target}")
        return attack

# ─── كشف ARP Spoofing و ARP Flood ────────────────────────
def detect_arp(pkt):
    if not pkt.haslayer(ARP):
        return
    arp = pkt[ARP]

    # أي حزمة ARP (طلب أو رد) بتكشفلنا وجود جهاز على الشبكة
    note_device(arp.psrc, arp.hwsrc)

    # تجاهل حركة الجهاز ده نفسه (زي طلبات المسح الفعّال active_scan)
    # عشان منعملش بلاغ هجوم على نفسنا
    if arp.psrc == LOCAL_IP:
        return

    # ARP Spoofing: تغيير MAC لـ IP موجود
    if arp.op == 2:
        ip  = arp.psrc
        mac = arp.hwsrc
        if ip in arp_table:
            if arp_table[ip] != mac:
                add_attack(
                    "ARP Spoofing", mac,
                    f"جهاز {ip}", "حرج",
                    f"تغيير MAC للـ IP {ip}: {arp_table[ip]} → {mac}"
                )
        else:
            arp_table[ip] = mac

    # ARP Flood: كمية ضخمة من حزم ARP
    now = time.time()
    src = arp.psrc or arp.hwsrc
    flood_tracker[src] = [t for t in flood_tracker[src] if now - t < 3]
    flood_tracker[src].append(now)
    if len(flood_tracker[src]) > 50:
        add_attack(
            "ARP Flood", arp.hwsrc,
            "الشبكة كاملة", "حرج",
            f"إرسال {len(flood_tracker[src])} حزمة ARP في 3 ثواني - هجوم قطع الإنترنت"
        )
        flood_tracker[src] = []

# ─── كشف Port Scan ───────────────────────────────────────
def detect_port_scan(pkt):
    if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
        return
    src   = pkt[IP].src
    dst   = pkt[IP].dst
    dport = pkt[TCP].dport
    flags = pkt[TCP].flags
    now   = time.time()

    if flags == 0x02:  # SYN فقط
        t = port_scan_tracker[src]
        if now - t["first_time"] > 5:
            t["ports"] = set()
            t["first_time"] = now
        t["ports"].add(dport)
        if len(t["ports"]) >= 10:
            add_attack(
                "Port Scan", src,
                dst if dst != LOCAL_IP else "هذا الجهاز", "حرج",
                f"فحص {len(t['ports'])} منفذ في 5 ثواني"
            )
            t["ports"] = set()
            t["first_time"] = now

# ─── كشف SYN Flood ───────────────────────────────────────
def detect_syn_flood(pkt):
    if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
        return
    if pkt[TCP].flags != 0x02:
        return
    src = pkt[IP].src
    now = time.time()
    syn_tracker[src] = [t for t in syn_tracker[src] if now - t < 2]
    syn_tracker[src].append(now)
    if len(syn_tracker[src]) > 100:
        add_attack(
            "SYN Flood", src,
            pkt[IP].dst, "حرج",
            f"إرسال {len(syn_tracker[src])} حزمة SYN في ثانيتين"
        )
        syn_tracker[src] = []

# ─── كشف ICMP Flood ──────────────────────────────────────
def detect_icmp_flood(pkt):
    if not (pkt.haslayer(IP) and pkt.haslayer(ICMP)):
        return
    src = pkt[IP].src
    now = time.time()
    key = f"icmp_{src}"
    flood_tracker[key] = [t for t in flood_tracker[key] if now - t < 2]
    flood_tracker[key].append(now)
    if len(flood_tracker[key]) > 50:
        add_attack(
            "ICMP Flood", src,
            pkt[IP].dst, "تحذير",
            f"إرسال {len(flood_tracker[key])} ping في ثانيتين"
        )
        flood_tracker[key] = []

# ─── معالج الحزم ─────────────────────────────────────────
def packet_handler(pkt):
    try:
        detect_arp(pkt)
        detect_port_scan(pkt)
        detect_syn_flood(pkt)
        detect_icmp_flood(pkt)
    except Exception:
        pass

def start_sniffing():
    global sniff_error
    print(f"[*] بدأ المراقبة على IP: {LOCAL_IP}")
    try:
        sniff(prn=packet_handler, store=False, filter="arp or tcp or icmp")
    except Exception as e:
        sniff_error = str(e)
        print("=" * 50)
        print("[!] فشلت مراقبة الشبكة — شغّل السكريبت كـ Administrator")
        print(f"[!] السبب: {e}")
        print("=" * 50)

# ─── API ─────────────────────────────────────────────────
@app.route("/")
def index():
    # send_from_directory serves the raw file bytes — no Jinja templating,
    # which would otherwise choke on the JSX's {{ }} inline-style syntax.
    return send_from_directory(TEMPLATE_DIR, "index.html")

@app.route("/api/attacks")
def get_attacks():
    with lock:
        return jsonify(list(reversed(attacks[-100:])))

@app.route("/api/stats")
def get_stats():
    with lock:
        return jsonify(stats)

@app.route("/api/clear", methods=["POST"])
def clear_attacks():
    with lock:
        attacks.clear()
        stats.update({"total": 0, "critical": 0, "warnings": 0, "blocked": 0})
    return jsonify({"ok": True})

@app.route("/api/devices")
def get_devices():
    with lock:
        devices = dict(discovered_devices)
        recent_attacks = list(attacks)

    result = []
    seen_ips = set(devices.keys()) | {LOCAL_IP}
    for ip in seen_ips:
        d = devices.get(ip, {})
        mac = d.get("mac") or (LOCAL_MAC if ip == LOCAL_IP else None)
        attacks_from_ip = [a for a in recent_attacks if a["ip"] == ip]
        info = lookup_device_type(mac)
        result.append({
            "ip": ip,
            "mac": mac or "؟؟:؟؟:؟؟:؟؟:؟؟:؟؟",
            "is_you": ip == LOCAL_IP,
            "last_seen": d.get("last_seen"),
            "suspicious": len(attacks_from_ip) > 0,
            "attack_count": len(attacks_from_ip),
            "vendor": info["vendor"],
            "device_type": "you" if ip == LOCAL_IP else info["device_type"],
            "icon": "💻" if ip == LOCAL_IP else info["icon"],
        })
    result.sort(key=lambda d: (not d["is_you"], d["ip"]))
    return jsonify(result)

@app.route("/api/scan", methods=["POST"])
def trigger_scan():
    threading.Thread(target=active_scan, daemon=True).start()
    return jsonify({"ok": True, "subnet": get_subnet_cidr()})

@app.route("/api/simulate", methods=["POST"])
def simulate_attack():
    form = request.get_json(force=True, silent=True) or {}
    attack = add_attack(
        form.get("type") or "ARP Spoofing",
        form.get("ip") or "192.168.1.???",
        form.get("target") or "هذا الجهاز",
        "حرج",
        form.get("desc") or "",
        status="محظور",
    )
    return jsonify(attack)

@app.route("/api/health")
def health():
    return jsonify({
        "ok": True,
        "monitoring": sniff_error is None,
        "error": sniff_error,
        "local_ip": LOCAL_IP,
        "local_mac": LOCAL_MAC,
        "subnet": get_subnet_cidr(),
        "scan_error": scan_error,
    })

@app.route("/api/stream")
def stream():
    my_queue = []
    with lock:
        sse_listeners.append(my_queue)

    def generate():
        yield "data: connected\n\n"
        while True:
            if my_queue:
                data = my_queue.pop(0)
                yield f"data: {data}\n\n"
            else:
                yield ": ping\n\n"
            time.sleep(0.3)

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

# ─── تشغيل ───────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 50)
    print("   CYBER SHIELD - Backend + Frontend")
    print("=" * 50)
    print(f"[*] IP الجهاز: {LOCAL_IP}")
    print("[!] شغّل كـ Administrator عشان مراقبة الشبكة تشتغل!")
    print(f"[*] افتح المتصفح على: http://localhost:5000")
    print("=" * 50)
    sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniff_thread.start()
    scan_thread = threading.Thread(target=scan_loop, daemon=True)
    scan_thread.start()
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
