import json
import queue
import threading
import time
import logging
logging.getLogger("werkzeug").setLevel(logging.ERROR)
from datetime import datetime
from flask import Flask, Response, render_template, jsonify
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

app = Flask(__name__)
packet_queue = queue.Queue(maxsize=300)
stats = {
    "total": 0,
    "TCP": 0,
    "UDP": 0,
    "ICMP": 0,
    "OTHER": 0,
    "start_time": time.time(),
}
stats_lock = threading.Lock()


def parse_payload(raw_bytes, limit=80):
    text = raw_bytes.decode("utf-8", errors="replace").strip()
    cleaned = "".join(ch if ch.isprintable() else "." for ch in text)
    return cleaned[:limit] + ("..." if len(cleaned) > limit else "")


def handle_packet(packet):
    if not packet.haslayer(IP):
        return

    proto = "OTHER"
    sport = None
    dport = None

    if packet.haslayer(TCP):
        proto = "TCP"
        sport = packet[TCP].sport
        dport = packet[TCP].dport
    elif packet.haslayer(UDP):
        proto = "UDP"
        sport = packet[UDP].sport
        dport = packet[UDP].dport
    elif packet.haslayer(ICMP):
        proto = "ICMP"

    payload_text = parse_payload(packet[Raw].load) if packet.haslayer(Raw) else ""

    entry = {
        "time": datetime.now().strftime("%H:%M:%S"),
        "proto": proto,
        "src": packet[IP].src,
        "dst": packet[IP].dst,
        "sport": sport,
        "dport": dport,
        "length": len(packet),
        "payload": payload_text,
    }

    with stats_lock:
        stats["total"] += 1
        stats[proto] = stats.get(proto, 0) + 1

    try:
        packet_queue.put_nowait(entry)
    except queue.Full:
        try:
            packet_queue.get_nowait()
            packet_queue.put_nowait(entry)
        except queue.Empty:
            pass


def start_sniffer_background():
    sniff(filter="ip", prn=handle_packet, store=False)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/stats")
def get_stats():
    with stats_lock:
        return jsonify(stats)


@app.route("/stream")
def stream():
    def event_stream():
        while True:
            try:
                pkt = packet_queue.get(timeout=1.0)
                with stats_lock:
                    current_stats = dict(stats)
                data = json.dumps({"packet": pkt, "stats": current_stats})
                yield f"data: {data}\n\n"
            except queue.Empty:
                yield ": keep-alive\n\n"

    return Response(event_stream(), mimetype="text/event-stream")


if __name__ == "__main__":
    sniffer_thread = threading.Thread(target=start_sniffer_background, daemon=True)
    sniffer_thread.start()
    print("[*] Live Web Sniffer running at http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)