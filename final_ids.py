from scapy.all import sniff, IP, ICMP, TCP
from collections import defaultdict, deque
import threading
import time

window_size = 10  # seconds
PORT_THRESHOLD = 10  # Unique ports in WINDOW_SIZE -> possible syn scan

# ICMP
icmp_count = defaultdict(deque)
icmp_threshold = 5

# SYN
syn_counts = defaultdict(deque)  # per source IP
syn_threshold = 5 # number of SYNs in window to raise alert
HALF_OPEN_TIMEOUT = 5  # seconds to wait for ACK
half_open = dict()  # Track half-open connections
R_counts=defaultdict(deque) 

# NULL and FIN scan
null_counts = defaultdict(deque)
fin_counts = defaultdict(deque)


#log file 
log_file="alert_logs.txt"
def alert_log(message):
    with open(log_file,"a") as f:
        f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")
        
running = True  # control cleanup thread


def cleanup_old_entries():
    #Periodically clean old entries to save up memory avoiding dict growing forever
    while running:
        now = time.time()

        # Clean ICMP counts
        for ip in list(icmp_count.keys()):
            while icmp_count[ip] and now - icmp_count[ip][0] > window_size:
                icmp_count[ip].popleft()
            if not icmp_count[ip]:   # del the ip from the icmp_count if the value of the ip(key) is empty
                del icmp_count[ip]

        # Clean SYN counts
        for ip in list(syn_counts.keys()):
            while syn_counts[ip] and now - syn_counts[ip][0][1] > window_size:
                syn_counts[ip].popleft()
            if not syn_counts[ip]:
                del syn_counts[ip]

        # Clean RST counts
        for ip in list(R_counts.keys()):
            while R_counts[ip] and now - R_counts[ip][0][1] > window_size:
                R_counts[ip].popleft()
            if not R_counts[ip]:
                del R_counts[ip]

        # Clean NULL counts
        for ip in list(null_counts.keys()):
            while null_counts[ip] and now - null_counts[ip][0][1] > window_size:
                null_counts[ip].popleft()
            if not null_counts[ip]:
                del null_counts[ip]

        # Clean FIN counts
        for ip in list(fin_counts.keys()):
            while fin_counts[ip] and now - fin_counts[ip][0][1] > window_size:
                fin_counts[ip].popleft()
            if not fin_counts[ip]:
                del fin_counts[ip]

        # Clean expired half-open connections
        expired = []
        for conn_key, ts in list(half_open.items()):
            if now - ts > HALF_OPEN_TIMEOUT:
                expired.append(conn_key)
        for conn_key in expired:
            if conn_key in half_open:
                del half_open[conn_key]

        time.sleep(2)  # run cleanup every 2 seconds


def packet_handler(pkt):
    if pkt.haslayer(IP):
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        protocol_type = pkt[IP].proto
        now = time.time()  # use real time now instead of pkt.time

        #----ICMP detection----

        if pkt.haslayer(ICMP):
            icmp_type = pkt[ICMP].type  # ECHO request = 8, ECHO reply = 0

            if icmp_type == 8:  # Count only echo requests (pings)
                icmp_count[src_ip].append(now)

                # Keep only timestamps within window_size
                while icmp_count[src_ip] and now - icmp_count[src_ip][0] > window_size:
                    icmp_count[src_ip].popleft()

                count = len(icmp_count[src_ip])
                if count > icmp_threshold:
                    print(f"[ALERT] ICMP FLOOD SUSPECT from {src_ip}! {count} pings in last {window_size}s")
                    alert = f"Possible ICMP Flood from {src_ip}"
                    alert_log(alert)

        elif pkt.haslayer(TCP):
            flags = str(pkt[TCP].flags)
            dport = pkt[TCP].dport
            key = (src_ip, dst_ip, dport)

            # ----SYN detection----
            if flags == 'S':
                syn_counts[src_ip].append((dport, now))
                half_open[key] = now

                # Remove old timestamps
                while syn_counts[src_ip] and now - syn_counts[src_ip][0][1] > window_size:
                    syn_counts[src_ip].popleft()

                # Count unique destination ports
                unique_ports = len(set(port for port, t in syn_counts[src_ip]))
                count = len(syn_counts[src_ip])
                print(f"[TCP SYN] {src_ip} -> {dst_ip}:{dport} count_last_{window_size}s: {count} packets")

                if count > syn_threshold:
                    print(f"[ALERT] High-rate SYN detected from {src_ip}! {count} SYNs in last {window_size}s")
                if unique_ports >= PORT_THRESHOLD:
                    print(f"[ALERT] Possible SYN scan from {src_ip}! {unique_ports} unique ports in last {window_size}s")
                    alert = f"Possible SYN Scan from {src_ip} to multiple ports"
                    alert_log(alert)

            # ACK means connection established, remove from half-open
            if flags == 'A':
                if key in half_open:
                    del half_open[key]

            # RST FLAGS
            if flags == 'R':
                R_counts[src_ip].append((dport, now))
                while R_counts[src_ip] and now -R_counts[src_ip][0][1] > window_size:
                    R_counts[src_ip].popleft()

                unique_R_ports = set(port for port, t in R_counts[src_ip])
                if len(unique_R_ports) > 5:
                    print(f"[ALERT]  SYN scan suspected from {src_ip}! {len(unique_R_ports)} unique ports in last {window_size}s")

          
                

            # ----NULL scan (no flags set)----
            if flags == '':
                null_counts[src_ip].append((dport, now))
                while null_counts[src_ip] and now - null_counts[src_ip][0][1] > window_size:
                    null_counts[src_ip].popleft()

                unique_null_ports = set(port for port, t in null_counts[src_ip])
                if len(unique_null_ports) > 10:
                    print(f"[ALERT] NULL scan suspected from {src_ip}! {len(unique_null_ports)} unique ports in last {window_size}s")
                    alert = f"Possible NULL Scan from {src_ip} to multiple ports"
                    alert_log(alert)

            # ----FIN scan----
            if flags == 'F':
                fin_counts[src_ip].append((dport, now))
                while fin_counts[src_ip] and now - fin_counts[src_ip][0][1] > window_size:
                    fin_counts[src_ip].popleft()

                unique_fin_ports = set(port for port, t in fin_counts[src_ip])
                if len(unique_fin_ports) > 10:
                    print(f"[ALERT] FIN scan suspected from {src_ip}! {len(unique_fin_ports)} unique ports in last {window_size}s")
                    alert = f"Possible FIN Scan from {src_ip} to multiple ports"
                    alert_log(alert)


# -------- RUN IN REAL TIME --------
if __name__ == "__main__":
    interface = input("Enter network interface to monitor (press Enter for default):  \n").strip()
    if not interface:
        interface = None

    print(f"Starting real-time monitoring on {interface or 'default'} interface...")

    cleanup_thread = threading.Thread(target=cleanup_old_entries, daemon=True)
    cleanup_thread.start()

    try:
        sniff(iface=interface, prn=packet_handler, store=0)
    except KeyboardInterrupt:
        print("\n[INFO] Stopping monitoring...")
        running = False
