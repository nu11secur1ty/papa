# ==============================================================================
# Tool: Ultimate Scientific PCAPNG Forensic & Threat Analyzer with Remediation
# Author: nu11secur1ty
# Description: Performs exhaustive deep packet inspection across Layers 2-7,
#              extracting granular parameters and injecting comprehensive 
#              remediation, risk assessment, and defensive documentation in English.
# ==============================================================================

import os
import glob
from datetime import datetime
from scapy.all import rdpcap, load_layer, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, DHCP, BOOTP

# Load Scapy's optional layers safely
load_layer("http")
from scapy.layers.http import HTTPRequest, HTTPResponse

# Automatically uses the current working directory where the script is executed
TARGET_DIR = os.getcwd()

def create_html_report(pcap_path, output_html_path):
    """
    Parses a PCAPNG file, executes deep packet inspection, and generates an 
    HTML forensic report complete with technical risk analysis, remediation guidelines,
    and a color-coded legend in English.
    """
    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        print(f"[-] Error reading {os.path.basename(pcap_path)}: {str(e)}")
        return False

    capture_time = "Unknown"
    if len(packets) > 0:
        try:
            capture_time = datetime.fromtimestamp(float(packets[0].time)).strftime('%Y-%m-%d %H:%M:%S')
        except Exception:
            capture_time = "Not available"

    # HTML structure with English text and color-coded legend
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>nu11secur1tyAI by nu11secur1ty - Ultimate Forensic Traffic & Threat Analysis Report</title>
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                line-height: 1.6;
                background-color: #f4f7f6;
                color: #333;
                margin: 40px;
            }}
            .container {{
                max-width: 1100px;
                background: #fff;
                padding: 30px;
                border-radius: 8px;
                box-shadow: 0 4px 15px rgba(0,0,0,0.1);
                margin: auto;
            }}
            h1 {{
                color: #2c3e50;
                border-bottom: 2px solid #e74c3c;
                padding-bottom: 10px;
            }}
            .meta {{
                font-size: 0.95em;
                color: #555;
                background: #ecf0f1;
                padding: 15px;
                border-radius: 6px;
                margin-bottom: 20px;
            }}
            .legend-box {{
                background: #fff;
                border: 1px solid #bdc3c7;
                padding: 15px;
                margin-bottom: 25px;
                border-radius: 6px;
            }}
            .legend-item {{
                display: inline-block;
                margin-right: 20px;
                font-size: 0.85em;
                font-weight: bold;
            }}
            .legend-color {{
                display: inline-block;
                width: 15px;
                height: 15px;
                margin-right: 5px;
                vertical-align: middle;
                border-radius: 3px;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 15px;
                margin-bottom: 25px;
            }}
            th, td {{
                padding: 10px;
                border: 1px solid #ddd;
                text-align: left;
                font-size: 0.85em;
                font-family: monospace;
            }}
            th {{
                background-color: #2c3e50;
                color: white;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            }}
            .threat {{
                background: #fff0f0;
                border-left: 5px solid #c0392b;
                padding: 15px;
                margin: 15px 0;
                border-radius: 4px;
                font-size: 0.9em;
            }}
            .issue {{
                background: #fff8f0;
                border-left: 5px solid #e67e22;
                padding: 15px;
                margin: 15px 0;
                border-radius: 4px;
                font-size: 0.9em;
            }}
            .info {{
                background: #f0f7ff;
                border-left: 5px solid #3498db;
                padding: 15px;
                margin: 15px 0;
                border-radius: 4px;
                font-size: 0.9em;
            }}
            .remediation-box {{
                background: #f8f9fa;
                border: 1px dashed #bdc3c7;
                padding: 10px 15px;
                margin-top: 10px;
                border-radius: 4px;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                font-size: 0.88em;
                color: #2c3e50;
            }}
            .footer {{
                margin-top: 30px;
                font-size: 0.85em;
                color: #95a5a6;
                text-align: center;
                border-top: 1px solid #ecf0f1;
                padding-top: 15px;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>nu11secur1tyAI by nu11secur1ty - Ultimate Scientific Forensic & Threat Analysis Report</h1>
            <div class="meta">
                <strong>File Name:</strong> {os.path.basename(pcap_path)}<br>
                <strong>Capture Timestamp:</strong> {capture_time}<br>
                <strong>Total Packets Scanned:</strong> {len(packets)}<br>
                <strong>Engine:</strong> nu11secur1tyAI by nu11secur1ty Ultimate Forensic Deep Intelligence Engine
            </div>

            <!-- Color-Coded Severity Legend -->
            <div class="legend-box">
                <strong>Severity & Event Legend:</strong><br><br>
                <div class="legend-item"><span class="legend-color" style="background-color: #c0392b;"></span>Critical Threat / Attack Vector</div>
                <div class="legend-item"><span class="legend-color" style="background-color: #e67e22;"></span>Warning / Protocol Issue</div>
                <div class="legend-item"><span class="legend-color" style="background-color: #3498db;"></span>Informational Event / Resolution</div>
            </div>
    """

    findings = []
    total_packets = len(packets)
    
    tcp_count = 0
    udp_count = 0
    icmp_count = 0
    arp_count = 0
    dns_count = 0
    dhcp_count = 0
    http_count = 0
    other_count = 0

    syn_counter = {}
    ip_activity = {}
    port_scan_tracker = {}
    ip_port_scan_ports = {}
    brute_force_tracker = {}

    for index, packet in enumerate(packets, start=1):
        try:
            pkt_time = datetime.fromtimestamp(float(packet.time)).strftime('%H:%M:%S.%f')[:-3]
        except Exception:
            pkt_time = "Unknown Time"

        try:
            # Layer distribution counting
            if packet.haslayer(TCP):
                tcp_count += 1
            elif packet.haslayer(UDP):
                udp_count += 1
            elif packet.haslayer(ICMP):
                icmp_count += 1
            elif packet.haslayer(ARP):
                arp_count += 1
            else:
                other_count += 1

            if packet.haslayer(DNS):
                dns_count += 1
            if packet.haslayer(DHCP) or packet.haslayer(BOOTP):
                dhcp_count += 1
            if packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse):
                http_count += 1

            src_ip = packet[IP].src if packet.haslayer(IP) else "Non-IP"
            dst_ip = packet[IP].dst if packet.haslayer(IP) else "Non-IP"

            if src_ip != "Non-IP":
                ip_activity[src_ip] = ip_activity.get(src_ip, 0) + 1

            # 1. ARP Forensic Analysis (ARP Spoofing / Poisoning Detection)
            if packet.haslayer(ARP):
                arp_layer = packet.getlayer(ARP)
                if arp_layer.op == 2:  # ARP Reply
                    findings.append({
                        "html": f"<div class='threat'><strong>[{pkt_time}] Packet #{index} [Layer 2 - ARP Spoofing / Cache Poisoning]:</strong><br>"
                                f"• <b>Protocol:</b> ARP (Address Resolution Protocol)<br>"
                                f"• <b>Operation Code:</b> {arp_layer.op} (ARP Reply)<br>"
                                f"• <b>Hardware Source (hwsrc):</b> {arp_layer.hwsrc} | <b>Protocol Source (psrc):</b> {arp_layer.psrc}<br>"
                                f"• <b>Scientific Context:</b> Unsolicited ARP reply signature detected. Potential Man-in-the-Middle (MITM) vector targeting local segment mapping.<br>"
                                f"<div class='remediation-box'>"
                                f"<strong>📌 Documentation & Defensive Strategy:</strong><br>"
                                f"• <b>Where is the problem:</b> Data Link Layer (Layer 2) within the local area network (LAN).<br>"
                                f"• <b>Why it must be fixed:</b> Allows a malicious actor to redirect traffic through their device, leading to packet sniffing, data tampering, or session hijacking.<br>"
                                f"• <b>How to fix it:</b> Use static ARP entries (`arp -s`) for critical hosts like the gateway and configure DHCP Snooping on network switches.<br>"
                                f"• <b>Defensive posture:</b> Enable Dynamic ARP Inspection (DAI) on enterprise switches and install host-based IDS/IPS monitoring agents."
                                f"</div></div>"
                    })

            # 2. ICMP Tunneling / Data Exfiltration Analysis
            if packet.haslayer(ICMP):
                icmp_layer = packet.getlayer(ICMP)
                icmp_payload_len = len(packet[ICMP].payload) if packet.haslayer(ICMP) else 0
                if icmp_payload_len > 100:
                    findings.append({
                        "html": f"<div class='threat'><strong>[{pkt_time}] Packet #{index} [Layer 3 - ICMP Tunneling / Data Exfiltration]:</strong><br>"
                                f"• <b>Flow:</b> {src_ip} -> {dst_ip}<br>"
                                f"• <b>ICMP Type / Code:</b> Type {icmp_layer.type}, Code {icmp_layer.code} | Payload Size: {icmp_payload_len} bytes<br>"
                                f"• <b>Scientific Context:</b> Unusually large ICMP payload detected. Commonly utilized for covert data exfiltration or tunneling command-and-control traffic.<br>"
                                f"<div class='remediation-box'>"
                                f"<strong>📌 Documentation & Defensive Strategy:</strong><br>"
                                f"• <b>Where is the problem:</b> Network Layer (Layer 3) via ICMP echo requests/replies.<br>"
                                f"• <b>Why it must be fixed:</b> Bypasses standard firewall stateful rules and allows unauthorized data leakage or remote access.<br>"
                                f"• <b>How to fix it:</b> Rate-limit ICMP traffic on perimeter firewalls and inspect raw payloads for encoded or structured data blocks.<br>"
                                f"• <b>Defensive posture:</b> Deploy behavioral Network Detection and Response (NDR) solutions monitoring protocol anomaly metrics."
                                f"</div></div>"
                    })

            # 3. Transport Layer Analysis (TCP Resets, SYN Floods, Port Scans, Brute-Force, Legacy Protocols)
            if packet.haslayer(TCP):
                tcp_layer = packet.getlayer(TCP)
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
                flags = tcp_layer.sprintf("%TCP.flags%")
                seq_num = tcp_layer.seq
                ack_num = tcp_layer.ack

                # Enhanced Port Scan Detection (Tracking unique destination ports per source IP)
                if src_ip != "Non-IP" and dst_ip != "Non-IP":
                    ip_port_scan_ports.setdefault(src_ip, set()).add(dst_port)
                    if len(ip_port_scan_ports[src_ip]) >= 15:
                        # Log only once per threshold trigger to prevent flood reports
                        if src_ip not in port_scan_tracker:
                            port_scan_tracker[src_ip] = True
                            findings.append({
                                "html": f"<div class='threat'><strong>[{pkt_time}] Packet #{index} [Layer 4 - Advanced Port Scan Activity Detected]:</strong><br>"
                                        f"• <b>Source IP:</b> {src_ip} is probing multiple destination ports (Total unique ports: {len(ip_port_scan_ports[src_ip])}).<br>"
                                        f"• <b>Scientific Context:</b> Horizontal/Vertical port scanning signature identified. Enumerating active services prior to targeted exploitation.<br>"
                                        f"<div class='remediation-box'>"
                                        f"<strong>📌 Documentation & Defensive Strategy:</strong><br>"
                                        f"• <b>Where is the problem:</b> Transport Layer (Layer 4) reconnaissance phase.<br>"
                                        f"• <b>Why it must be fixed:</b> Exposes service layout and vulnerable software versions to attackers.<br>"
                                        f"• <b>How to fix it:</b> Implement port-knocking, hide unused listening ports, and configure automated fail2ban blocking rules.<br>"
                                        f"• <b>Defensive posture:</b> Deploy Intrusion Detection Systems (IDS) like Snort or Suricata with portscan detection preprocessors."
                                        f"</div></div>"
                            })

                # Brute-Force / Credential Stuffing Detection (SSH, RDP, SMB, FTP)
                if dst_port in [22, 3389, 445, 21] and 'S' not in flags:
                    brute_force_tracker[src_ip] = brute_force_tracker.get(src_ip, 0) + 1
                    if brute_force_tracker[src_ip] == 20:
                        findings.append({
                            "html": f"<div class='threat'><strong>[{pkt_time}] Packet #{index} [Layer 4/7 - Brute-Force / Credential Stuffing Attack]:</strong><br>"
                                    f"• <b>Flow:</b> {src_ip}:{src_port} -> {dst_ip}:{dst_port}<br>"
                                    f"• <b>Scientific Context:</b> High frequency of connection/authentication attempts to sensitive service port ({dst_port}).<br>"
                                    f"<div class='remediation-box'>"
                                    f"<strong>📌 Documentation & Defensive Strategy:</strong><br>"
                                    f"• <b>Where is the problem:</b> Application/Transport layers (Authentication interface).<br>"
                                    f"• <b>Why it must be fixed:</b> Risk of account takeover through credential guessing or dictionary attacks.<br>"
                                    f"• <b>How to fix it:</b> Enforce Multi-Factor Authentication (MFA), account lockout policies, and SSH key-based authentication only.<br>"
                                    f"• <b>Defensive posture:</b> Integrate Fail2Ban or cloud-native Identity Protection safeguards."
                                    f"</div></div>"
                        })

                # TCP RST Flag Analysis
                if tcp_layer.flags & 0x04:  # RST Flag
                    findings.append({
                        "html": f"<div class='issue'><strong>[{pkt_time}] Packet #{index} [Layer 4 - TCP Reset / Session Termination]:</strong><br>"
                                f"• <b>Flow:</b> {src_ip}:{src_port} -> {dst_ip}:{dst_port}<br>"
                                f"• <b>TCP Flags:</b> {flags} (RST bit active, hex: 0x04)<br>"
                                f"• <b>Parameters:</b> Seq: {seq_num}, Ack: {ack_num}<br>"
                                f"• <b>Scientific Context:</b> Stateful firewall drop, closed port refusal, or forged RST injection hijacking an active session.<br>"
                                f"<div class='remediation-box'>"
                                f"<strong>📌 Documentation & Defensive Strategy:</strong><br>"
                                f"• <b>Where is the problem:</b> Transport Layer (Layer 4) during TCP session establishment or maintenance.<br>"
                                f"• <b>Why it must be fixed:</b> Frequent unexpected RST packets indicate unstable routes, aggressive firewall rules, or active connection tearing attacks.<br>"
                                f"• <b>How to fix it:</b> Review stateful firewall rules and monitor link quality (Packet Loss/Jitter).<br>"
                                f"• <b>Defensive posture:</b> Use encrypted and spoof-resilient protocols and enforce SYN cookies."
                                f"</div></div>"
                    })
                elif 'S' in flags and 'A' not in flags:
                    syn_counter[src_ip] = syn_counter.get(src_ip, 0) + 1
                    if syn_counter[src_ip] == 10:
                        findings.append({
                            "html": f"<div class='threat'><strong>[{pkt_time}] Packet #{index} [Layer 4 - SYN Flood DoS Signature]:</strong><br>"
                                    f"• <b>Source IP:</b> {src_ip} targeting Port {dst_port}<br>"
                                    f"• <b>TCP Flags:</b> {flags} (SYN Handshake Initiation)<br>"
                                    f"• <b>Parameters:</b> Cumulative SYN count from source = {syn_counter[src_ip]}<br>"
                                    f"• <b>Scientific Context:</b> High-frequency half-open connection flood causing backlog queue exhaustion on target system.<br>"
                                    f"<div class='remediation-box'>"
                                    f"<strong>📌 Documentation & Defensive Strategy:</strong><br>"
                                    f"• <b>Where is the problem:</b> Transport Layer (Layer 4) – Operating system TCP handshake stack.<br>"
                                    f"• <b>Why it must be fixed:</b> Leads to memory and resource exhaustion, rendering services unavailable to legitimate users.<br>"
                                    f"• <b>How to fix it:</b> Enable SYN cookies in the OS kernel and shorten half-open timeouts.<br>"
                                    f"• <b>Defensive posture:</b> Deploy DDoS mitigation appliances (Rate Limiting, SYN Proxies) in front of critical servers."
                                    f"</div></div>"
                        })

                # Unencrypted Legacy Protocols (Telnet, FTP, HTTP cleartext ports)
                if dst_port in [23, 21, 80]:
                    findings.append({
                        "html": f"<div class='issue'><strong>[{pkt_time}] Packet #{index} [Layer 4/7 - Unencrypted Legacy Protocol / Plaintext Traffic]:</strong><br>"
                                f"• <b>Flow:</b> {src_ip}:{src_port} -> {dst_ip}:{dst_port}<br>"
                                f"• <b>Scientific Context:</b> Traffic detected on unencrypted management/transfer port ({dst_port}). Credentials and data exposed to sniffing.<br>"
                                f"<div class='remediation-box'>"
                                f"<strong>📌 Documentation & Defensive Strategy:</strong><br>"
                                f"• <b>Where is the problem:</b> Application and Transport layers (Layer 4/7) using unencrypted protocols.<br>"
                                f"• <b>Why it must be fixed:</b> Credentials and data are transmitted in plaintext, exposing them to network sniffing.<br>"
                                f"• <b>How to fix it:</b> Disable legacy services (Telnet, FTP, HTTP) and migrate to secure alternatives (SSH, SFTP, HTTPS).<br>"
                                f"• <b>Defensive posture:</b> Enforce firewall ACLs blocking ports 21 and 23 outside isolated management segments."
                                f"</div></div>"
                    })

            # 4. DNS Analysis & DNS Tunneling / Exfiltration Inspection
            if packet.haslayer(DNS):
                dns_layer = packet.getlayer(DNS)
                if dns_layer.qr == 0 and packet.haslayer(DNSQR):
                    qname = packet.getlayer(DNSQR).qname.decode(errors='ignore')
                    clean_qname = qname.strip('.')
                    
                    if len(clean_qname) > 50:
                        findings.append({
                            "html": f"<div class='threat'><strong>[{pkt_time}] Packet #{index} [Layer 7 - Potential DNS Tunneling / Data Exfiltration]:</strong><br>"
                                    f"• <b>Source:</b> {src_ip} -> <b>Query Domain:</b> <code>{clean_qname}</code> (Length: {len(clean_qname)})<br>"
                                    f"• <b>Scientific Context:</b> Abnormally long domain string detected in DNS query. Indicator of DNS tunneling or encoded data exfiltration.<br>"
                                    f"<div class='remediation-box'>"
                                    f"<strong>📌 Documentation & Defensive Strategy:</strong><br>"
                                    f"• <b>Where is the problem:</b> Application Layer (Layer 7) – DNS protocol query structure.<br>"
                                    f"• <b>Why it must be fixed:</b> Attackers use DNS queries to tunnel malicious payloads or steal files past standard firewalls.<br>"
                                    f"• <b>How to fix it:</b> Monitor DNS query length distributions, entropy scores, and frequency per client.<br>"
                                    f"• <b>Defensive posture:</b> Implement advanced DNS security solutions with machine learning-based tunneling detection."
                                    f"</div></div>"
                        })
                    else:
                        findings.append({
                            "html": f"<div class='info'><strong>[{pkt_time}] Packet #{index} [Layer 7 - DNS Query Domain Resolution]:</strong><br>"
                                    f"• <b>Source:</b> {src_ip} -> <b>Query Domain:</b> <code>{clean_qname}</code><br>"
                                    f"• <b>Scientific Context:</b> Domain name lookup request. Useful for tracking external infrastructure communication and C2 lookups.<br>"
                                    f"<div class='remediation-box'>"
                                    f"<strong>📌 Documentation & Defensive Strategy:</strong><br>"
                                    f"• <b>Where is the problem:</b> Application Layer (Layer 7) – Domain name resolution requests.<br>"
                                    f"• <b>Why it must be fixed / monitored:</b> Suspicious or unrecognized domains may indicate Command & Control (C2) callbacks.<br>"
                                    f"• <b>How to fix it:</b> Audit query logs for anomalies and verify against Threat Intelligence feeds.<br>"
                                    f"• <b>Defensive posture:</b> Implement secure filtering DNS resolvers (DNSSEC, enterprise controls)."
                                    f"</div></div>"
                        })

            # 5. HTTP Payload Injection (XSS, SQLi, Remote Code Execution, Path Traversal)
            if packet.haslayer(HTTPRequest):
                http_req = packet.getlayer(HTTPRequest)
                path = http_req.Path.decode(errors='ignore') if http_req.Path else ""
                method = http_req.Method.decode(errors='ignore') if http_req.Method else ""
                
                if any(sig in path.lower() for sig in ["<script>", "alert(", "union select", "exec(", "eval(", "../", "..\\", "cmd.exe", "/bin/sh"]):
                    findings.append({
                        "html": f"<div class='threat'><strong>[{pkt_time}] Packet #{index} [Layer 7 - Web Attack Payload Injection (XSS/SQLi/RCE)]:</strong><br>"
                                f"• <b>Method / Path:</b> {method} <code>{path}</code><br>"
                                f"• <b>Flow:</b> {src_ip} -> {dst_ip}<br>"
                                f"• <b>Scientific Context:</b> Malicious signature string matched in input vector. Indicates absence of parameter sanitization.<br>"
                                f"<div class='remediation-box'>"
                                f"<strong>📌 Documentation & Defensive Strategy:</strong><br>"
                                f"• <b>Where is the problem:</b> Application Layer (Layer 7) – Web parameter input vectors.<br>"
                                f"• <b>Why it must be fixed:</b> Allows arbitrary code execution, cross-site scripting, or direct database manipulation.<br>"
                                f"• <b>How to fix it:</b> Use parameterized queries (Prepared Statements) and strict input validation/escaping.<br>"
                                f"• <b>Defensive posture:</b> Deploy a Web Application Firewall (WAF) and configure strict Content Security Policy (CSP) headers."
                                f"</div></div>"
                    })

        except Exception:
            continue

    # Tables and layout formatting
    html_content += f"""
        <h3>Exhaustive Protocol & Traffic Distribution Matrix</h3>
        <table>
            <tr><th>Protocol Layer / Vector Metric</th><th>Packet Count / Volume</th><th>Forensic Significance</th></tr>
            <tr><td>Total Processed Packets</td><td>{total_packets}</td><td>Complete Capture Scope</td></tr>
            <tr><td>TCP (Transmission Control Protocol)</td><td>{tcp_count}</td><td>Reliable Session Layer (Layer 4)</td></tr>
            <tr><td>UDP (User Datagram Protocol)</td><td>{udp_count}</td><td>Datagram Transport Layer (Layer 4)</td></tr>
            <tr><td>DNS (Domain Name System)</td><td>{dns_count}</td><td>Name Resolution (Layer 7)</td></tr>
            <tr><td>HTTP (Hypertext Transfer Protocol)</td><td>{http_count}</td><td>Web Application Traffic (Layer 7)</td></tr>
            <tr><td>ARP (Address Resolution Protocol)</td><td>{arp_count}</td><td>MAC Sublayer / Mapping (Layer 2)</td></tr>
            <tr><td>ICMP (Internet Control Message Protocol)</td><td>{icmp_count}</td><td>Network Diagnostics (Layer 3)</td></tr>
            <tr><td>DHCP (Dynamic Host Configuration)</td><td>{dhcp_count}</td><td>IP Assignment (Layer 7)</td></tr>
            <tr><td>Other / Unclassified Protocols</td><td>{other_count}</td><td>Miscellaneous / Proprietary</td></tr>
            <tr><td>Total Logged Forensic Findings / Threats</td><td>{len(findings)}</td><td>Isolated Anomalies & Attacks</td></tr>
        </table>

        <h3>Active Endpoint Volume Breakdown (Top IP Sources)</h3>
        <table>
            <tr><th>Source IP Address</th><th>Packet Count</th><th>Activity Share (%)</th></tr>
    """

    for ip, count in sorted(ip_activity.items(), key=lambda x: x[1], reverse=True)[:5]:
        share = (count / total_packets) * 100 if total_packets > 0 else 0
        html_content += f"<tr><td>{ip}</td><td>{count}</td><td>{share:.2f}%</td></tr>"

    html_content += """
        </table>
        <h3 style="margin-top: 25px;">Detailed Scientific Forensic Event Log & Remediation Guide</h3>
    """

    if not findings:
        html_content += "<div class='info'><strong>[✔] Status:</strong> No security violations or critical threat signatures identified within the scope of parameters.</div>"
    else:
        for f in findings:
            html_content += f["html"]

    html_content += """
            <div class="footer">
                Generated automatically by nu11secur1tyAI Ultimate Forensic Deep Intelligence Engine by nu11secur1ty.
            </div>
        </div>
    </body>
    </html>
    """

    with open(output_html_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    return True

def main():
    print(f"[+] Scanning working directory for PCAPNG files: {TARGET_DIR}")

    pcap_files = glob.glob(os.path.join(TARGET_DIR, "*.pcapng"))
    
    if not pcap_files:
        print("[!] No .pcapng files found in this directory. Place your capture files here.")
        return

    print(f"[+] Found {len(pcap_files)} file(s) to process...")

    for file_path in pcap_files:
        output_path = os.path.splitext(file_path)[0] + "_remediation_report.html"
        if create_html_report(file_path, output_path):
            print(f"[✔] Forensic report with remediation generated: {os.path.basename(output_path)}")

if __name__ == "__main__":
    main()
