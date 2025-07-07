# Anton Hagsäter
#----------- Python Script för IDS/IPS Slutuppgift
#-----Library import
import csv
import smtplib
import time
from datetime import datetime, timedelta
from collections import defaultdict
import subprocess
from scapy.all import sniff, IP, TCP, UDP # Scapy import för nätverksanalys, sniff n dissect
#--------------------------------------------------- 
# config-----------------------------------------
REPORT_FILE = "attack_report.csv"
ADMIN_EMAIL = "test@testmannen.se"
SMTP_SERVER = ""
SMTP_PORT = 587
SMTP_USER = "smtp_user"
SMTP_PASSWORD = "smtp_password"

ALLOWED_PORTS = {22, 80, 443}
PORT_THRESHOLD = 1024
CONNECTION_THRESHOLD = 100
INTERVAL = 300  # 5min
#-----------------------------------
traffic_data = defaultdict(list)   # dictionary för att lagra trafikdata
start_time = datetime.now() 
end_time = start_time + timedelta(seconds=INTERVAL)  #definierar start och sluttid för översikt
 #---- Mail funktion--------------
def send_email_alert(suspicious_ip, details):  #mail alert vid fuffens aktivitet och kopplar till smtp servern
    message = f"""\
Subject: ALERT - Spooky Network Activity from {suspicious_ip}

The following activity was detected: 
{details}
"""
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server: 
            server.starttls()  # Startar TLS encryption
            server.login(SMTP_USER, SMTP_PASSWORD) # Loggar in
            server.sendmail(SMTP_USER, ADMIN_EMAIL, message) # Skickar mail
        print(f"[INFO] Email alert sent for {suspicious_ip}")
    except Exception as e:
        print(f"[ERROR] Failed to send email: {e}")
#--------------------------------- Skickar mail till admin och ger feedback om det inte fungerar
def block_ip(ip): # blockerar IP-adress
    try:
        subprocess.run(["sudo", "ufw", "deny", "from", ip], check=True)
        print(f"[INFO] Blocked IP: {ip}")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to block IP {ip}: {e}")
#--------------------------------- blockerar IP-adress och notifierar om det inte fungerar
def packet_handler(packet): 
    global start_time, end_time 

    # hanterar specifikt ip packets
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        port = None

        # hanterar tcp/udp trafik
        if TCP in packet:
            port = packet[TCP].sport if packet[IP].src == src_ip else packet[TCP].dport
        elif UDP in packet:
            port = packet[UDP].sport if packet[IP].src == src_ip else packet[UDP].dport

        if port:
            timestamp = datetime.now()

            if start_time <= timestamp <= end_time:
                traffic_data[src_ip].append((timestamp, dst_ip, port))

def analyze_traffic(): # analyserar trafikdata
    global start_time, end_time
    flagged = []

    # analyserar samlad data under intervallet i traffic_data variabeln
    for ip, entries in traffic_data.items(): 
        connections = len(entries) #kallar på antalet anslutningar
        unusual_ports = [p for _, _, p in entries if p < PORT_THRESHOLD and p not in ALLOWED_PORTS] #listan identifierar ovanliga portar
        dst_counter = defaultdict(int) #skapar en tom dictionary för att räkna destinationer
        for _, dst, _ in entries: 
            dst_counter[dst] += 1

        high_dst_volume = any(count > 50 for count in dst_counter.values()) # identifierar hög volym av destinationer

        if connections > CONNECTION_THRESHOLD or unusual_ports or high_dst_volume:  #Om det finns mer än tillåtet antal anslutningar eller ovanliga portar
            details = f"{connections} connections, {len(unusual_ports)} unusual ports, {len(dst_counter)} unique destinations"
            flagged.append((ip, details))
            send_email_alert(ip, details) 
            block_ip(ip)

    if flagged: # rapporterar och blockerar IP-adresser
        with open(REPORT_FILE, "a", newline="") as csvfile:
            writer = csv.writer(csvfile)
            for ip, details in flagged:
                writer.writerow([datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ip, details])
        print(f"[INFO] Report updated ({len(flagged)} incidents).")

def run_monitoring():
    global start_time, end_time
    print("[STARTED] IDS system running...")

    # Sniff packets
    sniff(prn=packet_handler, store=0, timeout=INTERVAL)

    # analyserar
    analyze_traffic() #funktion kallelse som triggar analyze traffic funktionen

    # big old time reset
    start_time = datetime.now()
    end_time = start_time + timedelta(seconds=INTERVAL)

if __name__ == "__main__": # kör scriptet
    while True:
        run_monitoring()
        time.sleep(INTERVAL)
