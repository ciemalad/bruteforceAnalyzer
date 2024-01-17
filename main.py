from tkinter import filedialog
import customtkinter
import re
from collections import defaultdict
import platform
import ctypes
import sys
import requests
import ipaddress
from datetime import datetime
from datetime import timedelta
import psycopg2
from socket import getservbyport

customPath=""

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def db_check_value(ip_addr):
    conn = psycopg2.connect(
        dbname='ip_rep',
        user='postgres',
        password='ZAQ!2wsx',
        host='127.0.0.1',
        port='5432'
    )

    cursor = conn.cursor()

    query = "SELECT ip_address FROM ip_addr WHERE ip_address = %s"

    cursor.execute(query, (ip_addr,))
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    if rows:
        return True
    else:
        return False

def db_get_value(ip_addr):
    conn = psycopg2.connect(
        dbname='ip_rep',
        user='postgres',
        password='ZAQ!2wsx',
        host='127.0.0.1',
        port='5432'
    )

    cursor = conn.cursor()

    query = "SELECT vt_rep,vt_vs,aipdb_s FROM ip_addr WHERE ip_address = %s"

    cursor.execute(query, (ip_addr,))
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    if rows:
        return rows[0]

def db_add(ip_address, vt_rep, vt_vs, aipdb_s):
    try:
        conn = psycopg2.connect(
            dbname='ip_rep',
            user='postgres',
            password='ZAQ!2wsx',
            host='127.0.0.1',
            port='5432'
        )

        cursor = conn.cursor()

        query = "INSERT INTO ip_addr (ip_address, vt_rep, vt_vs, aipdb_s) VALUES (%s, %s, %s, %s)"
        cursor.execute(query, (ip_address, vt_rep, vt_vs, aipdb_s))

        conn.commit()
        cursor.close()
        conn.close()

        print("Dane zostały dodane do bazy danych.")
    except Exception as e:
        print(f"Wystąpił błąd: {e}")

def is_private_ip(ip_address):
    try:
        ip = ipaddress.ip_address(ip_address)
        return ip.is_private
    except ValueError:
        return False

def get_abuse_score(ip_address):
    with open('apikeys.txt', 'r') as file:
        API_KEY = file.readline()
    url = f'https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}'
    headers = {
        'Key': API_KEY,
        'Accept': 'application/json'
    }

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            abuse_score = data['data']['abuseConfidenceScore']
            return abuse_score
        else:
            print(f'Błąd: {response.status_code}')
            return None
    except requests.RequestException as e:
        print(f'Wyjątek: {e}')
        return None

def check_ip_virustotal_reputation(ip):
    with open('apikeys.txt', 'r') as file:
        file.readline()
        api_key = file.readline()
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
    headers = {
        'x-apikey': api_key
    }
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            if 'data' in data:
                attributes = data['data']['attributes']
                if 'reputation' in attributes:
                    reputation = attributes['reputation']
                    if 'last_analysis_results' in attributes:
                        analysis_results = attributes['last_analysis_results']
                        vendors_count = len(set(result['engine_name'] for result in analysis_results.values()))
                        flagged_count = sum(
                            1 for result in analysis_results.values() if result['category'] == 'malicious')
                        flagged_count=str(flagged_count)+'/'+str(vendors_count)
                        return reputation, flagged_count
    except requests.RequestException as e:
        print(f"Error checking VirusTotal reputation for IP {ip}: {e}")

    return None, None

def get_log_paths():
    global customPath
    log_files = []
    system = platform.system()

    if system == "Windows":
        log_files.extend([
            #'C:\\Windows\\System32\\winevt\\Logs\\Security.evtx',
            #'C:\\Windows\\System32\\winevt\\Logs\\Application.evtx',
        ])
    elif system == "Linux":
        log_files.extend([
            '/var/log/auth.log',
            '/var/log/syslog',
        ])
    else:
        print("Nieobsługiwany system operacyjny.")
    if(customPath.strip()!= ""):
        log_files.append(customPath)
    return log_files

def parse_logs(log_files, phrase='Failed'):
    brute_force_attempts = defaultdict(list)

    date_formats = [
        ('%Y-%m-%d %H:%M:%S', r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}'),
        ('%m/%d/%Y %H:%M:%S', r'\b\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}\b'),
        ('%Y-%m-%dT%H:%M:%S', r'\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\b'),
        ('%b %d %H:%M:%S', r'\b\w{3} \d{2} \d{2}:\d{2}:\d{2}\b')
    ]

    for log_file in log_files:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as file:
                for line in file:
                    if phrase in line:
                        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                        if ip_match:
                            ip_address = ip_match.group()
                            try:
                                port_number = line.split(' ')[-1].strip()
                            except IndexError:
                                port_number = "N/A"
                            for date_format, regex_pattern in date_formats:
                                time_match = re.search(regex_pattern, line)
                                if time_match:
                                    timestamp_str = time_match.group()
                                    try:
                                        timestamp = datetime.strptime(timestamp_str, date_format)
                                        brute_force_attempts[ip_address].append((timestamp, port_number))
                                    except ValueError:
                                        pass
                                    break

    return brute_force_attempts



def detect_brute_force(attempts, threshold=5, time_threshold_minutes=2):
    potential_attackers = defaultdict(int)
    for ip, data in attempts.items():
        ip_ports = defaultdict(int)
        for timestamp, port in data:
            ip_ports[port] += 1

        for port, attempts_count in ip_ports.items():
            if attempts_count >= threshold:
                recent_attempts = [ts for ts, p in data if p == port and (datetime.now() - ts) <= timedelta(minutes=time_threshold_minutes)]
                if len(recent_attempts) >= threshold:
                    potential_attackers[(ip, port)] = attempts_count

    filtered_attackers = [ip_port for ip_port, count in potential_attackers.items() if count >= threshold]
    return filtered_attackers

def open_file_dialog():
    global customPath
    file_path = filedialog.askopenfilename()
    print("Wybrany plik:", file_path)
    customPath=file_path

def runScan(app):
    log_files_to_analyze = get_log_paths()

    potential_attackers=[]

    phrase = app.checkbox_frame.checkboxes[2].get()
    time = app.checkbox_frame.checkboxes[3].get()
    times = app.checkbox_frame.checkboxes[4].get()

    #app.checkbox_frame.checkboxes[2].delete(0,"end")
    #app.checkbox_frame.checkboxes[3].delete(0,"end")
    #app.checkbox_frame.checkboxes[4].delete(0,"end")
    #print(phrase)
    #print(time)
    #print(times)
    if phrase.strip() != "":
        attempts = parse_logs(log_files_to_analyze, phrase)
    else:
        attempts = parse_logs(log_files_to_analyze)

    if (time !="" and times !=""):
        potential_attackers = detect_brute_force(attempts, int(times), float(time))
    elif (time !="" and times ==""):
        potential_attackers = detect_brute_force(attempts, time_threshold_minutes=float(time))
    elif (time =="" and times !=""):
        potential_attackers = detect_brute_force(attempts, int(times))
    else:
        potential_attackers = detect_brute_force(attempts)

    if potential_attackers:
        app.checkbox_frame1 = MyScrollableCheckboxFrame(app, "List of attacks", values=potential_attackers)
        app.checkbox_frame1.grid(row=0, column=1, padx=10, pady=(10, 0), sticky="nsew", columnspan=2)
    else:
        app.checkbox_frame1 = MyScrollableCheckboxFrame(app, "List of attacks", values=["No attacks found"])
        app.checkbox_frame1.grid(row=0, column=1, padx=10, pady=(10, 0), sticky="nsew", columnspan=2)

def showDetails(app,value):
    #print("click2")
    attacker_ip=value[0]
    #print(attacker_ip)
    prompt=""
    infosrc=""
    serviceName=getservbyport(int(value[1]))

    promptdet=f"IP address of attacker: {attacker_ip}\nPort: {value[1]} ({serviceName})\n"
    if (is_private_ip(attacker_ip) == False):
        if (db_check_value(attacker_ip)):
            infosrc += "Data comes from local database\n"
            vtReputation, vtVendors_flagged, aipdbReputation_data = db_get_value(attacker_ip)
        else:
            infosrc += "Data comes from the Internet\n"
            vtReputation, vtVendors_flagged  = check_ip_virustotal_reputation(attacker_ip)
            aipdbReputation_data = get_abuse_score(attacker_ip)
            db_add(attacker_ip, vtReputation, vtVendors_flagged, aipdbReputation_data)
        if vtReputation is not None:
            prompt += f"VirusTotal Reputation for IP {attacker_ip}: {vtReputation}\n"
            if vtVendors_flagged is not None:
                prompt+=f"VirusTotal vendors flagging IP {attacker_ip} as malicious: {vtVendors_flagged}\n"
            else:
                prompt+=f"No information available on VirusTotal for IP: {attacker_ip}\n"
        else:
            prompt=f"No VirusTotal reputation data found for IP {attacker_ip}\n"
        if aipdbReputation_data is not None:
            prompt+=f"AbuseIPDB abuse score for IP {attacker_ip}: {aipdbReputation_data}%\n"
        else:
            prompt+=f"No AbuseIPDB data found for IP {attacker_ip}\n"
    else:
        prompt="IP address belongs to private network"
    prompt+=infosrc
    #print(prompt)
    app.checkbox_frame2.label2.destroy()

    app.checkbox_frame2.label2 = customtkinter.CTkLabel(master=app.checkbox_frame2.tab("IP Address Reputation"), text=prompt, justify="left")
    app.checkbox_frame2.label2.grid(row=0, column=0, padx=(0, 20), pady=10, sticky="w")

    app.checkbox_frame2.label1.destroy()
    app.checkbox_frame2.label1 = customtkinter.CTkLabel(master=app.checkbox_frame2.tab("Details"),text=promptdet, justify="left")
    app.checkbox_frame2.label1.grid(row=0, column=0, padx=(0, 20), pady=10, sticky="w")

class MyScrollableCheckboxFrame(customtkinter.CTkScrollableFrame):
    def __init__(self, master, title, values):
        super().__init__(master, label_text=title)
        self.grid_columnconfigure(0, weight=1)
        self.values = values
        self.checkboxes = []
        for i, value in enumerate(self.values):
            if(value=="No attacks found"):
                checkbox = customtkinter.CTkButton(self, text=value, fg_color="#212121", command=lambda txt=value: showDetails(master, txt),state="disabled")
            else:
                checkbox = customtkinter.CTkButton(self, text=value[0]+" on port "+value[1], fg_color="#363636", hover_color="grey",command=lambda txt=value: showDetails(master, txt))
            checkbox.grid(row=i, column=0, padx=10, pady=(10, 0), sticky="ew")
            self.checkboxes.append(checkbox)

class OptionsFrame(customtkinter.CTkFrame):
    def __init__(self, master, title, values):
        super().__init__(master)
        self.grid_columnconfigure((0), weight=1)
        self.values = values
        self.title = title
        self.checkboxes = []

        labelNames=["Phrase:","Period:","Records:"]
        defaultPlaceholders=["\"Failed\"","2 minutes","5 times"]

        checkbox = customtkinter.CTkButton(self, text="Run analysis",command=lambda:runScan(master))
        checkbox.grid(row=0, column=0, padx=10, pady=(10, 0), sticky="we")
        self.checkboxes.append(checkbox)
        checkbox1 = customtkinter.CTkButton(self, text="Choose custom file", command=open_file_dialog)
        checkbox1.grid(row=1, column=0, padx=10, pady=(10, 0), sticky="we")
        self.checkboxes.append(checkbox1)

        for i, value in enumerate(self.values):
            label = customtkinter.CTkLabel(self, text=labelNames[i], fg_color="transparent")
            label.grid(row=i + 2, column=0, padx=10, pady=(10, 0), sticky="w")
            checkbox = customtkinter.CTkEntry(self, placeholder_text=defaultPlaceholders[i],justify="center")
            checkbox.grid(row=i+2, column=0, padx=10, pady=(10, 0), sticky="e")
            self.checkboxes.append(checkbox)

class DetailsView(customtkinter.CTkTabview):
    def __init__(self, master, txt1, txt2):
        super().__init__(master)
        self.txt = txt1
        self.txt2 = txt2

        self.add("Details")
        self.add("IP Address Reputation")

        self.label1 = customtkinter.CTkLabel(master=self.tab("Details"),text=txt1)
        self.label1.grid(row=0, column=0, padx=20, pady=10, sticky="w")
        self.label2 = customtkinter.CTkLabel(master=self.tab("IP Address Reputation"), text=txt2)
        self.label2.grid(row=0, column=0, padx=20, pady=10, sticky="w")


class App(customtkinter.CTk):
    def __init__(self):
        super().__init__()

        self.title("BruteForce Analyzer")
        self.geometry("650x400")
        self.grid_columnconfigure((0,1,2), weight=1)
        self.grid_rowconfigure((0,1,2), weight=1)


        self.checkbox_frame = OptionsFrame(self, "Values", values=["value 1", "value 2", "value 3"])
        self.checkbox_frame.grid(row=0, column=0, padx=10, pady=(10, 0), sticky="nsew",rowspan=3)
        self.checkbox_frame1 = MyScrollableCheckboxFrame(self, "List of possible attacks", values=[])
        self.checkbox_frame1.grid(row=0, column=1, padx=10, pady=(10, 0), sticky="nsew",columnspan=2)
        self.checkbox_frame2 = DetailsView(self,txt1="Choose IP address from list",txt2="Choose IP address from list")
        self.checkbox_frame2.grid(row=1, column=1, padx=10, pady=(10, 0), sticky="nsew",columnspan=2, rowspan=3)

if is_admin():
    customtkinter.set_default_color_theme("dark-blue")
    app = App()
    app.mainloop()

else:
    #jeśli .exe zmienić
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
