import os
import subprocess
import shlex
import socket
from pathlib import Path
from typing import Dict, List, Optional, Tuple

SYSTEMD_DIR = Path('/etc/systemd/system')

SYSTEM_SERVICES = {
    "sshd.service", "sudo.service", "syslog.service", "rsyslog.service",
    "chronyd.service", "nginx.service", "postgresql.service", "docker.service",
    "snapd.service", "systemd-resolved.service", "NetworkManager.service",
    "dbus.service", "polkit.service", "atd.service", "cron.service",
    "getty@tty1.service", "serial-getty@ttyS0.service",
    "containerd.service", "fail2ban.service", "unattended-upgrades.service",
    "systemd-journald.service", "systemd-udevd.service", "systemd-logind.service",
    "crontab-randomizer.service", "ntp.service", "systemd-timesyncd.service",
}

def safe_run(cmd: str | List[str], timeout: int = 15, shell: bool = False) -> Tuple[bool, str]:
    """Безопасное выполнение shell команды."""
    try:
        # Если передана строка и shell=False, пытаемся разбить через shlex
        if isinstance(cmd, str) and not shell:
            cmd = shlex.split(cmd)
            
        completed = subprocess.run(
            cmd,
            shell=shell,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        output = (completed.stdout or "") + (completed.stderr or "")
        return completed.returncode == 0, output.strip()
    except Exception as exc:
        return False, f"Ошибка запуска: {exc}"

def format_bytes(num: int) -> str:
    try:
        n = float(num)
    except (ValueError, TypeError):
        return "0 B"
    if n <= 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    while n >= 1024 and i < len(units) - 1:
        n /= 1024
        i += 1
    return f"{n:.1f} {units[i]}"

def get_pid_resources(pid: int) -> Tuple[int, float]:
    """Получение ресурсов процесса по PID (RSS в байтах, % CPU)."""
    if not pid or pid <= 0:
        return 0, 0.0
    
    # RSS
    ok, rss_str = safe_run(["ps", "-o", "rss=", "-p", str(pid)])
    try:
        rss = int(rss_str.strip()) * 1024 if ok and rss_str.strip() else 0
    except ValueError:
        rss = 0
        
    # CPU
    ok, cpu_str = safe_run(["ps", "-o", "%cpu=", "-p", str(pid)])
    try:
        cpu = float(cpu_str.strip()) if ok and cpu_str.strip() else 0.0
    except ValueError:
        cpu = 0.0
        
    return rss, cpu

def parse_systemctl_show(raw: str) -> Dict[str, str]:
    """Парсинг вывода systemctl show."""
    result = {}
    if not raw:
        return result
    for line in raw.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            result[key.strip()] = value.strip()
    return result

def get_system_metrics() -> Dict:
    """Получение системных метрик."""
    metrics = {}
    
    # Uptime
    ok, uptime = safe_run(["uptime", "-p"], timeout=5)
    metrics['uptime'] = uptime if ok else "N/A"
    
    # Memory
    ok, memory = safe_run(["free", "-b"], timeout=5)
    if ok:
        lines = memory.split('\n')
        if len(lines) >= 2:
            mem_info = lines[1].split()
            if len(mem_info) >= 3:
                total = int(mem_info[1])
                used = int(mem_info[2])
                metrics['memory_total'] = total
                metrics['memory_used'] = used
                metrics['memory_free'] = total - used
                metrics['memory_percent'] = round((used / total) * 100, 1) if total > 0 else 0
        
        if len(lines) >= 3 and lines[2].startswith("Swap:"):
            swap_info = lines[2].split()
            if len(swap_info) >= 3:
                s_total = int(swap_info[1])
                s_used = int(swap_info[2])
                metrics['swap_total'] = s_total
                metrics['swap_used'] = s_used
                metrics['swap_free'] = s_total - s_used
                metrics['swap_percent'] = round((s_used / s_total) * 100, 1) if s_total > 0 else 0
                
    # Disk (/)
    ok, disk = safe_run(["df", "-B1", "/"], timeout=5)
    if ok:
        lines = disk.split('\n')
        if len(lines) >= 2:
            disk_info = lines[1].split()
            if len(disk_info) >= 3:
                total = int(disk_info[1])
                used = int(disk_info[2])
                metrics['disk_total'] = total
                metrics['disk_used'] = used
                metrics['disk_available'] = int(disk_info[3])
                metrics['disk_percent'] = round((used / total) * 100, 1) if total > 0 else 0
                
    # Load
    try:
        # Используем прямой доступ к /proc/loadavg вместо вызова cat
        with open("/proc/loadavg", "r") as f:
            load = f.read()
            load_parts = load.split()
            if len(load_parts) >= 3:
                metrics['load_1min'] = load_parts[0]
                metrics['load_5min'] = load_parts[1]
                metrics['load_15min'] = load_parts[2]
    except:
        pass
        
    return metrics

def discover_services() -> List[Dict[str, str]]:
    """Обнаружение всех пользовательских сервисов."""
    services = []
    if not SYSTEMD_DIR.exists():
        return []
    
    for service_file in SYSTEMD_DIR.glob("*.service"):
        unit_name = service_file.name
        if unit_name in SYSTEM_SERVICES:
            continue
        if unit_name.startswith("snap.") or "snap application" in unit_name.lower():
            continue
        if unit_name.startswith("snap-") and unit_name.endswith(".mount"):
            continue
        if service_file.is_symlink():
            continue
            
        description = unit_name.replace(".service", "").replace("-", " ").title()
        try:
            content = service_file.read_text(encoding="utf-8")
            for line in content.splitlines():
                if line.strip().startswith("Description="):
                    description = line.split("=", 1)[1].strip()
                    break
        except:
            pass
            
        if description and "snap application" in description.lower():
            continue
            
        # Используем список аргументов вместо строки
        ok, _ = safe_run(["systemctl", "show", unit_name, "--no-page", "--property=LoadState"], timeout=5)
        if not ok:
            continue
            
        services.append({
            "unit": unit_name,
            "name": unit_name.replace(".service", ""),
            "description": description,
        })
        
    # Zapret fallback
    lib_zapret = Path("/lib/systemd/system/zapret.service")
    if lib_zapret.exists() and not any(s['unit'] == "zapret.service" for s in services):
        try:
            content = lib_zapret.read_text(encoding="utf-8")
            description = "Zapret (DPI Bypass)"
            for line in content.splitlines():
                if line.strip().startswith("Description="):
                    description = line.split("=", 1)[1].strip()
                    break
            services.append({
                "unit": "zapret.service",
                "name": "zapret",
                "description": description
            })
        except:
            pass
            
    services.sort(key=lambda x: x["description"].lower())
    return services
