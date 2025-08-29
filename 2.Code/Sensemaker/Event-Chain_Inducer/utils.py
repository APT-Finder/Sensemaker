import json
import os
import re
from typing import List, Dict, Any, Optional
from collections import defaultdict
import ipaddress

internal_ips = [
    '10.0.0.0/8',
    '172.16.0.0/12',
    '192.168.0.0/16'
]

private_ips = [ipaddress.ip_network(ip) for ip in internal_ips]

def extract_llm_input(data: List[Dict[str, Any]]) -> str:
    result = []
    for item in data:
        result.append(f"告警ID: {item.get('id', '')}")
        result.append(f"源IP: {item.get('source_ip', '')}")
        result.append(f"目的IP: {item.get('destination_ip', '')}")
        result.append(f"告警消息: {item.get('attack_msg', '')}")
        result.append('---')
    return '\n'.join(result)

def determine_network_type(ip: str) -> str:
    try:
        ip_obj = ipaddress.ip_address(ip)
        for network in private_ips:
            if ip_obj in network:
                return 'internal'
        return 'external'
    except ValueError:
        return 'unknown'

def is_saved_a_chain(chain_data: Dict[str, Any], saved_chains: List[Dict[str, Any]]) -> bool:
    for saved_chain in saved_chains:
        if (chain_data.get('chains-id') == saved_chain.get('chains-id') and
            len(chain_data.get('alerts', [])) == len(saved_chain.get('alerts', []))):
            return True
    return False

class FileLock:
    def __init__(self, file_path):
        self.file_path = file_path
        self.lock_path = file_path + '.lock'
    
    def acquire(self):
        while os.path.exists(self.lock_path):
            time.sleep(0.1)
        with open(self.lock_path, 'w') as f:
            f.write(str(os.getpid()))
    
    def release(self):
        if os.path.exists(self.lock_path):
            os.remove(self.lock_path)
    
    def __enter__(self):
        self.acquire()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.release()

def Write2Json(file_path: str, data: Any, create_dir: bool = True):
    dir_path = os.path.dirname(file_path)
    if create_dir and dir_path and not os.path.exists(dir_path):
        os.makedirs(dir_path, exist_ok=True)
    with FileLock(file_path):
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

def ReadJsonData(file_path: str) -> Any:
    if not os.path.exists(file_path):
        return {}
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except json.JSONDecodeError:
        return {}

def pathExists(path: str, create: bool = False) -> bool:
    if os.path.exists(path):
        return True
    if create:
        os.makedirs(path, exist_ok=True)
        return True
    return False

def fileExists(file_path: str, create: bool = False) -> bool:
    if os.path.exists(file_path):
        return True
    if create:
        dir_path = os.path.dirname(file_path)
        if dir_path and not os.path.exists(dir_path):
            os.makedirs(dir_path, exist_ok=True)
        with open(file_path, 'w') as f:
            pass
        return True
    return False

def isInternalIp(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        for network in private_ips:
            if ip_obj in network:
                return True
        return False
    except ValueError:
        return False

def get_victim_host(alert_data: Dict[str, Any]) -> str:
    if isinstance(alert_data, list):
        for alert in alert_data:
            if alert.get('source_ip') and isInternalIp(alert.get('source_ip', '')):
                return alert.get('source_ip', '')
            if alert.get('destination_ip') and isInternalIp(alert.get('destination_ip', '')):
                return alert.get('destination_ip', '')
    elif isinstance(alert_data, dict):
        if alert_data.get('source_ip') and isInternalIp(alert_data.get('source_ip', '')):
            return alert_data.get('source_ip', '')
        if alert_data.get('destination_ip') and isInternalIp(alert_data.get('destination_ip', '')):
            return alert_data.get('destination_ip', '')
    return ''

# 以下是内部使用的辅助函数

def isInRange(ip: str, ip_range: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        network = ipaddress.ip_network(ip_range, strict=False)
        return ip_obj in network
    except ValueError:
        return False

# 安全行为检测函数

def judgeXSS(alert_msg: str) -> bool:
    xss_patterns = ['<script>', 'javascript:', 'onerror=', 'onload=', 'alert(']
    for pattern in xss_patterns:
        if pattern.lower() in alert_msg.lower():
            return True
    return False

def judgeSQL(alert_msg: str) -> bool:
    sql_patterns = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'EXEC', 'UNION']
    for pattern in sql_patterns:
        if pattern.lower() in alert_msg.lower():
            return True
    return False

def judgeRCE(alert_msg: str) -> bool:
    rce_patterns = ['command execution', 'shell', 'cmd.exe', 'bash', 'exec', 'system(']
    for pattern in rce_patterns:
        if pattern.lower() in alert_msg.lower():
            return True
    return False

# 日志关键信息提取函数
def key_info(alert_data: Dict[str, Any]) -> Dict[str, Any]:
    result = {}
    result['id'] = alert_data.get('id', '')
    result['timestamp'] = alert_data.get('timestamp', 0)
    result['source_ip'] = alert_data.get('source_ip', '')
    result['destination_ip'] = alert_data.get('destination_ip', '')
    result['attack_msg'] = alert_data.get('attack_msg', '')
    result['ttps'] = alert_data.get('ttps', [])
    return result

# 统计打印函数
def printStat(data: List[Dict[str, Any]], field: str) -> None:
    stats = defaultdict(int)
    for item in data:
        value = item.get(field, 'unknown')
        if isinstance(value, list):
            for v in value:
                stats[v] += 1
        else:
            stats[value] += 1
    sorted_stats = sorted(stats.items(), key=lambda x: x[1], reverse=True)
    print(f"{field} 统计:")
    for key, count in sorted_stats[:10]:
        print(f"{key}: {count}")

# 文件操作函数
def addTxtA2TxtB(txtA: str, txtB: str) -> None:
    if not os.path.exists(txtA):
        return
    with open(txtA, 'r', encoding='utf-8') as f:
        content = f.read()
    with open(txtB, 'a', encoding='utf-8') as f:
        f.write(content)