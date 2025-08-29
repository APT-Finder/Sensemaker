import json
import os
import re
import time
from typing import List, Dict, Any, Optional
from collections import defaultdict
from datetime import datetime
from tqdm import tqdm
from exp_step2_correlation.utils import *

def convert_single_alert_2_json(raw_alert="单个Suricata告警数据", rulefile="规则文件"):
    alert = [i.strip() for i in raw_alert.strip().split(" [**] ")]
    if "[" in alert[1] and "]" in alert[1]:
        group, sid, rev = alert[1].split(" ")[0][1:-1].split(":")
    elif "[" in alert[2] and "]" in alert[2]:
        group, sid, rev = alert[2].split(" ")[0][1:-1].split(":")
    timestamp_value = alert[0]
    timestamp_pattern = r'(\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d{6})'
    timestamp_regex = re.compile(timestamp_pattern)
    timestamps = timestamp_regex.findall(timestamp_value)
    if len(timestamps) == 0:
        dt_now = datetime.now()
        timestamp_value = dt_now.strftime("%m/%d/%Y-%H:%M:%S.%f")
    else:
        timestamp_value = timestamps[0]
    attack_msg = alert[1].strip().split(" ")[0] + " " + rulefile[sid]['msg']
    if len(alert[2].split("} ")[-1])>50:
        return {}
    pattern = r'\[(Classification:\s*.*?)\]\s+\[(Priority:\s*.*?)\]\s+\{(.*?)\}\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)\s+->\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)'
    classification, priority, protocol, source_ip, source_port, destination_ip, destination_port = None, None, None, None, None, None, None
    for i in range(2,len(alert)):
        match = re.search(pattern, alert[i])
        if match != None:
            classification, priority, protocol, source_ip, source_port, destination_ip, destination_port = match.groups()
            break
    if classification is None:
        return {}
    json_data = {
        "sid": sid,
        "rev": rev,
        "group": group,
        "apt_group": None,
        "timestamp": datetime.strptime(timestamp_value, "%m/%d/%Y-%H:%M:%S.%f").timestamp(),
        "time": timestamp_value,
        "source_ip": source_ip,
        "source_port": source_port,
        "destination_ip": destination_ip,
        "destination_port": destination_port,
        "chains-id": None,
        "phase": None,
        "attack_msg": attack_msg,
        "classification": classification,
        "alerts_number": 1,
        "protocol": protocol,
        "priority": priority,
    }
    return json_data

def convert_multi_alerts_2_json(fastlogfiles="日志文件们", rulefile="规则JSON文件"):
    time_sta = time.time()
    raw_count = 0
    json_data = []
    alert_count = 0
    alert_ttp_count = 0
    realted_sid, realted_ttp_sid = defaultdict(int), defaultdict(int)
    for fastlogfile in fastlogfiles:
        if fileExists(fastlogfile, create=False)==False:
            print(f"文件 {fastlogfile} 不存在。")
            continue
        for alert in tqdm(open(fastlogfile, 'r', encoding='utf-8')):
            raw_count += 1
            single_json_data = convert_single_alert_2_json(alert, rulefile)
            if len(single_json_data)==0:
                continue
            single_json_data["id"] = alert_count + 1
            sid = single_json_data["sid"]
            single_json_data["ttps"] = rulefile[sid]["ttps"] if sid in rulefile and len(rulefile[sid]["ttps"])>0 else ["Unknown"]
            single_json_data["ttps_description"] = rulefile[sid]["ttps_description"] if sid in rulefile and len(rulefile[sid]["ttps"])>0 else ["Unknown"]
            single_json_data["tactics_ttps"] = rulefile[sid]["tactics_ttps"] if sid in rulefile and len(rulefile[sid]["ttps"])>0 else ["Unknown"]
            single_json_data["alert_features"] = rulefile[sid]["alert_features"] if sid in rulefile and len(rulefile[sid]["alert_features"])>0 else ["Unknown"]
            single_json_data["sec_ttps"] = rulefile[sid]["sec_ttps"] if sid in rulefile and len(rulefile[sid]["sec_ttps"])>0 else ["Unknown"]
            single_json_data["sec_ttps_description"] = rulefile[sid]["sec_ttps_description"] if sid in rulefile and len(rulefile[sid]["sec_ttps_description"])>0 else ["Unknown"]
            single_json_data["sec_tactics_ttps"] = rulefile[sid]["sec_tactics_ttps"] if sid in rulefile and len(rulefile[sid]["sec_tactics_ttps"])>0 else ["Unknown"]
            single_json_data["third_ttps"] = rulefile[sid]["third_ttps"] if sid in rulefile and len(rulefile[sid]["third_ttps"])>0 else ["Unknown"]
            single_json_data["third_ttps_description"] = rulefile[sid]["third_ttps_description"] if sid in rulefile and len(rulefile[sid]["third_ttps_description"])>0 else ["Unknown"]
            realted_sid[sid] += 1
            if len(single_json_data["ttps"])!=0:
                realted_ttp_sid[sid] += 1
                alert_ttp_count += 1
            json_data.append(single_json_data)
            alert_count += 1
    json_data = sorted(json_data, key=lambda x: x["timestamp"])
    realted_sid = sorted(realted_sid.items(), key=lambda x: x[1], reverse=True)
    total_count = sum(i[1] for i in realted_sid)
    print(f"涉及告警数及频率：{total_count}")
    print("Top 10 Alerts:")
    print("ID\tCount\tPercentage")
    print("----------------------------------------------")
    for alert_id, count in realted_sid[:10]:
        percentage = count / total_count * 100
        print(f"{alert_id}\t{count}\t{percentage:.2f}%f")
    return json_data