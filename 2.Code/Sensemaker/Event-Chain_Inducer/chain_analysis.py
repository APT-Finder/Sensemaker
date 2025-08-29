import json
import os
import re
import time
from typing import List, Dict, Any, Optional
from collections import defaultdict
from utils import *

def erase_wrong_alerts_from_chain(chain_data: Dict[str, Any]) -> Dict[str, Any]:
    cleaned_alerts = []
    for alert in chain_data.get('alerts', []):
        attack_msg = alert.get('attack_msg', '').lower()
        if any(wrong_keyword in attack_msg for wrong_keyword in ['bitcoin', 'torrent', 'p2p']):
            continue
        cleaned_alerts.append(alert)
    chain_data['alerts'] = cleaned_alerts
    chain_data['total_alerts'] = len(cleaned_alerts)
    return chain_data

def is_dns_server(ip: str, chain_data: List[Dict[str, Any]]) -> bool:
    dns_alert_count = 0
    total_alerts = 0
    for chain in chain_data:
        for alert in chain.get('alerts', []):
            if alert.get('destination_ip') == ip or alert.get('source_ip') == ip:
                total_alerts += 1
                attack_msg = alert.get('attack_msg', '').lower()
                if 'dns' in attack_msg:
                    dns_alert_count += 1
    if total_alerts == 0:
        return False
    return (dns_alert_count / total_alerts) > 0.7


def clean_chains_data(
    raw_chain_data="已挖掘链路们"
):
    new_chain_data = {}

    key_changed = 0
    for key, chain in raw_chain_data.items():

        ttmsgs = ".".join([x["attack_msg"] for x in chain["alerts_chains"].values()])
        if is_saved_a_chain(chain["chains_len"], ttmsgs, STEP_LENGTH=1)==False:
            continue

        print("\t新的步长：", chain["chains_len"])

        new_chain_data["chain_"+str(key_changed)] = chain
        key_changed += 1

    print(f"从 {len(raw_chain_data)} 链路中，聚类后有 {key_changed} 个链路")

    return new_chain_data

def extract_info_to_llm(chain_data):
    data = {}
    
    data["alerts_info"] = []

    alerts = list(chain_data["alerts_chains"].values())
    
    for i, (sid, ttp_chain) in enumerate(zip(chain_data["sid_chains"], chain_data["ttps_chains"])):
        val = alerts[i]
        
        main_ttps = val["ttps"][0] + ": " + val["ttps_description"][0]
        sec_ttps = val["sec_ttps"][0] + ": " + val["sec_ttps_description"][0]
        third_ttps = val["third_ttps"][0] + ": " + val["third_ttps_description"][0]
        
        features = "|".join(val["alert_features"])
        
        if ttp_chain[0] in [t.split(':')[0] for t in val["ttps"]]:
            ttp_info = main_ttps
        elif ttp_chain[0] in [t.split(':')[0] for t in val["sec_ttps"]]:
            ttp_info = sec_ttps
        elif ttp_chain[0] in [t.split(':')[0] for t in val["third_ttps"]]:
            ttp_info = third_ttps
        else:
            ttp_info = main_ttps  # 默认使用main_ttps
        
        alert_info = f"第{i+1}步攻击：{ttp_info}  从{val["time"].split(".")[0]}开始到{val["time_end"].split(".")[0]}结束，共{str(val['alerts_number'])}条，其关键特征为{features}"
        
        data["alerts_info"].append(alert_info)
    data["此攻击链关联的原因"] = chain_data["association_reasons"]
    data["关联的信心程度"] = chain_data["confidence_level"]
    data["此攻击链的关键事件和行为"] = chain_data["summary"]

    return data

def extract_all_info_from_chain_data(chain_data):
    data = {}
    for item in chain_data:
        if item in {
            "victim_host",
            "total_alert_numer",
            "chains_len",
            "sid_chains",
            "ttps_chains",
            "tas_chains",
            "confidence_level",
            "association_reasons",
            "summary"
        }: data[item] = chain_data[item]

    data["alert_msg"] = [val["attack_msg"] for val in chain_data["alerts_chains"].values()]
    data["alert_classification"] = [val["classification"] for val in chain_data["alerts_chains"].values()]

    data["alert_time(start|end|number)"] = [
        " | ".join((val["time"].split(".")[0], val["time_end"].split(".")[0], str(val["alerts_number"]))) for val in
        chain_data["alerts_chains"].values()
    ]

    data["main_ttps_info"] = [
        val["tactics_ttps"][0] + ": " + val["ttps"][0] + ": " + val["ttps_description"][0] for val in chain_data["alerts_chains"].values()
    ]
    
    data["sec_ttps_info"] = [
        val["sec_tactics_ttps"][0] + ": " + val["sec_ttps"][0] + ": " + val["sec_ttps_description"][0] for val in chain_data["alerts_chains"].values()
    ]

    data["third_ttps_info"] = [
        val["third_ttps"][0] + ": " + val["third_ttps_description"][0] for val in chain_data["alerts_chains"].values()
    ]

    data["alert_features"] = [
        "|".join(val["alert_features"]) for val in chain_data["alerts_chains"].values()  #if "alert_features" in val and val["alert_features"]
    ]

    data["4_tuple"] = [
        val["4-tuple(src,dst,sport,dport)"] for val in chain_data["alerts_chains"].values()
    ]
    data["detail_time(time,alertnumber)"] = [
        val["times_chain (time,alertNumber)"] for val in chain_data["alerts_chains"].values()
    ]
    # print(data)
    return data

def extract_chain_data_for_anaylze_main(
        raw_chain_data="",
        simple_saved_path="",
        all_saved_path="",
):

    new_chain_data = clean_chains_data(
        raw_chain_data
    )

    next_llm_chains_info = {}
    all_chains_info = {}

    with open(simple_saved_path, 'w', encoding='utf-8') as f:
        json.dump({}, f, ensure_ascii=False, indent=2)
    with open(all_saved_path, 'w', encoding='utf-8') as f:
        json.dump({}, f, ensure_ascii=False, indent=2)

    pos = ""
    chain_time_len, single_time_len = 0, 0
    min_steps, max_steps = 999, 0

    for key, chain in new_chain_data.items():

        min_steps = min(min_steps, chain["chains_len"])
        max_steps = max(max_steps, chain["chains_len"])

        next_llm_chain_info = extract_info_to_llm(chain)
        next_llm_chains_info[key] = next_llm_chain_info

        all_chain_info = extract_all_info_from_chain_data(chain)
        all_chains_info[key] = all_chain_info

        sta = list(chain["alerts_chains"].values())[0]["timestamp"]
        end = list(chain["alerts_chains"].values())[-1]["timestamp"]

        if end-sta>=chain_time_len:
            pos = key
            chain_time_len = end - sta
            chain_sta_time = sta
            chain_end_time = end

        single_time_len = max([single_time_len] + [v["timestamp_end"]-v["timestamp"] for v in chain["alerts_chains"].values()])

    all_chains_info = add_other_infos(all_chains_info, "4_tuple")
    
    print(f"一共挖掘 {len(new_chain_data)} 条链路（{min_steps}，{max_steps}），原本 {len(raw_chain_data)} 条。")
    print(f"单个告警跨度最长：{single_time_len/3600:.2f} 小时")
    print(f"告警链路跨度最长：{pos}, {chain_sta_time}，{chain_end_time}, {chain_time_len/3600:.2f} 小时")

    Write2Json(simple_saved_path, next_llm_chains_info)
    Write2Json(all_saved_path, all_chains_info)
    return len(new_chain_data) > 0