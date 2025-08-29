import json
import os
import re
import time
from typing import List, Dict, Any, Optional
from collections import defaultdict
from datetime import datetime, timedelta
from exp_step2_correlation.utils import *


def clean_hyperalerts(hyper_clusterdata="超级告警数据", STEP_LENGTH=1):
    cleaned_hyper_clusterdata = {k: v for k, v in hyper_clusterdata.items() if len(v) >= STEP_LENGTH}
    lens = [len(v) for k, v in cleaned_hyper_clusterdata.items()]
    # print(cleaned_hyper_clusterdata)

    print(
        f"清洗超级告警数据，得到{len(cleaned_hyper_clusterdata)}个清洗的超级告警数据，均长{np.mean(lens)}({min(lens)}, {max(lens)})，从{len(hyper_clusterdata)}个原告警中")
    return cleaned_hyper_clusterdata


def alert_2_hyperalerts_by_ta(alerts=""):
   
    clustered_data = defaultdict(dict)
    for alert in alerts:  # 遍历每个告警
        ta_key = "TA0043"
        ttp_key = alert["sid"]#alert["ttps"][0]
        tuple_4 = tuple([alert["source_ip"], alert["destination_ip"], alert["source_port"], alert["destination_port"]])
        time_second = alert["time"].split(".")[0]
        if ttp_key in clustered_data[ta_key]:
            clustered_data[ta_key][ttp_key]["alerts_number"] += alert["alerts_number"]
            clustered_data[ta_key][ttp_key]["4-tuple(src,dst,sport,dport)"][tuple_4].append(time_second)

            clustered_data[ta_key][ttp_key]["time_end"] = alert["time"]
            clustered_data[ta_key][ttp_key]["timestamp_end"] = alert["timestamp"]
            clustered_data[ta_key][ttp_key]["timestamp_avg"] += alert["timestamp"]
        else:
            clustered_data[ta_key][ttp_key] = dict(alert.items())
            clustered_data[ta_key][ttp_key]["4-tuple(src,dst,sport,dport)"] = defaultdict(list)
            clustered_data[ta_key][ttp_key]["4-tuple(src,dst,sport,dport)"][tuple_4] = [time_second]

            del clustered_data[ta_key][ttp_key]["source_ip"]
            del clustered_data[ta_key][ttp_key]["source_port"]
            del clustered_data[ta_key][ttp_key]["destination_ip"]
            del clustered_data[ta_key][ttp_key]["destination_port"]

            clustered_data[ta_key][ttp_key]["time_end"] = alert["time"]
            clustered_data[ta_key][ttp_key]["timestamp_end"] = alert["timestamp"]
            clustered_data[ta_key][ttp_key]["timestamp_avg"] = alert["timestamp"]

    for ta_key in clustered_data.keys():
        for ttp_key in clustered_data[ta_key].keys():

            clustered_data[ta_key][ttp_key]["times_chain (time,alertNumber)"] = [
                list(Counter(v).items()) for v in clustered_data[ta_key][ttp_key]["4-tuple(src,dst,sport,dport)"].values()
            ]
            clustered_data[ta_key][ttp_key]["times_chain (time,alertNumber)"] = [
                sorted(v, key=lambda x: datetime.strptime(x[0], "%m/%d/%Y-%H:%M:%S")) for v in clustered_data[ta_key][ttp_key]["times_chain (time,alertNumber)"]
            ]
            clustered_data[ta_key][ttp_key]["times_chain (time,alertNumber)"] = [
                [i[0]+" | "+str(i[1]) for i in v] for v in clustered_data[ta_key][ttp_key]["times_chain (time,alertNumber)"]
            ]

            clustered_data[ta_key][ttp_key]["4-tuple(src,dst,sport,dport)"] = list(clustered_data[ta_key][ttp_key]["4-tuple(src,dst,sport,dport)"].keys())

            clustered_data[ta_key][ttp_key]["4-tuple(src,dst,sport,dport)"] = [
                " | ".join(v) for v in clustered_data[ta_key][ttp_key]["4-tuple(src,dst,sport,dport)"]
            ]
            pass

    for ta_key in clustered_data.keys():
        for ttp_key in clustered_data[ta_key].keys():
            clustered_data[ta_key][ttp_key]["timestamp_avg"] = int(
                clustered_data[ta_key][ttp_key]["timestamp_avg"] / clustered_data[ta_key][ttp_key]["alerts_number"])
    return clustered_data

def get_victim_host_v2(hyperalert: Dict[str, Any]) -> str:
    internal_ips = []
    for alert in hyperalert.get('alerts', []):
        src_ip = alert.get('source_ip', '')
        dst_ip = alert.get('destination_ip', '')
        if isInternalIp(src_ip):
            internal_ips.append(src_ip)
        if isInternalIp(dst_ip):
            internal_ips.append(dst_ip)
    if internal_ips:
        return max(set(internal_ips), key=internal_ips.count)
    return ''

def cluster_by_ip(logfile="", savedpath=""):
    time_sta = time.time()
    clusterdata = defaultdict(list)
    for alert in logfile:
        victim_host = get_victim_host_v2(alert)
        clusterdata[victim_host].append(alert)
    Write2Json(savedpath, clusterdata)

    print(
        f"[TIME] 构建基于受害IP(内网)的JSON数据，得到{len(clusterdata)}个内网受害主机，从{len(logfile)}个告警中，保存到 {savedpath} 中, 费时：{time.time() - time_sta:.2f}s")
    return clusterdata

def reconstruct_alert_2_hyperalerts(clusterdata="", savedpath=""):
    time_sta = time.time()

    tactics = [
        'TA0043: Reconnaissance',
        'TA0042: Resource Development',
        'TA0001: Initial Access',
        'TA0002: Execution',
        'TA0003: Persistence',
        'TA0004: Privilege Escalation',
        'TA0005: Defense Evasion',
        'TA0006: Credential Access',
        'TA0007: Discovery',
        'TA0008: Lateral Movement',
        'TA0009: Collection',
        'TA0010: Exfiltration',
        'TA0011: Command and Control',
        'TA0040: Impact'
    ]
    tactics = [i.split(": ")[0] for i in tactics]

    hyper_clusterdata = defaultdict(dict)
    for victim_host in clusterdata:
        single_h_data = alert_2_hyperalerts_by_ta(clusterdata[victim_host])
        tmp = {}
        for i in tactics:
            if i in single_h_data: tmp[i] = single_h_data[i]
        single_h_data = tmp
        hyper_clusterdata[victim_host] = single_h_data
    hyper_clusterdata = clean_hyperalerts(hyper_clusterdata, 1)
    Write2Json(savedpath, hyper_clusterdata)

    print(
        f"[TIME] 构建基于受害IP(内网)的JSON超级告警数据，清洗得到{len(hyper_clusterdata)}个内网受害主机，从{len(clusterdata)}个原超级告警中，保存到 {savedpath} 中, 费时：{time.time() - time_sta:.2f}s")
    return hyper_clusterdata


def find_chain_data(gpt_response_data, hyperalerts="基于IP，TA，TTP的超级告警数据", T=None, notP=False, STEP_LENGTH=3,):
    time_sta = time.time()

    chain_set = set()  # 临时存储链路集合，避免重合
    chain_data_list = []  # 临时存储所有的链路告警集合
    victim_hosts = []
    print(len(gpt_response_data))
    for ip, chain_info in gpt_response_data.items():
        victim_host = ip
        if isinstance(chain_info, list):
            chains = chain_info
        else:
            chains = [chain_info]
        
        for chain in chains:
            sid_chain = chain.get('alert_chain', [])
            ttps_chain = chain.get('ttps_chain', [])
            tas_chain = chain.get('tas_chain', [])
            confidence = chain.get('confidence_level', 'unknown')
            reasons = chain.get('association_reasons', 'unknown')
            summary = chain.get('summary', '')
            single_chain_data = []
            for sid in sid_chain:
                found = False
                for ta_key in hyperalerts[victim_host].keys():
                    if sid in hyperalerts[victim_host][ta_key]:
                        single_chain_data.append(hyperalerts[victim_host][ta_key][sid])
                        found = True
                        break
                if not found and notP != True:
                    print(f"警告: SID {sid} 在超级告警数据中未找到")

            if len(single_chain_data) < STEP_LENGTH:
                print(f"警告: 链路 {ip} {chain_info} 长度不足 {STEP_LENGTH}，跳过")
                continue
            ttp_chain = " + ".join([str(v['sid']) for v in single_chain_data] + ["--> " + victim_host])
            if ttp_chain in chain_set:
                continue
            chain_set.add(ttp_chain)
            chain_data_list.append((single_chain_data, ttps_chain, tas_chain, confidence, reasons, summary))
            victim_hosts.append(victim_host)
            if notP != True: print(f"{victim_host} 加入：{ttp_chain}")
    chain_data = defaultdict(dict)

    for count, item in enumerate(chain_data_list):
        key = "chain_" + str(count)
        victim_host = victim_hosts[count]
        single_chain_data, ttps_chain, tas_chain, confidence, reasons, summary = item
        total_alert_numer = sum([v["alerts_number"] for v in single_chain_data])
        chain_data[key] = {
            "victim_host": victim_host,  # 受害主机
            "total_alert_numer": total_alert_numer,  # 总告警量
            "chains_len": len(single_chain_data),  # 链路长度
            "sid_chains": [v['sid'] for v in single_chain_data],  # 每一步对应的Sid编号
            "ttps_chains": ttps_chain,  # 从GPT响应获取的ttps_chain
            "tas_chains": tas_chain,  # 从GPT响应获取的tas_chain
            "confidence_level": confidence,  # 链路置信度
            "association_reasons": reasons,  # 关联原因
            "summary": summary  # 链路摘要信息
        }

        chain_data[key]["alerts_chains"] = {}
        for i, h_alert in enumerate(single_chain_data):
            chain_data[key]["alerts_chains"]["alerts_" + str(i)] = h_alert

    print(f"\n采用策略 {T}，总共发现了 {len(chain_data)} 条链路。")

    if len(chain_data) == 0:
        print("没有发现任何链路")
        return None

    assert len(chain_set) == len(chain_data)
    print(
        f"[TIME] 构建基于受害IP(内网)超级告警数据的链路数据，得到{len(chain_data)}条链路，从{len(hyperalerts)}个受害者主机中, 费时：{time.time() - time_sta:.2f}s")

    print(f"---> 链路数据 <---")

    tmp = [chain_data[v]["chains_len"] for v in chain_data]
    print(f"总计 {len(chain_data)} 条，平均步长 {np.mean(tmp):.2f}, 最短：{min(tmp)}，最长：{max(tmp)}")
    return chain_data

def reverse_cluster_by_ip(logfile="告警JSON内容.json", savedpath="保存的位置"):
    time_sta = time.time()
    clusterdata = defaultdict(list)
    for alert in logfile:
        victim_host = get_attack_host_v2(alert)
        clusterdata[victim_host].append(alert)
    Write2Json(savedpath, clusterdata)
    print(
        f"[TIME] 构建基于攻击IP的JSON数据，得到{len(clusterdata)}个攻击IP，从{len(logfile)}个告警中，保存到 {savedpath} 中, 费时：{time.time() - time_sta:.2f}s")
    return clusterdata