import json
import os
import re
from typing import List, Dict, Any, Optional
from collections import defaultdict
from exp_step2_correlation.utils import *

featrure_str = []

same_fact_sids = [{}]

def find_related_sids(sid="", sid_index="", sids_dict="", visited=""):
    if sid in visited:
        return set(), visited
    res = set([sid])
    visited.add(sid)
    for pos in sid_index[sid]:
        for next_sid in sids_dict[pos]:
            if next_sid not in visited:
                res_next, visited = find_related_sids(next_sid, sid_index, sids_dict, visited)
                res = res.union(res_next)
    return res, visited

def merge_set(sids_list):
    sids_dict = {i: val for i,val in enumerate(sids_list)}
    sid_index = defaultdict(list)
    for i, sids in sids_dict.items():
        for sid in sids:
            sid_index[sid].append(i)
    all_sids = list(set().union(*sids_list))
    res_same_sids_set = []
    visited = set()
    for sid in all_sids:
        if sid in visited: continue
        related_sids, visited = find_related_sids(sid, sid_index, sids_dict, visited)
        res_same_sids_set.append(related_sids)
    return res_same_sids_set

def cluster_rules(rules="", featrure_str="",same_fact_sids=""):
    same_sids_set = []
    same_feature_sid = defaultdict(list)
    for rule in rules.values():
        for i,str in enumerate(featrure_str):
            if str in rule["raw_rules"]:
                same_feature_sid[i].append(rule["sid"])
                break
    for sids in same_feature_sid.values(): 
        x = set(sids)
        if len(x) <= 1: continue
        same_sids_set.append(x)
    all_sids = set(rules.keys())
    for sids in same_fact_sids:
        tmp = sids & all_sids
        if len(tmp) <= 1: continue
        same_sids_set.append(tmp)
    for i in same_sids_set:
        assert len(i) > 1
    same_sids_set = merge_set(same_sids_set)
    same_sids_dict = {}
    for mid,sids in enumerate(same_sids_set):
        sids = list(sids)
        mul_sids = "[M-SID] " + ",".join(sids)
        mul_msgs = "[M-MSG] " + " <-|*|-> ".join([f"({sid})-"+rules[sid]["msg"] for sid in sids])
        mul_rules = "[M-RULE] " + " <-|*|-> ".join([f"({sid})-"+rules[sid]["kernel"] for sid in sids])
        mul_rawrules = "[M-RAWRULE] " + " <-|*|-> ".join([f"({sid})-"+rules[sid]["raw_rules"] for sid in sids])
        value_data = [mid, mul_sids, mul_msgs, mul_rules, sids, len(sids), "*", mul_rawrules]
        if "DNS" in mul_msgs: value_data[-1] = "DNS"
        for sid in sids:
            same_sids_dict[sid] = value_data
    return same_sids_dict

def analysis_sids_and_merge(
    rules="dict: sid,values",
    same_nlp_str=[],
    featrure_str=featrure_str,
    same_fact_sids=same_fact_sids,
):
    same_sids_dict = cluster_rules(rules, featrure_str, same_fact_sids)
    return same_sids_dict
