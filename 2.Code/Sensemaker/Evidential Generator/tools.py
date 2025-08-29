#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations
import json, math, argparse, os
from typing import Dict, Any, List, Tuple, Optional

def sigmoid(x: float) -> float:
    try: return 1/(1+math.exp(-x))
    except OverflowError: return 0.0 if x<0 else 1.0

def logit(p: float, eps: float=1e-6) -> float:
    p = min(max(p, eps), 1-eps); return math.log(p/(1-p))

def odds_pool(probs: List[float], weights: List[float]) -> float:
    z = sum(float(w)*logit(float(p)) for p,w in zip(probs,weights))
    return sigmoid(z)

def conf_map(v: Any, default=0.5) -> float:
    if v is None: return default
    s=str(v).strip().lower()
    if s in ["high","高","高度","非常高"]: return 0.85
    if s in ["medium","中","一般"]: return 0.65
    if s in ["low","低"]: return 0.45
    try:
        x=float(s); 
        if 0<=x<=1: return x
    except: pass
    return default

def level_map(v: Any) -> float:
    if v is None: return 0.5
    return 0.80 if str(v).strip().upper()=="HIGH" else 0.50

def norm01_risk(v: Any) -> float:
    try: x=float(v)
    except: x=0.0
    x=max(0.0,min(10.0,x)); return x/10.0

def reweight_with_agreement(weights: List[float], signals: List[float]) -> List[float]:
    if not signals: return weights
    m = sum(signals)/len(signals)
    var = sum((s-m)**2 for s in signals)/len(signals)
    agree = 1.0 - min(var/0.25, 1.0)   # 1 when agree, 0 when maximally disagree
    scaled = [max(0.0,w) * (0.75 + 0.5*agree) for w in weights]
    s = sum(scaled); 
    return [w/s for w in scaled] if s>0 else weights

# ---------- Severity ----------
def severity_probability(assoc: Dict[str,Any], judge: Dict[str,Any],
                         sev_weights=(0.40,0.25,0.20,0.15),
                         batch_scores: Optional[List[float]]=None,
                         sev_th: float=0.65,
                         method: str="fixed",
                         sev_quantile: float=None) -> Tuple[float,float]:
    p_risk   = norm01_risk(judge.get("risk_score"))
    p_level  = level_map(judge.get("level"))
    p_jconf  = conf_map(judge.get("confidence"))
    p_aconn  = conf_map(assoc.get("关联的信心程度") or assoc.get("confidence"))

    base = [p_risk, p_jconf, p_aconn, p_level]
    w = list(sev_weights)
    if sum(w)==0: w=[0.40,0.25,0.20,0.15]
    w = reweight_with_agreement(w, base)
    p = odds_pool(base, w)

    if method=="quantile" and batch_scores:
        import numpy as np
        th = float(np.quantile(np.array(batch_scores), float(sev_quantile or 0.7)))
    elif method=="otsu" and batch_scores and len(batch_scores)>1:
        import numpy as np
        x = np.clip(np.array(batch_scores),0,1)
        hist,edges = np.histogram(x,bins=50,range=(0,1))
        hist = hist.astype(float)/max(1.0,hist.sum())
        cum  = np.cumsum(hist)
        mids = (edges[:-1]+edges[1:])/2.0
        mu   = np.cumsum(hist*mids)
        mu_t = mu[-1]
        sigma_b = (mu_t*cum - mu)**2 / (cum*(1-cum)+1e-12)
        k=int(np.nanargmax(sigma_b))
        th=float((edges[k]+edges[k+1])/2.0)
    else:
        th=sev_th
    return p, th

# ---------- Attribution parsing & fusion ----------
def _collect_org_probs(org: Dict[str,Any]) -> List[Tuple[float,float]]:

    pairs=[]
    for k in ["prob","p","score","value"]:
        if k in org:
            try:
                p=float(org[k]); 
                if 0<=p<=1: 
                    pairs.append((p, 1.0))  
                    return pairs
            except: 
                pass
    key_weights=[("final_score",0.20),("kb_score",0.40),("tool_score",0.40)]
    for k,w in key_weights:
        if k in org:
            try:
                p=float(org[k]); 
                if 0<=p<=1: pairs.append((p, w))
            except: pass
    if not pairs:
        for k,v in org.items():
            try:
                p=float(v); 
                if 0<=p<=1:
                    pairs.append((p, 1.0))
                    break
            except: 
                continue
    return pairs

def fuse_org_probability(org: Dict[str,Any]) -> float:
    pairs=_collect_org_probs(org)
    if not pairs:
        return 0.0
    if len(pairs)==1:
        return float(pairs[0][0])
    probs=[p for p,_ in pairs]; weights=[w for _,w in pairs]
    weights=reweight_with_agreement(weights, probs)
    return odds_pool(probs, weights)

def normalize_attrib_input(attrib: Any) -> Tuple[List[Dict[str,Any]], Optional[float]]:

    if isinstance(attrib, list):
        return attrib, None
    if isinstance(attrib, dict):
        if "top3_combined_prob" in attrib:
            try:
                p=float(attrib["top3_combined_prob"]); 
                if 0<=p<=1: return [], p
            except: pass
        # dict mapping org->prob?
        per=[]
        for k,v in attrib.items():
            try:
                p=float(v)
            except:
                continue
            if 0<=p<=1:
                per.append({"name": k, "prob": p})
        if per:
            return per, None
    return [], None

def apt_probability_modeA(attrib_list, p_severity, alpha_best=0.8, alpha_margin=0.6, beta_link=0.5):
    if not attrib_list: return 0.0, {}, 0.0, 0.0
    per={}
    for org in attrib_list:
        name = org.get("name") or org.get("org") or org.get("actor") or "UNKNOWN"
        per[name] = fuse_org_probability(org)
    items = sorted(per.items(), key=lambda kv: kv[1], reverse=True)
    best_p = items[0][1]
    second = items[1][1] if len(items)>1 else 0.0
    margin = max(0.0, best_p - second)
    z = alpha_best*logit(best_p) + alpha_margin*logit(0.5 + 0.5*margin)
    p_apt_raw = sigmoid(z)
    p_apt = odds_pool([p_apt_raw, p_severity],[beta_link, 1.0-beta_link])
    return p_apt, per, best_p, margin

def apt_probability_modeB(top3_combined_prob: float, p_severity: float, beta_link=0.5):
    p_attr = float(top3_combined_prob or 0.0)
    p_apt = odds_pool([p_attr, p_severity],[beta_link, 1.0-beta_link])
    return p_apt

def decide(sample: Dict[str,Any], cfg: Dict[str,Any]) -> Dict[str,Any]:
    assoc = sample.get("assoc_agent", {}) or {}
    judge = sample.get("judge_agent", {}) or {}
    attrib= sample.get("attrib_agent", {}) or {}

    p_sev, th = severity_probability(
        assoc, judge,
        sev_weights=cfg.get("sev_weights",(0.40,0.25,0.20,0.15)),
        batch_scores=cfg.get("batch_scores"),
        sev_th=cfg.get("sev_th",0.65),
        method=cfg.get("sev_method","fixed"),
        sev_quantile=cfg.get("sev_quantile")
    )
    sev_label = "HIGH" if p_sev>=th else "LOW"

    per_org_list, top3_prob = normalize_attrib_input(attrib)

    per_org, best_p, margin = {}, 0.0, 0.0
    org_name, org_prob = None, 0.0

    if per_org_list:
        p_apt, per_org, best_p, margin = apt_probability_modeA(
            per_org_list, p_sev,
            alpha_best=cfg.get("alpha_best",0.8),
            alpha_margin=cfg.get("alpha_margin",0.6),
            beta_link=cfg.get("beta_link",0.5)
        )
        is_apt = p_apt >= cfg.get("apt_th",0.60)
        if is_apt and per_org:
            best_name, best_val = max(per_org.items(), key=lambda kv: kv[1])
            if (best_val >= cfg.get("org_th",0.55)) and (margin >= cfg.get("org_margin",0.05)):
                org_name, org_prob = best_name, best_val
    else:
        p_apt = apt_probability_modeB(top3_prob, p_sev, beta_link=cfg.get("beta_link",0.5))
        is_apt = p_apt >= cfg.get("apt_th",0.60)

    return {
        "severity_prob": round(p_sev,4),
        "severity_threshold": round(th,4),
        "severity_label": sev_label,
        "is_apt": bool(is_apt),
        "apt_prob": round(p_apt,4),
        "apt_threshold": cfg.get("apt_th",0.60),
        "org": org_name,
        "org_prob": round(org_prob,4),
        "org_margin": round(margin,4),
        "per_org_prob": {k: round(v,4) for k,v in per_org.items()},
        "signals": {
            "assoc_conf": conf_map(assoc.get("关联的信心程度") or assoc.get("confidence")),
            "judge_level": level_map(judge.get("level")),
            "judge_risk_norm": norm01_risk(judge.get("risk_score")),
            "judge_conf": conf_map(judge.get("confidence"))
        }
    }

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True, help="Path to JSON (single or batch)")
    ap.add_argument("--sev-th", type=float, default=0.65)
    ap.add_argument("--apt-th", type=float, default=0.50)
    ap.add_argument("--org-th", type=float, default=0.55)
    ap.add_argument("--org-margin", type=float, default=0.05)
    ap.add_argument("--sev-method", choices=["fixed","otsu","quantile"], default="fixed")
    ap.add_argument("--sev-quantile", type=float, default=None)
    args = ap.parse_args()

    data = json.loads(open(args.run,"r",encoding="utf-8").read())
    cfg = {
        "sev_th": args.sev_th,
        "apt_th": args.apt_th,
        "org_th": args.org_th,
        "org_margin": args.org_margin,
        "sev_method": args.sev_method,
        "sev_quantile": args.sev_quantile
    }

    if isinstance(data, dict) and not {"assoc_agent","judge_agent","attrib_agent"} & set(data.keys()):
        if args.sev_method in ["otsu","quantile"]:
            scores=[]
            for v in data.values():
                p,_ = severity_probability(v.get("assoc_agent",{}), v.get("judge_agent",{}), method="fixed")
                scores.append(p)
            cfg["batch_scores"]=scores
        out={k: decide(v,cfg) for k,v in data.items()}
        output_path = "file_path"
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump({"preds": out}, f, ensure_ascii=False, indent=2)
        print(f"Results saved to {output_path}"); return

    if isinstance(data, dict):
        if args.sev_method in ["otsu","quantile"]:
            cfg["batch_scores"]=[severity_probability(data.get("assoc_agent",{}), data.get("judge_agent",{}), method="fixed")[0]]
        output_path = "file_path"
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump({"pred": decide(data,cfg)}, f, ensure_ascii=False, indent=2)
        print(f"Result saved to {output_path}"); return

    print("[error] invalid input JSON")

if __name__=="__main__":
    main()
