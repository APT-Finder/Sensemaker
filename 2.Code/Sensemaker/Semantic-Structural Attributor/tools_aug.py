#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, sys, json, math, argparse, random, csv, re, ast
from collections import Counter, defaultdict
from typing import List, Dict, Any, Optional

def normalize_ttp(t: str) -> Optional[str]:
    if not isinstance(t,str): return None
    t=t.strip().upper().replace('/','.')
    if not t.startswith('T'): return None
    p=t.split('.')
    if len(p)==1 and p[0][1:].isdigit(): return p[0]
    if p[0][1:].isdigit():
        if len(p)>1 and p[1].isdigit(): return p[0]+"."+p[1]
        return p[0]
    return None

def normalize_chain(seq: List[str]) -> List[str]:
    out=[]
    for x in seq:
        y=normalize_ttp(x)
        if y: out.append(y)
    return out

def is_list_of_str(x)->bool:
    return isinstance(x, list) and all(isinstance(e, str) for e in x)

def extract_chains_from_obj(obj: Any) -> List[List[str]]:
    chains: List[List[str]] = []
    def push(seq):
        if is_list_of_str(seq):
            n = normalize_chain(seq)
            if n: chains.append(n)

    if isinstance(obj, list):
        for e in obj:
            if is_list_of_str(e):
                push(e)
            elif isinstance(e, dict):
                for k in ("ttps_chain","chain","chains","ttps","sequence"):
                    if k in e and is_list_of_str(e[k]): push(e[k])

    elif isinstance(obj, dict):
        if "chains" in obj and isinstance(obj["chains"], list):
            for e in obj["chains"]:
                if is_list_of_str(e): push(e)
                elif isinstance(e, dict):
                    for k in ("ttps_chain","chain","chains","ttps","sequence"):
                        if k in e and is_list_of_str(e[k]): push(e[k])

        for v in obj.values():
            if is_list_of_str(v):
                push(v)
            elif isinstance(v, list):
                for e in v:
                    if is_list_of_str(e): push(e)
                    elif isinstance(e, dict):
                        for k in ("ttps_chain","chain","chains","ttps","sequence"):
                            if k in e and is_list_of_str(e[k]): push(e[k])
            elif isinstance(v, dict):
                for k in ("ttps_chain","chain","chains","ttps","sequence"):
                    vv = v.get(k)
                    if is_list_of_str(vv): push(vv)

    return chains

def load_profile_json(path: str) -> List[List[str]]:
    with open(path,'r',encoding='utf-8') as f:
        txt=f.read()
    try:
        obj=json.loads(txt)
        chains = extract_chains_from_obj(obj)
        if chains:
            return chains
    except json.JSONDecodeError:
        pass
    chains=[]
    with open(path,'r',encoding='utf-8') as f:
        for line in f:
            line=line.strip()
            if not line: continue
            try:
                obj=json.loads(line)
                chains += extract_chains_from_obj(obj)
            except json.JSONDecodeError:
                continue
    return chains

def iter_profile_files(paths, recursive: bool) -> list:
    exts = (".json", ".jsonl")
    cand = []
    def add_if_json(path):
        if path.lower().endswith(exts) and os.path.isfile(path):
            cand.append(os.path.abspath(path))
    for p in paths:
        if os.path.isfile(p):
            add_if_json(p); continue
        if os.path.isdir(p):
            found_here = False
            try:
                for name in os.listdir(p):
                    full = os.path.join(p, name)
                    if os.path.isfile(full) and full.lower().endswith(exts):
                        add_if_json(full); found_here = True
            except Exception as e:
                print(f"[WARN] listdir failed: {p}: {e}", file=sys.stderr)
            if recursive or not found_here:
                for root, _, files in os.walk(p):
                    for name in files:
                        add_if_json(os.path.join(root, name))
        else:
            print(f"[WARN] path not found: {p}", file=sys.stderr)
    cand = sorted(set(cand))
    if not cand:
        print("[ERROR] No profile JSON/JSONL files found from inputs.", file=sys.stderr)
    else:
        print(f"[INFO] profile files discovered: {len(cand)}")
    return cand

def read_tactic_map_csv(path: str) -> Dict[str, List[str]]:

    if not path or not os.path.isfile(path):
        return {}

    mapping: Dict[str, List[str]] = {}

    parsed_any = False
    with open(path, 'r', encoding='utf-8') as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith('#'):
                continue
            if ';' not in line:
                continue
            left, right = line.split(';', 1)
            tech = (left or '').strip().upper().replace('/', '.')
            if not tech.startswith('T'):
                continue
            try:
                lst = ast.literal_eval(right.strip())
                if isinstance(lst, (list, tuple)):
                    tactics = [str(x).strip().upper() for x in lst if str(x).strip()]
                else:
                    tactics = [str(lst).strip().upper()]
            except Exception:
                try:
                    s = right.strip().replace("'", '"')
                    obj = json.loads(s)
                    if isinstance(obj, list):
                        tactics = [str(x).strip().upper() for x in obj if str(x).strip()]
                    else:
                        tactics = [str(obj).strip().upper()]
                except Exception:
                    continue

            if not tactics:
                continue
            parsed_any = True
            mapping.setdefault(tech, [])
            for t in tactics:
                if t not in mapping[tech]:
                    mapping[tech].append(t)
            parent = tech.split('.')[0]
            mapping.setdefault(parent, [])
            for t in tactics:
                if t not in mapping[parent]:
                    mapping[parent].append(t)

    if parsed_any:
        return mapping

    try:
        with open(path, 'r', encoding='utf-8') as f:
            r = csv.DictReader(f)
            if not r.fieldnames:
                return mapping
            hdr = [h.strip().lower() for h in r.fieldnames]
            col_tech = None; col_tac = None
            for i, h in enumerate(hdr):
                if 'tech' in h: col_tech = r.fieldnames[i]
                if 'tactic' in h: col_tac = r.fieldnames[i]
            if not col_tech or not col_tac:
                return mapping
            for row in r:
                tech = (row.get(col_tech, '') or '').strip().upper().replace('/', '.')
                tac  = (row.get(col_tac, '')  or '').strip().upper()
                if not tech.startswith('T') or not tac.startswith('TA'):
                    continue
                mapping.setdefault(tech, [])
                if tac not in mapping[tech]:
                    mapping[tech].append(tac)
                parent = tech.split('.')[0]
                mapping.setdefault(parent, [])
                if tac not in mapping[parent]:
                    mapping[parent].append(tac)
    except Exception:
        pass

    return mapping

def tactic_of(ttp: str, tac_map: Dict[str, List[str]], prev_tac: Optional[str]=None) -> str:
    opts = tac_map.get(ttp) or tac_map.get(ttp.split('.')[0]) or []
    if prev_tac and prev_tac in opts:
        return prev_tac
    return opts[0] if opts else "UNK"

def segment_by_tactic(seq: List[str], tac_map: Dict[str, List[str]]):
    segs=[]; cur=None; bucket=[]
    for t in seq:
        tac = tactic_of(t, tac_map, prev_tac=cur)
        if cur is None or tac==cur:
            bucket.append(t); cur = tac if cur is None else cur
        else:
            segs.append((cur,bucket)); bucket=[t]; cur=tac
    if bucket: segs.append((cur,bucket))
    return segs

def lcs_len(a: List[str], b: List[str]) -> int:
    n,m=len(a),len(b)
    if n==0 or m==0: return 0
    dp=[0]*(m+1)
    for i in range(1,n+1):
        prev=0
        for j in range(1,m+1):
            tmp=dp[j]
            if a[i-1]==b[j-1]: dp[j]=prev+1
            else: dp[j]=max(dp[j], dp[j-1])
            prev=tmp
    return dp[m]

def bounded_coverage(obs: List[str], cand: List[str], L: int=5) -> float:
    if not obs: return 0.0
    last=-1; matched=0
    for t in obs:
        s=(last+1) if last>=0 else 0
        e=min(len(cand), (last if last>=0 else -1)+L+1)
        for j in range(s,e):
            if cand[j]==t:
                matched+=1; last=j; break
    return matched/max(1,len(obs))

from collections import Counter
def stage_bigrams_from_segments(segs, win_intra=2, win_inter=2, w_intra=0.5, w_inter=1.0):
    c=Counter()
    for tac,toks in segs:
        m=len(toks)
        for i in range(m-1):
            for j in range(i+1, min(m, i+1+win_intra)):
                a=toks[i]; b=toks[j]
                if a!=b: c[(a,b)]+=w_intra
    for (t1,A),(t2,B) in zip(segs, segs[1:]):
        left=A[-win_inter:] if win_inter>0 else []
        right=B[:win_inter] if win_inter>0 else []
        for a in left:
            for b in right:
                if a!=b: c[(a,b)]+=w_inter
    return c

def build_siblings(group_chains: Dict[str, List[List[str]]]) -> Dict[str, List[str]]:
    parent2child=defaultdict(set)
    for chains in group_chains.values():
        for c in chains:
            for t in c:
                p=t.split('.')[0]
                if '.' in t: parent2child[p].add(t)
    return {p: sorted(list(s)) for p,s in parent2child.items()}

def augment_chain_phasewise(
    seq: List[str],
    tac_map: Dict[str,List[str]],
    win_intra=2, swap_p=0.15, drop_p=0.15, insert_p=0.15,
    siblings: Optional[Dict[str,List[str]]]=None,
    max_len: int = 8
) -> List[str]:
    segs = segment_by_tactic(seq, tac_map)
    out=[]
    for tac, toks in segs:
        toks=list(toks)
        
        i=0
        while i < len(toks)-1:
            if random.random() < swap_p:
                toks[i], toks[i+1] = toks[i+1], toks[i]
                i += 2
            else:
                i += 1
        kept=[]
        for t in toks:
            if random.random() < drop_p:
                continue
            kept.append(t)
        toks=kept
        if siblings:
            inserts=[]
            for t in toks:
                par=t.split('.')[0]
                sibs=[x for x in siblings.get(par, []) if x!=t]
                if sibs and random.random() < insert_p:
                    inserts.append(random.choice(sibs))
            for s in inserts:
                pos=random.randrange(0, len(toks)+1)
                toks.insert(pos, s)
        out.extend(toks)

    if len(out) > max_len:
        out = out[-max_len:]
    return out or seq

def main():
    ap=argparse.ArgumentParser("augment ttp profiles")
    ap.add_argument("-i","--inputs", nargs="+", required=True)
    ap.add_argument("--recursive", action="store_true")
    ap.add_argument("--tactic-map-csv", required=True)
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--per-chain", type=int, default=3)
    ap.add_argument("--max-len", type=int, default=8)
    ap.add_argument("--win-intra", type=int, default=2)
    ap.add_argument("--swap-p", type=float, default=0.15)
    ap.add_argument("--drop-p", type=float, default=0.15)
    ap.add_argument("--insert-p", type=float, default=0.15)
    ap.add_argument("--accept-lcs", type=float, default=0.60)
    ap.add_argument("--accept-bcov", type=float, default=0.70)
    args=ap.parse_args()

    files = iter_profile_files(args.inputs, args.recursive)
    if not files: return 2

    profiles: Dict[str, List[List[str]]] = {}
    for fp in files:
        chains=load_profile_json(fp)
        if chains:
            name=os.path.splitext(os.path.basename(fp))[0]
            profiles[name]=chains
            print(f"[INFO] loaded {name}: {len(chains)} chains")
        else:
            print(f"[WARN] no chains in {fp}", file=sys.stderr)
    if not profiles:
        print("[ERROR] empty profiles", file=sys.stderr); return 2

    tac_map = read_tactic_map_csv(args.tactic_map_csv)
    if not tac_map:
        print("[WARN] tactic map not loaded or empty; stage-aware增强将退化为非阶段感知", file=sys.stderr)
    siblings = build_siblings(profiles)

    os.makedirs(args.outdir, exist_ok=True)

    for g, chains in profiles.items():
        aug=[]
        for c in chains:
            base = c
            for _ in range(max(0, args.per_chain)):
                cand = augment_chain_phasewise(
                    base, tac_map,
                    win_intra=args.win_intra,
                    swap_p=args.swap_p, drop_p=args.drop_p, insert_p=args.insert_p,
                    siblings=siblings, max_len=args.max_len
                )
                best_lcs=0.0; best_bcov=0.0
                for real in chains:
                    if not real: continue
                    L=lcs_len(cand, real); best_lcs=max(best_lcs, L/max(1,len(cand)))
                    bc=bounded_coverage(cand, real, L=5); best_bcov=max(best_bcov, bc)
                if best_lcs >= args.accept_lcs or best_bcov >= args.accept_bcov:
                    aug.append(cand)

        out_path=os.path.join(args.outdir, f"{g}.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump({"chains": aug}, f, ensure_ascii=False, indent=2)
        print(f"[OK] {g}: +{len(aug)} chains -> {out_path}")

if __name__=="__main__":
    sys.exit(main())
