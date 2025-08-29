#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, sys, json, csv, math, random, argparse
from collections import Counter, defaultdict
from typing import List, Dict, Tuple, Optional, Iterable, Set

def normalize_ttp(t: str) -> Optional[str]:
    if not isinstance(t, str): return None
    s = t.strip().upper()
    if not s: return None
    if s.startswith("T"):
        p = s.split(".")
        if len(p) == 1:
            return p[0]
        q = p[1].replace("/", "").replace("\\", "")
        if q.isdigit():
            return p[0] + "." + q
        if p[1].isdigit():
            return p[0] + "." + p[1]
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

def extract_chains_from_obj(obj: any) -> List[List[str]]:
    chains=[]
    def push(seq):
        seq = normalize_chain(seq)
        if seq: chains.append(seq)
    if isinstance(obj, list):
        if is_list_of_str(obj):
            push(obj)
        else:
            for e in obj:
                if is_list_of_str(e): push(e)
                elif isinstance(e, dict):
                    for k in ("ttps_chain","chain","chains","ttps","sequence"):
                        if k in e and is_list_of_str(e[k]): push(e[k])
    if isinstance(obj, dict):
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
    try:
        with open(path,'r',encoding='utf-8') as f:
            txt=f.read().strip()
        try:
            obj=json.loads(txt)
            return extract_chains_from_obj(obj)
        except json.JSONDecodeError:
            pass
    except Exception as e:
        print(f"[WARN] read file failed: {path}: {e}", file=sys.stderr)
        return []
    out=[]
    try:
        with open(path,'r',encoding='utf-8') as f:
            for line in f:
                line=line.strip()
                if not line: continue
                try:
                    obj=json.loads(line)
                    out += extract_chains_from_obj(obj)
                except json.JSONDecodeError:
                    continue
    except Exception as e:
        print(f"[WARN] read jsonl failed: {path}: {e}", file=sys.stderr)
    return out

def load_observed_dict(path: str) -> Dict[str, List[str]]:
    with open(path,'r',encoding='utf-8') as f:
        obj=json.load(f)
    out={}
    for k,v in obj.items():
        if is_list_of_str(v): out[k]=normalize_chain(v)
    return out

def iter_profile_files(paths: List[str], recursive: bool) -> List[str]:
    exts=(".json",".jsonl"); cand=[]
    def add_if_json(p):
        if p.lower().endswith(exts) and os.path.isfile(p):
            cand.append(os.path.abspath(p))
    for p in paths:
        if os.path.isfile(p):
            add_if_json(p); continue
        if os.path.isdir(p):
            found=False
            try:
                for nm in os.listdir(p):
                    full=os.path.join(p,nm)
                    if os.path.isfile(full) and full.lower().endswith(exts):
                        add_if_json(full); found=True
            except Exception as e:
                print(f"[WARN] listdir: {p}: {e}", file=sys.stderr)
            if recursive or not found:
                for root,_,files in os.walk(p):
                    for nm in files:
                        add_if_json(os.path.join(root,nm))
        else:
            print(f"[WARN] path not found: {p}", file=sys.stderr)
    cand=sorted(set(cand))
    if not cand:
        print("[ERROR] No profile JSON/JSONL found.", file=sys.stderr)
    else:
        print(f"[INFO] profile files: {len(cand)}")
    return cand


def read_tactic_map_csv(path: str) -> Dict[str, List[str]]:
    mapping: Dict[str, List[str]] = {}
    parsed_any=False
    try:
        with open(path,'r',encoding='utf-8') as f:
            for line in f:
                s=line.strip()
                if not s or ";" not in s: continue
                a,b=s.split(";",1)
                tech=normalize_ttp(a)
                if not tech: continue
                try:
                    arr=json.loads(b.replace("'",'"'))
                except Exception: 
                    continue
                if not isinstance(arr,list) or not arr: 
                    continue
                parsed_any=True
                mapping.setdefault(tech, [])
                parent=tech.split('.')[0]
                mapping.setdefault(parent, [])
                for t in arr:
                    if isinstance(t,str):
                        if t not in mapping[tech]: mapping[tech].append(t)
                        if t not in mapping[parent]: mapping[parent].append(t)
    except Exception as e:
        print(f"[WARN] tactic semicolon parse fail: {e}", file=sys.stderr)
    if parsed_any: return mapping
    try:
        with open(path,'r',encoding='utf-8') as f:
            r=csv.DictReader(f)
            hdr=[(h or "").strip().lower() for h in (r.fieldnames or [])]
            col_tech=None; col_tac=None
            for i,h in enumerate(hdr):
                if 'tech' in h: col_tech=r.fieldnames[i]
                if 'tactic' in h: col_tac=r.fieldnames[i]
            if not col_tech or not col_tac:
                return mapping
            for row in r:
                tech=normalize_ttp(row.get(col_tech,""))
                tac=(row.get(col_tac,"") or "").strip()
                if not tech or not tac: continue
                parent=tech.split('.')[0]
                for k in (tech,parent):
                    mapping.setdefault(k, [])
                    if tac not in mapping[k]: mapping[k].append(tac)
    except Exception as e:
        print(f"[WARN] tactic csv parse fail: {e}", file=sys.stderr)
    return mapping

def tactic_of(ttp: str, tac_map: Dict[str, List[str]], prev: Optional[str]=None) -> str:
    opts=tac_map.get(ttp) or tac_map.get(ttp.split('.')[0]) or []
    if prev and prev in opts: return prev
    return opts[0] if opts else "UNK"

def segment_by_tactic(seq: List[str], tac_map: Dict[str, List[str]]):
    segs=[]; cur=None; buf=[]
    for t in seq:
        tac=tactic_of(t, tac_map, prev=cur)
        if cur is None:
            cur=tac; buf=[t]
        elif tac==cur:
            buf.append(t)
        else:
            segs.append((cur, buf))
            cur=tac; buf=[t]
    if buf: segs.append((cur, buf))
    return segs

def compress_runs(seq: List[str]) -> List[str]:
    out=[]; prev=None
    for t in seq:
        if t!=prev: out.append(t); prev=t
    return out

def map_to_parent(seq: List[str]) -> List[str]:
    return [s.split('.')[0] if '.' in s else s for s in seq]

def expand_prototypes(seq: List[str], kmin: int, kmax: int, cap: int=0) -> List[List[str]]:
    protos=[seq[:]]
    n=len(seq)
    windows=[]
    for k in range(max(2,kmin), max(2,kmax)+1):
        if k>n: break
        for i in range(0, n-k+1):
            windows.append(seq[i:i+k])
    if cap>0 and len(windows)>cap:
        random.shuffle(windows)
        windows=windows[:cap]
    protos += windows
    return protos

def parent(t: str) -> str:
    return t.split(".")[0]

def collapse(seq: List[str]) -> List[str]:
    return [parent(x) for x in seq]

def bigrams(seq: List[str]) -> List[Tuple[str,str]]:
    return list(zip(seq, seq[1:]))

def kskip_bigrams(seq: List[str], window: int=6) -> Counter:
    C=Counter()
    n=len(seq)
    for i in range(n-1):
        maxj=min(n-1, i+window)
        a=seq[i]
        for j in range(i+1, maxj+1):
            b=seq[j]
            if a!=b:
                C[(a,b)]+=1
    return C

def stage_bigrams_from_segments(segs, win_intra=2, win_inter=2, w_intra=0.6, w_inter=1.0) -> Counter:
    c=Counter()
    for _, toks in segs:
        m=len(toks)
        for i in range(m-1):
            a=toks[i]; maxj=min(m-1, i+win_intra)
            for j in range(i+1, maxj+1):
                b=toks[j]
                if a!=b: c[(a,b)] += w_intra
    for (t1,A),(t2,B) in zip(segs, segs[1:]):
        left=A[-win_inter:] if win_inter>0 else []
        right=B[:win_inter] if win_inter>0 else []
        for a in left:
            for b in right:
                if a!=b: c[(a,b)] += w_inter
    return c

def tactic_hist(seq: List[str], tac_map: Dict[str,List[str]])->Counter:
    c=Counter(); cur=None
    if not tac_map:
        c["UNK"]+=len(seq); return c
    for t in seq:
        cur = tactic_of(t, tac_map, prev=cur)
        c[cur]+=1
    return c

def tactic_trans_hist(seq: List[str], tac_map: Dict[str,List[str]], skip: int=1)->Counter:
    tacs=[]; cur=None
    for t in seq:
        cur=tactic_of(t, tac_map, prev=cur)
        tacs.append(cur)
    C=Counter()
    m=len(tacs)
    for i in range(m-1):
        C[(tacs[i], tacs[i+1])] += 1
        if skip>=1 and i+2<m:
            C[(tacs[i], tacs[i+2])] += 0.5
    return C

def jaccard_weighted_set(A: Set[str], B: Set[str], idf: Dict[str,float]) -> float:
    if not A and not B: return 1.0
    if not A or not B: return 0.0
    inter = sum(idf.get(t,1.0) for t in (A&B))
    union = sum(idf.get(t,1.0) for t in (A|B))
    return inter / (union+1e-12)

def weighted_jaccard_counts(c1: Counter, c2: Counter) -> float:
    keys=set(c1)|set(c2)
    if not keys: return 0.0
    smin=0.0; smax=0.0
    for k in keys:
        a=c1.get(k,0.0); b=c2.get(k,0.0)
        smin += min(a,b); smax += max(a,b)
    if smax<=0: return 0.0
    return smin/smax

def cosine_counts(c1:Counter, c2:Counter)->float:
    if not c1 or not c2: return 0.0
    dot=0.0; n1=0.0; n2=0.0
    keys=set(c1)|set(c2)
    for k in keys:
        a=c1.get(k,0.0); b=c2.get(k,0.0)
        dot+=a*b; n1+=a*a; n2+=b*b
    if n1<=0 or n2<=0: return 0.0
    return dot/(math.sqrt(n1)*math.sqrt(n2))

def minmax_norm(d: Dict[str,float]) -> Dict[str,float]:
    if not d: return {}
    mx=max(d.values()); mn=min(d.values())
    if mx<=mn: return {k:0.0 for k in d}
    return {k:(v-mn)/(mx-mn) for k,v in d.items()}

def lcs_len(a: List[str], b: List[str]) -> int:
    n, m = len(a), len(b)
    dp=[0]*(m+1)
    for i in range(1, n+1):
        prev=0
        for j in range(1, m+1):
            tmp=dp[j]
            if a[i-1]==b[j-1]:
                dp[j]=prev+1
            else:
                dp[j]=max(dp[j], dp[j-1])
            prev=tmp
    return dp[m]

def lcs_norm_sym(a: List[str], b: List[str]) -> float:
    L=lcs_len(a,b)
    denom=max(1, len(a)+len(b))
    return (2.0*L)/denom

def bounded_cov(obs: List[str], cand: List[str], L:int=6)->float:
    if not obs: return 0.0
    last=-1
    matched=0
    for t in obs:
        s = (last+1) if last>=0 else 0
        e = min(len(cand), (last if last>=0 else -1)+L+1)
        for jj in range(s, e):
            if cand[jj]==t:
                matched += 1
                last = jj
                break
    return matched/max(1,len(obs))

def topk_softmax(values: List[float], k: int=3, tau: float=0.15)->float:
    if not values: return 0.0
    xs=sorted(values, reverse=True)[:max(1,k)]
    ws=[math.exp(x/tau) for x in xs]
    Z=sum(ws)
    return sum(x*w for x,w in zip(xs,ws))/max(1e-12,Z)

def build_idf_for_sets(group_sets: Dict[str,set]) -> Dict[str,float]:
    df=Counter()
    for s in group_sets.values():
        for t in s: df[t]+=1
    N=max(1,len(group_sets))
    return {t:1.0+math.log((N+1)/(df_t+1)) for t,df_t in df.items()}

def collapse(seq: List[str]) -> List[str]:
    return [parent(x) for x in seq]

def train_multinomial_nb(profiles: Dict[str, List[List[str]]], alpha: float=1.0):
    vocab=set(); tok_cnt={}; class_cnt=Counter()
    for g,chains in profiles.items():
        C=Counter()
        for c in chains:
            C.update(collapse(c)) 
        tok_cnt[g]=C; vocab |= set(C)
        class_cnt[g]+=len(chains)
    V=max(1,len(vocab))
    model={}
    total_classes=sum(class_cnt.values())
    for g in profiles:
        tot = sum(tok_cnt[g].values()) + alpha*V
        loglik={t: math.log((tok_cnt[g].get(t,0)+alpha)/tot) for t in vocab}
        unk=math.log(alpha/tot)
        prior = math.log((class_cnt[g]/max(1,total_classes)))
        model[g]={"loglik":loglik,"unk":unk,"prior":prior}
    return model, vocab

def train_complement_nb(profiles: Dict[str, List[List[str]]], alpha: float=1.0):
    vocab=set(); tok_cnt={}; totals={}
    allC=Counter()
    for g,chains in profiles.items():
        C=Counter()
        for c in chains:
            C.update(collapse(c))
        tok_cnt[g]=C; allC+=C; vocab|=set(C)
    V=max(1,len(vocab))
    for g in profiles:
        comp = allC - tok_cnt[g]
        totals[g]=sum(comp.values()) + alpha*V
    model={}
    for g in profiles:
        comp = allC - tok_cnt[g]
        loglik={t: math.log((comp.get(t,0)+alpha)/totals[g]) for t in vocab}
        unk=math.log(alpha/totals[g])
        model[g]={"loglik":loglik,"unk":unk,"prior":0.0}
    return model, vocab

def nb_logprob(model, vocab, seq: List[str]) -> Dict[str,float]:
    cp=collapse(seq); cnt=Counter(cp)
    out={}
    for g,m in model.items():
        s = m.get("prior",0.0)
        for t,c in cnt.items():
            s += c * m["loglik"].get(t, m["unk"])
        out[g]=s
    return out

def otsu_threshold(values: List[float]) -> float:
    if not values: return 0.0
    xs=sorted(values)
    n=len(xs)
    if n==1: return xs[0]
    mn=min(xs); mx=max(xs)
    if mx<=mn: return mn
    xs=[(x-mn)/(mx-mn) for x in xs]
    hist=[0]*256
    for v in xs:
        i=min(255,max(0,int(v*255)))
        hist[i]+=1
    total=sum(hist)
    sum_total=sum(i*hist[i] for i in range(256))
    sumB=0; wB=0; max_var=-1; thr=0
    for t in range(256):
        wB += hist[t]
        if wB==0: continue
        wF = total - wB
        if wF==0: break
        sumB += t*hist[t]
        mB = sumB/wB
        mF = (sum_total - sumB)/wF
        var = wB*wF*(mB-mF)*(mB-mF)
        if var>max_var:
            max_var=var; thr=t
    return mn + (mx-mn)*(thr/255.0)

def parse_args(argv=None):
    ap=argparse.ArgumentParser("Multiclass TTP attribution")
    ap.add_argument("-i","--inputs", nargs="+", required=True)
    ap.add_argument("--recursive", action="store_true")
    ap.add_argument("--chains-file", required=True)
    ap.add_argument("--outdir", default="./out_stage")

    ap.add_argument("--collapse-runs", action="store_true")
    ap.add_argument("--parent-level", action="store_true")

    ap.add_argument("--proto-min-k", type=int, default=2)
    ap.add_argument("--proto-max-k", type=int, default=6)
    ap.add_argument("--proto-cap-per-chain", type=int, default=0, help=">0 to subsample windows per chain")

    ap.add_argument("--L", type=int, default=6)                
    ap.add_argument("--win-intra", type=int, default=2)
    ap.add_argument("--win-inter", type=int, default=2)
    ap.add_argument("--intra-weight", type=float, default=0.6)
    ap.add_argument("--inter-weight", type=float, default=1.0)

    ap.add_argument("--weights-long", nargs=6, type=float, default=[0.75,0.00,0.15,0.10,0.00,0.00])
    ap.add_argument("--weights-mid",  nargs=6, type=float, default=[0.70,0.00,0.20,0.10,0.00,0.00])
    ap.add_argument("--weights-short",nargs=6, type=float, default=[0.65,0.00,0.20,0.15,0.00,0.00])

    ap.add_argument("--preselect-groups", type=int, default=30)
    ap.add_argument("--preselect-thr", type=float, default=0.55, help="relative to top1 of (SET+TACTIC quick)")

    ap.add_argument("--margin-threshold", type=float, default=0.05)
    ap.add_argument("--accept-lcs", type=float, default=0.90)
    ap.add_argument("--accept-bcov", type=float, default=0.60)
    ap.add_argument("--seq-strong", type=float, default=0.00, help=">0 时，SEQ>=该阈值也作为强证据直通")

    ap.add_argument("--tactic-map-csv", default=None)

    ap.add_argument("--bayes-mode", choices=["bernoulli","mnb","cnb"], default="mnb")
    ap.add_argument("--bayes-alpha", type=float, default=1.0)
    ap.add_argument("--p-det", type=float, default=0.65)   
    ap.add_argument("--p-fp",  type=float, default=0.03)  

    ap.add_argument("--topk", type=int, default=3)        
    ap.add_argument("--tau", type=float, default=0.15)

    ap.add_argument("--seed", type=int, default=42)

    return ap.parse_args(argv)

def main(argv=None):
    args=parse_args(argv); random.seed(args.seed)

    files=iter_profile_files(args.inputs, args.recursive)
    if not files: return 2

    profiles={}
    for fp in files:
        chains=load_profile_json(fp)
        if not chains: continue
        name=os.path.splitext(os.path.basename(fp))[0]
        profiles[name]=chains
    if not profiles:
        print("[ERROR] empty profiles", file=sys.stderr); return 2

    observed=load_observed_dict(args.chains_file)
    if not observed:
        print("[ERROR] empty observed", file=sys.stderr); return 2

    if args.collapse_runs:
        profiles={g:[compress_runs(c) for c in chains] for g,chains in profiles.items()}
        observed={k:compress_runs(v) for k,v in observed.items()}
    if args.parent_level:
        profiles={g:[map_to_parent(c) for c in chains] for g,chains in profiles.items()}
        observed={k:map_to_parent(v) for k,v in observed.items()}

    tac_map = read_tactic_map_csv(args.tactic_map_csv) if args.tactic_map_csv else {}

    group_protos={}
    for g, chains in profiles.items():
        protos=[]
        for c in chains:
            protos += expand_prototypes(c, args.proto_min_k, args.proto_max_k, cap=args.proto_cap_per_chain)
        group_protos[g]=protos

    group_union_stage={}; group_union_skip={}
    group_tac_hist={}; group_tac_trans={}
    group_sets={}
    for g, protos in group_protos.items():
        u_stage=Counter(); u_skip=Counter()
        for p in protos:
            segs=segment_by_tactic(p, tac_map)
            u_stage += stage_bigrams_from_segments(segs, args.win_intra, args.win_inter, args.intra_weight, args.inter_weight)
            u_skip  += kskip_bigrams(p, window=args.L)
        group_union_stage[g]=u_stage
        group_union_skip[g]=u_skip
        th=Counter(); tr=Counter()
        for p in protos:
            th += tactic_hist(p, tac_map)
            tr += tactic_trans_hist(p, tac_map, skip=1)
        group_tac_hist[g]=th
        group_tac_trans[g]=tr
        group_sets[g]=set(t for c in profiles[g] for t in c)

    idf_sets=build_idf_for_sets(group_sets)

    nb_model=None; nb_vocab=None
    if args.bayes_mode=="mnb":
        nb_model, nb_vocab = train_multinomial_nb(profiles, alpha=args.bayes_alpha)
    elif args.bayes_mode=="cnb":
        nb_model, nb_vocab = train_complement_nb(profiles, alpha=args.bayes_alpha)

    def preselect_groups(seq: List[str]) -> List[str]:
        obs_set=set(seq)
        obs_tac=tactic_hist(seq, tac_map)
        quick={}
        for g in profiles.keys():
            set_sc=jaccard_weighted_set(obs_set, group_sets[g], idf_sets)
            tac_sc=cosine_counts(obs_tac, group_tac_hist[g])
            quick[g]=0.6*set_sc + 0.4*tac_sc
        sorted_g=sorted(quick.items(), key=lambda kv: kv[1], reverse=True)
        if not sorted_g: return []
        base=sorted_g[0][1]
        keep=[g for g,sc in sorted_g[:args.preselect_groups] if sc>=args.preselect_thr*base]
        return keep or [sorted_g[0][0]]

    os.makedirs(args.outdir, exist_ok=True)
    out_csv=os.path.join(args.outdir, "apt_attribution_scores_top1.csv")
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        fieldnames=[
            "chain","pred_group","fused_top1","fused_top2","margin","threshold_batch","unknown",
            "top1_set_raw","top1_seq_raw","top1_lcs_raw","top1_bcov_raw","top1_tac_raw","top1_bayes_raw",
            "set_top1_group","set_top1_raw","seq_top1_group","seq_top1_raw",
            "lcs_top1_group","lcs_top1_raw","bounded_top1_group","bounded_top1_raw",
            "tactic_top1_group","tactic_top1_raw","bayes_top1_group","bayes_top1_raw"
        ]
        writer=csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        fused_list=[]
        all_rows=[]

        for name, obs_seq in observed.items():
            n=len(obs_seq)
            if n<=3: weights=args.weights_short
            elif n<=6: weights=args.weights_mid
            else: weights=args.weights_long
            w_set,w_seq,w_lcs,w_bcov,w_tac,w_bayes=weights

            obs_skip = kskip_bigrams(obs_seq, window=args.L)
            obs_stage = stage_bigrams_from_segments(
                segment_by_tactic(obs_seq, tac_map),
                args.win_intra, args.win_inter,
                args.intra_weight, args.inter_weight
            )
            obs_tac_hist = tactic_hist(obs_seq, tac_map)
            obs_tac_tran = tactic_trans_hist(obs_seq, tac_map, skip=1)
            obs_set = set(obs_seq)

            cands = preselect_groups(obs_seq)

            set_raw={}; seq_raw={}; lcs_raw={}; bcov_raw={}; tac_raw={}; bayes_raw={}
            for g in cands:
                protos = group_protos[g]

                set_vals=[]
                for p in protos:
                    set_vals.append(jaccard_weighted_set(obs_set, set(p), idf_sets))
                set_raw[g]=topk_softmax(set_vals, k=args.topk, tau=args.tau) if set_vals else 0.0

                lcs_vals=[lcs_norm_sym(obs_seq, p) for p in protos]
                lcs_raw[g]=topk_softmax(lcs_vals, k=args.topk, tau=args.tau) if lcs_vals else 0.0

                Lb = args.L
                bc_vals=[bounded_cov(obs_seq, p, L=Lb) for p in protos]
                bcov_raw[g]=max(bc_vals) if bc_vals else 0.0

                sc_stage = weighted_jaccard_counts(obs_stage, group_union_stage[g])
                sc_skip  = weighted_jaccard_counts(obs_skip,  group_union_skip[g])
                seq_raw[g] = 0.6*sc_stage + 0.4*sc_skip

                sc_hist = cosine_counts(obs_tac_hist, group_tac_hist[g])
                sc_tran = cosine_counts(obs_tac_tran, group_tac_trans[g])
                tac_raw[g] = 0.3*sc_hist + 0.7*sc_tran

                if args.bayes_mode=="bernoulli":
                    sc=0.0
                    for t in set(obs_seq):
                        sc += math.log(args.p_det) if t in group_sets[g] else math.log(args.p_fp)
                    bayes_raw[g]=sc
                else:
                    if nb_model is not None:
                        bay = nb_logprob(nb_model, nb_vocab or set(), obs_seq)
                        bayes_raw[g]=bay.get(g, 0.0)
                    else:
                        bayes_raw[g]=0.0

            set_n  = minmax_norm(set_raw)
            seq_n  = minmax_norm(seq_raw)
            lcs_n  = minmax_norm(lcs_raw)
            bcov_n = minmax_norm(bcov_raw)
            tac_n  = minmax_norm(tac_raw)
            bay_n  = minmax_norm(bayes_raw)

            fused={}
            for g in cands:
                fused[g] = (w_set*set_n.get(g,0.0) + w_seq*seq_n.get(g,0.0) +
                            w_lcs*lcs_n.get(g,0.0) + w_bcov*bcov_n.get(g,0.0) +
                            w_tac*tac_n.get(g,0.0) + w_bayes*bay_n.get(g,0.0))
            if not fused:
                all_rows.append({"name":name,"fused":{},"set_raw":set_raw,"seq_raw":seq_raw,"lcs_raw":lcs_raw,
                                 "bcov_raw":bcov_raw,"tac_raw":tac_raw,"bayes_raw":bayes_raw})
                continue

            sorted_g=sorted(fused.items(), key=lambda kv: kv[1], reverse=True)
            top1, sc1 = sorted_g[0]
            top2, sc2 = (sorted_g[1] if len(sorted_g)>1 else (top1, 0.0))
            margin = sc1 - sc2

            fused_list.append(sc1)
            all_rows.append({
                "name":name, "top1":top1, "sc1":sc1, "top2":top2, "sc2":sc2, "margin":margin,
                "fused":fused,
                "set_raw":set_raw,"seq_raw":seq_raw,"lcs_raw":lcs_raw,"bcov_raw":bcov_raw,
                "tac_raw":tac_raw,"bayes_raw":bayes_raw
            })

        thr_otsu = otsu_threshold(fused_list) if fused_list else 0.0

        for r in all_rows:
            name=r["name"]
            fused=r.get("fused",{})
            if not fused:
                writer.writerow({
                    "chain": name, "pred_group": "Unknown", "fused_top1": 0.0, "fused_top2": 0.0,
                    "margin": 0.0, "threshold_batch": thr_otsu, "unknown": True,
                    "top1_set_raw":0,"top1_seq_raw":0,"top1_lcs_raw":0,"top1_bcov_raw":0,"top1_tac_raw":0,"top1_bayes_raw":0,
                    "set_top1_group":"","set_top1_raw":0,"seq_top1_group":"","seq_top1_raw":0,
                    "lcs_top1_group":"","lcs_top1_raw":0,"bounded_top1_group":"","bounded_top1_raw":0,
                    "tactic_top1_group":"","tactic_top1_raw":0,"bayes_top1_group":"","bayes_top1_raw":0
                })
                continue

            sorted_g=sorted(fused.items(), key=lambda kv: kv[1], reverse=True)
            top1, sc1 = sorted_g[0]
            top2, sc2 = (sorted_g[1] if len(sorted_g)>1 else (top1, 0.0))
            margin = sc1 - sc2

            def best_item(d: Dict[str,float]) -> Tuple[str,float]:
                if not d: return "",0.0
                k=max(d, key=d.get); return k, d[k]

            set_best = best_item(r["set_raw"]);  seq_best = best_item(r["seq_raw"])
            lcs_best = best_item(r["lcs_raw"]);  bc_best  = best_item(r["bcov_raw"])
            tac_best = best_item(r["tac_raw"]);  bay_best = best_item(r["bayes_raw"])

            # 强匹配直通（保留）
            lcs_top1=r["lcs_raw"].get(top1,0.0); bc_top1=r["bcov_raw"].get(top1,0.0)
            seq_top1=r["seq_raw"].get(top1,0.0)
            strong=(lcs_top1>=args.accept_lcs and bc_top1>=args.accept_bcov) or \
                   (args.seq_strong>0.0 and seq_top1>=args.seq_strong)

            unknown = (not strong) and (sc1 < thr_otsu) and (margin < args.margin_threshold)
            pred = "Unknown" if unknown else top1

            writer.writerow({
                "chain": name, "pred_group": pred, "fused_top1": sc1, "fused_top2": sc2, "margin": margin,
                "threshold_batch": thr_otsu, "unknown": unknown,
                "top1_set_raw": r["set_raw"].get(top1,0.0),
                "top1_seq_raw": r["seq_raw"].get(top1,0.0),
                "top1_lcs_raw": r["lcs_raw"].get(top1,0.0),
                "top1_bcov_raw": r["bcov_raw"].get(top1,0.0),
                "top1_tac_raw": r["tac_raw"].get(top1,0.0),
                "top1_bayes_raw": r["bayes_raw"].get(top1,0.0),
                "set_top1_group": set_best[0],   "set_top1_raw": set_best[1],
                "seq_top1_group": seq_best[0],   "seq_top1_raw": seq_best[1],
                "lcs_top1_group": lcs_best[0],   "lcs_top1_raw": lcs_best[1],
                "bounded_top1_group": bc_best[0],"bounded_top1_raw": bc_best[1],
                "tactic_top1_group": tac_best[0],"tactic_top1_raw": tac_best[1],
                "bayes_top1_group": bay_best[0], "bayes_top1_raw": bay_best[1],
            })
    # 生成JSON输出
    out_json = os.path.join(args.outdir, "apt_attribution_top3.json")
    json_output = {}
    
    for r in all_rows:
        name = r["name"]
        fused = r.get("fused", {})
        
        if not fused:
            json_output[name] = {
                "top3": [],
                "total_scores": {}
            }
            continue
        
        sorted_g = sorted(fused.items(), key=lambda kv: kv[1], reverse=True)[:3]
        top3 = [{
            "group": g,
            "score": round(sc, 6)
        } for g, sc in sorted_g]
        
        total_scores = {g: round(sc, 6) for g, sc in sorted(fused.items(), key=lambda kv: kv[1], reverse=True)}
        
        json_output[name] = {
            "top3": top3,
            "total_scores": total_scores
        }
    
    with open(out_json, 'w', encoding='utf-8') as f:
        json.dump(json_output, f, ensure_ascii=False, indent=2)
    
    print(f"CSV output: {out_csv}")
    print(f"JSON output: {out_json}")
    return 0

if __name__=="__main__":
    sys.exit(main())
