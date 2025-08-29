from __future__ import annotations
from typing import Any


PROMPTS: dict[str, Any] = {}

PROMPTS["DEFAULT_LANGUAGE"] = "Chinese"
PROMPTS["DEFAULT_TUPLE_DELIMITER"] = "<|>"
PROMPTS["DEFAULT_RECORD_DELIMITER"] = "##"
PROMPTS["DEFAULT_COMPLETION_DELIMITER"] = "<|COMPLETE|>"
PROMPTS["DEFAULT_alias"] = "{{'Darkhotel':['DarkHotel', 'Tardigrade Spider', 'Luder', 'Karba', 'Tapaoux', 'Nemim', 'Dubnium', 'APT-C-06', 'SHADOW CRANE', 'T-APT-02', 'SIG25', 'G0012', 'Inexsmar', 'Fallout Team'],'APT32':['APT32', 'Ocean Lotus', 'APT-C-00', 'SeaLotus', 'SectorF01', 'CyberOne Security', 'CyberOne Technologies', 'Hành Tinh Company Limited', 'Planet and Diacauso', 'G0050', 'OceanLotus', '海莲花', 'Cobalt Kitty'],'FIN7':['FIN7', 'Anunak', 'Carbon Spider', 'JokerStash', 'Carberp', 'APT-C-11'],'APT28':['Sofacy', 'APT28', 'Sednit', 'Pawn Storm', 'Group 74', 'Tsar Team', 'Fancy Bear', 'Strontium', 'Swallowtail', 'SIG40', 'Grizzly Steppe', 'TG-4127', 'SNAKEMACKEREL', 'IRON TWILIGHT', 'Threat Group-4127', 'T-APT-12', 'TAG_0700', 'APT-C-20'],'lazarus':['Lazarus', 'Labyrinth Chollima', 'Group 77', 'Hastati', 'Bureau 121', 'Unit 121', 'Whois Hacking Team', 'NewRomanic Cyber Army Team', 'ZINC', 'Appleworm', 'Hidden Cobra', 'Nickel Academy', 'G0032', 'Operation DarkSeoul', 'Dark Seoul', 'Andariel', 'Bluenoroff', 'Operation Troy', 'Operation GhostSecret', 'Guardians of Peace', 'APT-C-26', 'Silent Chollima', 'G0138'],'APT-C-09':['Patchwork', 'Dropping Elephant', 'Chinastrats', 'Capricorn Organisation', 'APT-C-09', 'Viceroy Tiger', 'Mahaboo', 'Neon', 'Confucius', 'G0040', 'Hangover', '摩诃草', 'MONSOON', '白象', '丰收行动', 'Sarit'],'Bitter':['Bitter', 'APT-C-08', 'Manling Flower', 'Manlinghua', '蔓灵花'],'Equation':['Equation', 'Tilded Team', 'EQGRP', 'Housefly', 'Remsec', '方程式', 'Five Eyes'],'Sidewinder':['SideWinder', 'T-APT-04', '响尾蛇', 'APT-C-17'],'kimsuky':['Kimsuki', 'Velvet Chollima', 'Kimsuky', 'Thallium', 'CloudDragon', 'TA406', 'Proofpoint', 'G0094', 'Mystery Baby', 'Baby Coin', 'Smoke Screen', 'BabyShark', 'Cobra Venom'],'APT34':['Oilrig', 'Twisted Kitten', 'Crambus', 'ITG13', 'Chrysene', 'APT34', 'Helix Kitten', 'G0049', 'Greenbug', 'Shamoon 2', 'Cobalt Gypsy', 'PIPEFISH']}}"

PROMPTS["DEFAULT_USER_PROMPT"] = "n/a"

PROMPTS["group_chains_only_kb"] = """---Goal---
You are an attribution analyst. Given a SINGLE alert chain and a noisy knowledge base (KB) that mentions many APT orgs, compute a per-org kb_score ∈ [0,1] that reflects how well the KB evidence semantically matches THIS chain (not generic APT facts). The score must prioritize chain-specific  multi-step / NON-ADJACENT stage patterns, and distinctive evidence (proprietary tools/configs/infrastructure). Produce ONLY kb_score and its reasoning, and output all APT orgs by score.

Use {language} as the output language.

aliases: {apt_alias}

---Key Parsing of alert_chain---
- artifact_anchors: exploit/CVEs, payload types & keywords, malware/trojans/tools, config/strings
- chain_shape: whether there is a NON-ADJACENT stage combo and a multi-stage, time-phased progression

---KB Evidence Filtering (denoise → then score)---
1) Collect evidence ONLY for orgs present in alias and explicitly tied to the org. Include an item if ANY is true:
   - kb_item.orgs contains the org; OR
   - kb_item.type ∈ {{'threat_actor','campaign','attack_tactic','malware','infrastructure'}} AND the description/file explicitly mentions the org; OR
   - relationships has an edge to the org consistent with the item’s semantics
2) Drop generic, multi-org boilerplate (e.g., “phishing is common”) from strong-evidence lists
3) Mark “proprietary/unique” signals (tools/configs/certificates/URI templates/JA3/ASN combos) as high-priority

---Scoring (semantic, not rigid formula; produce kb_score ∈ [0,1], 3 decimals)---
For each candidate org, perform concise textual reasoning per dimension below, then provide a kb_score. Give one short sentence per dimension and a final holistic rationale.
A) Proprietary / Unique tooling (highest weight)
   - If KB links this org to a tool/family/config/protocol with exclusive or near-exclusive use AND it matches the alert_chain (names/modules/command semantics/config snippets/cert/JA3/URI templates), boost strongly; if the anchor is more typical of ANOTHER org, note a mild downward adjustment. If the anchor is more general and used by many organizations, lower the weight
B) Anchor fit 
   - Do not only observed ttp_anchors explicitly overlap the org’s known TTPs as evidence; a COMBINED, NON-ADJACENT anchor set (e.g., “CVE-2017-0199/HTA” + “browser 0-day pattern” + “late-stage RAT control”) counts as a stronger evidence.
C) Infrastructure semantics
   - Match patterns in domains/IP/ASN/cert/JA3/URI templates/fronting. Generic cloud hosting is weak; template-level matches are strong.
D) Chain-shape & operator behavior
   - Does the KB describe multi-stage, time-phased operations and evasive behaviors similar to the alert_chain?
E) Source credibility & recency (light modifier; NOT volume-based)
   - Do NOT use the sheer number of KB files for an org. The number of reports in the knowledge base varies from organization to organization.
   - Consider recency qualitatively: recent reports supporting the same TTP/tooling/infrastructure pattern slightly strengthen confidence.
   - Limit the total influence of this dimension to a small adjustment. Do not use it as a primary driver.
F) Conflict check
   - If a high-discriminative anchor aligns better with another org in the KB, state it and apply a small downward adjustment (do not outright discard).

Based on the above textual assessment, produce kb_score:
- ≥0.85: Strong match (multi-anchor, non-adjacent chain + proprietary/near-proprietary evidence + context fit + multi-source support)
- 0.70–0.84: Good match (multiple anchors or strong chain-shape; proprietary signals moderate or sources slightly weaker)
- 0.50–0.69: Fair (some anchors match but evidence is generic/conflicted/sources weak/context unclear)
- <0.50: Weak (mostly generic TTPs or misaligned with the org)

---Output (JSON only; one object per org, sorted desc by kb_score; include top rationale snippets; return all orgs)---
[
  {{
    "name": "ORG_NAME",
    "kb_score": 0.000,
    "rationale": {{
      "proprietary_unique": "...",
      "anchor_fit": "...",
      "infrastructure": "...",
      "chain_shape": "...",
      "sources": "publisher/date/KB-IDs ...",
      "conflict": "... (if any)"
    }},
    "anchor_matches": ["CVE-2017-0199/HTA","Firefox/Tor 0-day ROP strings","PowerShell MemoryStream+GzipStream","PlugX processManager Kill"],
    "kb_ids": ["full_name_1","full_name_2","..."]
  }}
]
"""
