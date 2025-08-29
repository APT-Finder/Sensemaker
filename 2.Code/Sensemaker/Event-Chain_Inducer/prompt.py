from __future__ import annotations
from typing import Any


PROMPTS: dict[str, Any] = {}

PROMPTS["DEFAULT_LANGUAGE"] = "Chinese"
PROMPTS["DEFAULT_TUPLE_DELIMITER"] = "<|>"
PROMPTS["DEFAULT_RECORD_DELIMITER"] = "##"
PROMPTS["DEFAULT_COMPLETION_DELIMITER"] = "<|COMPLETE|>"

PROMPTS["DEFAULT_USER_PROMPT"] = "n/a"


PROMPTS["correlate_chains"] = """---Goal---
As a cybersecurity threat analysis expert, correlate alerts into one or more causal attack chains with a focus on TTP-centric reasoning. Core requirements:

1.TTP-centric reasoning:
-Use each alert's ttps and the corresponding tactics as the main thread to infer causal attack chains.
-Allow missing steps and incomplete alert coverage; chains may include jumps or omitted phases if overall TTP sequence and time order are plausible.

2.Auxiliary TTP fallback:
-If the primary TTP (ttps) of an alert cannot logically connect with the chain, consider using sec_ttps and sec_tactics_ttps to supplement the reasoning. If a logical connection is established via auxiliary TTPs, note this explicitly in the association reason.

3.Semantic analysis:
-Incorporate TTP descriptions (ttps_description, sec_ttps_description) and alert features (alert_features) to fully understand the behavior behind each step and strengthen logical continuity.
-Both TTP ID sequence and behavioral semantics are considered in chain inference.

4.Chain summary:
-After association, generate a concise summary (≤100 words) for each chain, capturing key stages, major behavioral features, and overall storyline, to facilitate human review.
-The summary should describe the attack story as a complete event, mentioning key behaviors, major features, and phase transitions.

5.Supplementary rules:
-If no plausible chain can be formed, return an empty object.
-If multiple distinct chains are inferred, put the json output of each chain into a list.
-Do not invent TTPs or behaviors; maintain all original IOC, IP, payload, and context as is.

---Steps---

1.Temporal-TTP reasoning:
-Map alerts onto the MITRE ATT&CK framework using both primary and auxiliary TTPs.
-Identify chains primarily by TTP progression (TA0043→TA0042→TA0001→...→TA0011→TA0010→TA0040) and time order.
-If main TTP linkage is not logical, attempt association via auxiliary TTPs and semantic context.
-Allow chain formation even when intermediate steps are missing, as long as the overall narrative remains plausible.

2.Stealth/APT-specific handling:
-Permit non-adjacent TTP links for long campaigns; missing alerts are acceptable.
-Consider time gaps up to 360 days for advanced persistent threats (APTs).

3.Chain formation & uncertainty flags:
-Create chains based on strong evidence (TTP progression, time continuity, infrastructure overlap, or semantic connection).
-Mark weak/uncertain links with:
  --NON_CASUAL_RELATIONSHIP: When causality is unclear
  --POTENTIAL_GAP: For time intervals >30 days
  --MISSING_STEP: When intermediate TTPs are absent
-Prioritize longer attack chains where logically possible; the goal is to maximize alert inclusion per chain while preserving TTP and semantic validity.

4.Structured output generation:
Each attack chain must include:
-"alert_chain": A list of sid for all alerts in the chain (sorted by time/TTP logic).
-"ttps_chain": A list of ttps for all alerts involved, the order needs to correspond to the list of alerts.
-"tas_chain": A list of the corresponding tactics of ttps for all alerts involved, the order needs to correspond to the list of alerts.
-"confidence_level": Confidence in the association of the entire attack chain (High/Medium/Low).
-"association_reasons":≤50 words, justifying why the alerts are linked, emphasizing TTP progression, time, auxiliary TTP, or semantic support.
-"summary": ≤100 words, capturing the key events and behaviors of the attack chain, should describe the complete attack narrative including major behaviors and transitions between phases.

5.Validation:
-Output must be strictly valid JSON.
-If there is only one alarm in the attack chain, please ignore it.
-Do not generate any content outside the strict output structure.


#############################
Input_Text:
{inputtext}
######################
Use {language} as the output language.
Please strictly follow the following json format output:
{{
  "alert_chain": ["sid1", "sid2", "sid3"],
  "ttps_chain": ["T1190", "T1190", "T1190"],
  "tas_chain": ["TA0043", "TA0042", "TA0001"],
  "confidence_level": "High/Medium/Low",
  "association_reasons": "association_reasons",
  "summary": "the key events and behaviors of the attack chain"
}}"""