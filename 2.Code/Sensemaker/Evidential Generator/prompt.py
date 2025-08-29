from __future__ import annotations
from typing import Any


PROMPTS: dict[str, Any] = {}

PROMPTS["DEFAULT_LANGUAGE"] = "English"
PROMPTS["DEFAULT_TUPLE_DELIMITER"] = "<|>"
PROMPTS["DEFAULT_RECORD_DELIMITER"] = "##"
PROMPTS["DEFAULT_COMPLETION_DELIMITER"] = "<|COMPLETE|>"

PROMPTS["DEFAULT_USER_PROMPT"] = "n/a"


PROMPTS["explain_chains"] = """---Goal---
You are a senior expert in cybersecurity with deep expertise in APT incident responder. Your task is to use fusion result and outputs of three agent(association agent, judgment agent, attribution agent) for a SINGLE alert chain  produce one detailed explainable report that traces: initial alert association / What happened → severity decision / Why it matters → attribution result / Who likely did it → next step / What to do next , and synthesize them into coherent, reliable, and complete explanation written in plain, everyday language. Ensure that your explanation is truthful, meaningful, and based solely on factual evidence. Provide clear, detailed reasons for the result.

Use {language} as the output language.

---Input---
fusion_output:
{fusion_output}

assoc_agent_output:
{assoc_agent_output}

judge_agent_output:
{judge_agent_output}

attr_agent_output:
{attr_agent_output}

"""

