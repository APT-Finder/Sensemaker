from __future__ import annotations
from typing import Any


PROMPTS: dict[str, Any] = {}

PROMPTS["DEFAULT_LANGUAGE"] = "Chinese"
PROMPTS["DEFAULT_TUPLE_DELIMITER"] = "<|>"
PROMPTS["DEFAULT_RECORD_DELIMITER"] = "##"
PROMPTS["DEFAULT_COMPLETION_DELIMITER"] = "<|COMPLETE|>"

PROMPTS["DEFAULT_ENTITY_TYPES"] = [
    "attack_technique", "report_name",
    "attack_tactic", "timestamp",
    "malware", "tool", "threat_actor", "intrusion_set", "event",
    "ip_address", "domain", "url", "file_hash", "email", "process", "command",
    "cve_id", "cpe", "service", "product",
    "kill_chain_phase", "campaign", "operation",
    "protocol", "port", "script", "task", "vulnerability", "rule signatures"
]


PROMPTS["DEFAULT_USER_PROMPT"] = "n/a"

PROMPTS["entity_extraction"] = """---Goal---
You are analyzing threat intelligence reports or alert logs or intelligence csvs related to Advanced Persistent Threats (APT). 
Given the following input text and a list of entity types, identify all entities of those types from the text and all relationships among the identified entities.

Use {language} as the output language.

---Steps---
1. Identify all entities. For each identified entity, extract the following information:
- entity_name: Name of the entity, use condensed or canonical names where appropriate. If English, capitalized the name.
- entity_type: one of the following types: [{entity_types}]
- entity_description: Comprehensive description of the entity's attributes and activities. Pay attention to the relationship between the entity and the report or APT organization.

Format each entity must strictly as ("entity"{tuple_delimiter}<entity_name>{tuple_delimiter}<entity_type>{tuple_delimiter}<entity_description>)

---Special Requirements---
-- For "report_name" entity: Treat the entire report_name as a single atomic entity. 
-- For list/dicts-type fields in the input_text, extract each item as a separate entity, and if the entity is redundant, condense it into a single or multiple representative phrases, canonical entities.
-- IOC normalization: When extracting IP, URL, or domain IOCs, normalize the representation (e.g., "8.8.8[.]8" → "8.8.8.8").

2. From the entities identified in step 1, identify all pairs of (source_entity, target_entity) that are clearly related to each other. In addition, for every entity as identified in step 1, must create a relationship to the entity which entity_type is "report_name". 
For each pair of related entities, extract the following information:
- source_entity: name of the source entity, as identified in step 1
- target_entity: name of the target entity, as identified in step 1
- relationship_description: summarize the explanation as to why you think the source entity and the target entity are related to each other, the relevance to the attack, the original key, and the parent key (if present).
- relationship_strength: a numeric score indicating strength of the relationship(must be 1-10)
- relationship_keywords: one or more high-level key words that summarize the overarching nature of the relationship, focusing on concepts or themes rather than specific details.

Format each relationship must strictly as ("relationship"{tuple_delimiter}<source_entity>{tuple_delimiter}<target_entity>{tuple_delimiter}<relationship_description>{tuple_delimiter}<relationship_keywords>{tuple_delimiter}<relationship_strength>)

---Special Requirements---
-- Pay more attention to the relationship between different entities as identified in step 1, rather than just the relationship between the entity which entity_type is "threat_actor" and each entity. If any entity does not have any relationship, establish a relationship between this entity and the entity which entity_type is "threat_actor".
-- For dictionary-type fields (key-value) in input text: when forming the relationship, the relationship_description should summarize the original key, its parent key (if present), their relevance to this attack, and the reason for creating this relationship.
-- For lists/dicts-type fields in input text: consider whether there is a logical connection between each entity. If a clear relationship exists, establish a relationship. If there is no direct connection between the elements, do not force a relationship.

3. Return output in {language} as a single list of all the entities and relationships identified in steps 1 and 2. Use {record_delimiter} as the list delimiter.

4. When finished, output {completion_delimiter}

######################
---Examples---
######################
{examples}

#############################
---Real Data---
######################
Entity_types: [{entity_types}]
---Text---:
{input_text}
######################
---Output Format---
Your output must strictly follow the formats below. Do not mix entity and relationship formats.
1. Each entity must start with ("entity"{tuple_delimiter} and include exactly three fields: entity_name, entity_type, entity_description, separated by {tuple_delimiter}.
2. Each relationship must start with ("relationship"{tuple_delimiter} and include exactly five fields: source_entity, target_entity, relationship_description, relationship_keywords, relationship_strength, separated by {tuple_delimiter}.
3. Never use the entity format for a relationship or vice versa. Before outputting, always check that each line matches the correct format.
4. Use {record_delimiter} as the separator between records.
-- Entity output format: ("entity"{tuple_delimiter}<entity_name>{tuple_delimiter}<entity_type>{tuple_delimiter}<entity_description>)
-- Relationship output format: ("relationship"{tuple_delimiter}<source_entity>{tuple_delimiter}<target_entity>{tuple_delimiter}<relationship_description>{tuple_delimiter}<relationship_keywords>{tuple_delimiter}<relationship_strength>)
/no_think"""

PROMPTS["entity_extraction_examples"] = [
    """Example 1:

Entity_types: [report_name, threat_actor, protocol, product, port, attack_technique]
Text:
```
{{"report_name":"APT32攻击西门子PLC事件分析报告",
"report_content":"APT32利用端口445进行横向扫描（Discovery，T1018），随后通过RPC DCOM漏洞（T1190）远程执行，最终修改西门子PLC逻辑。"
}}```

Output:
("entity"{tuple_delimiter}"APT32攻击西门子PLC事件分析报告"{tuple_delimiter}"report_name"{tuple_delimiter}"关于APT32利用横向扫描与RPC DCOM漏洞攻击西门子PLC的威胁情报报告。"){record_delimiter}
("entity"{tuple_delimiter}"APT32"{tuple_delimiter}"threat_actor"{tuple_delimiter}"APT32是知名APT组织，主导本次工业控制系统攻击。"){record_delimiter}
("entity"{tuple_delimiter}"445"{tuple_delimiter}"port"{tuple_delimiter}"SMB协议默认端口，APT32通过该端口横向扫描目标主机。"){record_delimiter}
("entity"{tuple_delimiter}"SMB"{tuple_delimiter}"protocol"{tuple_delimiter}"445端口承载的协议，是APT32横向移动的基础。"){record_delimiter}
("entity"{tuple_delimiter}"横向扫描"{tuple_delimiter}"attack_technique"{tuple_delimiter}"攻击链初期，用于发现目标主机的行为。"){record_delimiter}
("entity"{tuple_delimiter}"T1018"{tuple_delimiter}"attack_technique"{tuple_delimiter}"MITRE ATT&CK编号，代表横向扫描（Remote System Discovery）技术。"){record_delimiter}
("entity"{tuple_delimiter}"RPC DCOM漏洞"{tuple_delimiter}"attack_technique"{tuple_delimiter}"APT32利用该漏洞实现远程执行，属于攻击链后期。"){record_delimiter}
("entity"{tuple_delimiter}"T1190"{tuple_delimiter}"attack_technique"{tuple_delimiter}"MITRE ATT&CK编号，代表远程服务漏洞利用（Remote Service Exploit）技术。"){record_delimiter}
("entity"{tuple_delimiter}"西门子PLC"{tuple_delimiter}"product"{tuple_delimiter}"工业控制系统中的核心设备，是APT32本次攻击的目标。"){record_delimiter}
("relationship"{tuple_delimiter}"APT32攻击西门子PLC事件分析报告"{tuple_delimiter}"APT32"{tuple_delimiter}"报告确定APT32为威胁主角，组织本次攻击活动。"{tuple_delimiter}"威胁组织,报告归属"{tuple_delimiter}10){record_delimiter}
("relationship"{tuple_delimiter}"APT32攻击西门子PLC事件分析报告"{tuple_delimiter}"445"{tuple_delimiter}"报告细节描述APT32利用445端口横向扫描目标主机。"{tuple_delimiter}"端口利用,技术细节"{tuple_delimiter}9){record_delimiter}
("relationship"{tuple_delimiter}"APT32攻击西门子PLC事件分析报告"{tuple_delimiter}"SMB"{tuple_delimiter}"报告说明APT32横向利用SMB协议进行网络扩展。"{tuple_delimiter}"协议利用,横向移动"{tuple_delimiter}8){record_delimiter}
("relationship"{tuple_delimiter}"APT32攻击西门子PLC事件分析报告"{tuple_delimiter}"横向扫描"{tuple_delimiter}"APT32攻击链起始阶段，采用横向扫描技术识别目标主机。"{tuple_delimiter}"横向扫描,攻击链"{tuple_delimiter}10){record_delimiter}
("relationship"{tuple_delimiter}"APT32攻击西门子PLC事件分析报告"{tuple_delimiter}"T1018"{tuple_delimiter}"报告引用T1018编号标准化横向扫描技术。"{tuple_delimiter}"技术标准,ATT&CK"{tuple_delimiter}8){record_delimiter}
("relationship"{tuple_delimiter}"APT32攻击西门子PLC事件分析报告"{tuple_delimiter}"RPC DCOM漏洞"{tuple_delimiter}"报告指出APT32通过RPC DCOM漏洞远程执行，推进攻击链。"{tuple_delimiter}"漏洞利用,远程攻击"{tuple_delimiter}10){record_delimiter}
("relationship"{tuple_delimiter}"APT32攻击西门子PLC事件分析报告"{tuple_delimiter}"T1190"{tuple_delimiter}"报告引用T1190编号标准化漏洞利用技术。"{tuple_delimiter}"技术标准,ATT&CK"{tuple_delimiter}8){record_delimiter}
("relationship"{tuple_delimiter}"APT32攻击西门子PLC事件分析报告"{tuple_delimiter}"西门子PLC"{tuple_delimiter}"APT32攻击目标为西门子PLC，成功篡改其逻辑。"{tuple_delimiter}"攻击目标,工控设备"{tuple_delimiter}10){record_delimiter}
("relationship"{tuple_delimiter}"横向扫描"{tuple_delimiter}"T1018"{tuple_delimiter}"横向扫描技术对应MITRE ATT&CK编号T1018。"{tuple_delimiter}"编号对应,ATT&CK"{tuple_delimiter}9){record_delimiter}
("relationship"{tuple_delimiter}"RPC DCOM漏洞"{tuple_delimiter}"T1190"{tuple_delimiter}"RPC DCOM漏洞对应MITRE ATT&CK编号T1190。"{tuple_delimiter}"编号对应,ATT&CK"{tuple_delimiter}9){record_delimiter}
("relationship"{tuple_delimiter}"T1018"{tuple_delimiter}"T1190"{tuple_delimiter}"T1018（横向扫描）在攻击链中先于T1190（漏洞利用），APT32先用T1018发现目标，后用T1190突破主机，逻辑为攻击递进。"{tuple_delimiter}"攻击链,技战术递进"{tuple_delimiter}9){record_delimiter}
("relationship"{tuple_delimiter}"APT32"{tuple_delimiter}"横向扫描"{tuple_delimiter}"APT32攻击初期采用横向扫描寻找目标主机。"{tuple_delimiter}"横向扫描,发现阶段"{tuple_delimiter}8){record_delimiter}
("relationship"{tuple_delimiter}"APT32"{tuple_delimiter}"RPC DCOM漏洞"{tuple_delimiter}"APT32利用RPC DCOM漏洞远程执行代码，强化攻击渗透。"{tuple_delimiter}"漏洞利用,远程攻击"{tuple_delimiter}8){record_delimiter}
("relationship"{tuple_delimiter}"445"{tuple_delimiter}"SMB"{tuple_delimiter}"445端口为SMB协议的标准端口，APT32横向扫描依赖此绑定。"{tuple_delimiter}"端口协议绑定,横向移动"{tuple_delimiter}8){record_delimiter}
("relationship"{tuple_delimiter}"RPC DCOM漏洞"{tuple_delimiter}"西门子PLC"{tuple_delimiter}"APT32通过RPC DCOM漏洞最终控制并修改西门子PLC，导致工业系统威胁。"{tuple_delimiter}"工控攻击,远控"{tuple_delimiter}7){record_delimiter}
#############################"""
]


PROMPTS[
    "summarize_entity_descriptions"
] = """You are a helpful assistant responsible for generating a comprehensive summary of the data provided below.
Given one or two entities, and a list of descriptions, all related to the same entity or group of entities.
Please concatenate all of these into a single, comprehensive description. Make sure to include information collected from all the descriptions.
If the provided descriptions are contradictory, please resolve the contradictions and provide a single, coherent summary.
Make sure it is written in third person, and include the entity names so we have the full context.
Use {language} as output language.

#######
---Data---
Entities: {entity_name}
Description List: {description_list}
#######
Output:
/no_think
"""

PROMPTS["entity_continue_extraction"] = """
MANY entities and relationships were missed in the last extraction. Please find only the missing entities and relationships from previous text. If any entity does not have any relationship, establish a relationship between this entity and the entity which entity_type is "threat_actor".

---Remember Steps---
1. Identify all entities. For each identified entity, extract the following information:
- entity_name: Name of the entity, use condensed or canonical names where appropriate. If English, capitalized the name.
- entity_type: one of the following types: [{entity_types}]
- entity_description: Comprehensive description of the entity's attributes and activities. Pay attention to the relationship between the entity and the report or APT organization.

Format each entity must strictly as ("entity"{tuple_delimiter}<entity_name>{tuple_delimiter}<entity_type>{tuple_delimiter}<entity_description>)

---Special Requirements---
-- For "report_name" entity: Treat the entire report_name as a single atomic entity. 
-- For list/dicts-type fields in the input_text, extract each item as a separate entity, and if the entity is redundant, condense it into a single or multiple representative phrases, canonical entities.
-- IOC normalization: When extracting IP, URL, or domain IOCs, normalize the representation (e.g., "8.8.8[.]8" → "8.8.8.8").

2. From the entities identified in step 1, identify all pairs of (source_entity, target_entity) that are clearly related to each other.  In addition, for every entity as identified in step 1, must create a relationship to the entity which entity_type is "report_name". 
For each pair of related entities, extract the following information:
- source_entity: name of the source entity, as identified in step 1
- target_entity: name of the target entity, as identified in step 1
- relationship_description: summarize the explanation as to why you think the source entity and the target entity are related to each other, the relevance to the attack, the original key, and the parent key (if present).
- relationship_strength: a numeric score indicating strength of the relationship(must be 1-10)
- relationship_keywords: one or more high-level key words that summarize the overarching nature of the relationship, focusing on concepts or themes rather than specific details.

Format each relationship must strictly as ("relationship"{tuple_delimiter}<source_entity>{tuple_delimiter}<target_entity>{tuple_delimiter}<relationship_description>{tuple_delimiter}<relationship_keywords>{tuple_delimiter}<relationship_strength>)

---Special Requirements---
-- Pay more attention to the relationship between different entities as identified in step 1, rather than just the relationship between the entity which entity_type is "threat_actor" and each entity. If any entity does not have any relationship, establish a relationship between this entity and the entity which entity_type is "threat_actor".
-- For dictionary-type fields (key-value) in input text: when forming the relationship, the relationship_description should summarize the original key, its parent key (if present), their relevance to this attack, and the reason for creating this relationship.
-- For lists/dicts-type fields in input text: consider whether there is a logical connection between each entity. If a clear relationship exists, establish a relationship. If there is no direct connection between the elements, do not force a relationship.

3. Return output in {language} as a single list of all the entities and relationships identified in steps 1 and 2. Use {record_delimiter} as the list delimiter.

4. When finished, output {completion_delimiter}

---Output Format Example---
Your output must strictly follow the formats below. Do not mix entity and relationship formats.
1. Each entity must start with ("entity"{tuple_delimiter} and include exactly three fields: entity_name, entity_type, entity_description, separated by {tuple_delimiter}.
2. Each relationship must start with ("relationship"{tuple_delimiter} and include exactly five fields: source_entity, target_entity, relationship_description, relationship_keywords, relationship_strength, separated by {tuple_delimiter}.
3. Never use the entity format for a relationship or vice versa. Before outputting, always check that each line matches the correct format.
4. Use {record_delimiter} as the separator between records.
-- Entity output format: ("entity"{tuple_delimiter}<entity_name>{tuple_delimiter}<entity_type>{tuple_delimiter}<entity_description>)
-- Relationship output format: ("relationship"{tuple_delimiter}<source_entity>{tuple_delimiter}<target_entity>{tuple_delimiter}<relationship_description>{tuple_delimiter}<relationship_keywords>{tuple_delimiter}<relationship_strength>)

Do not include entities and relations that have been previously extracted. Any entity or relationship that does not explicitly occur in the provided text or previous conversation must be strictly ignored.\n /no_think
""".strip()

PROMPTS["entity_if_loop_extraction"] = """
---Goal---'

It appears some entities may have still been missed.

---Output---

Answer ONLY by `YES` OR `NO` if there are still entities that need to be added. /no_think
""".strip()

PROMPTS["fail_response"] = (
    "Sorry, I'm not able to provide an answer to that question.[no-context] /no_think"
)

PROMPTS["rag_response"] = """---Role---

You are a helpful assistant responding to user query about Knowledge Graph and Document Chunks provided in JSON format below.


---Goal---

Generate a concise response based on Knowledge Base and follow Response Rules, considering both the conversation history and the current query. Summarize all information in the provided Knowledge Base, and incorporating general knowledge relevant to the Knowledge Base. Do not include information not provided by Knowledge Base.

When handling relationships with timestamps:
1. Do not consider "created_at" timestamp of each relationship.
2. When encountering conflicting relationships, consider both the semantic content and the timestamp associated with that content.
3. Do not automatically prioritize the most recently created relationship—use context for judgment.

---Conversation History---
{history}

---Knowledge Graph and Document Chunks---
{context_data}

---Response Rules---

- Target format and length: {response_type}
- Use markdown formatting with appropriate section headings
- Please respond in the same language as the user's question.
- Ensure the response maintains continuity with the conversation history.
- List up to 5 most important reference sources at the end under "References" section. Clearly indicating whether each source is from Knowledge Graph (KG) or Document Chunks (DC), and include the file path if available, in the following format: [KG/DC] file_path
- If you don't know the answer, just say so.
- Do not make anything up. Do not include information not provided by the Knowledge Base.
- Additional user prompt: {user_prompt}

Response: /no_think"""

PROMPTS["keywords_extraction"] = """---Role---
You are a cybersecurity assistant. Your task is to extract both high-level and low-level keywords relevant to threat intelligence, APT activities, and security analysis from the user's query and conversation history.

---Goal---

Given the query and conversation history, list both high-level and low-level keywords. 
  -high-level keywords focus on overarching concepts, themes, attack stages, operation types, or techniques. 
  -low-level keywords focus on specific entities, details, or concrete terms, including but not limited to: TTP IDs, ATT&CK technique names, IOC values, Threat actor, APT group names, Tools, malware, exploits, CVE numbers, Organization/product names, regions, victim sectors, Unique report IDs or filenames

---Instructions---

- Consider both the current query and relevant conversation history when extracting keywords
- Output the keywords in JSON format, it will be parsed by a JSON parser, do not add any extra content in output
- The JSON should have two keys:
  - "high_level_keywords" for overarching concepts or themes, [...]
  - "low_level_keywords" for specific entities or details, [...]
- Each keyword should appear only once per list, even if repeated in input.

######################
---Examples---
######################
{examples}

######################
---Real Data---
######################
Conversation History:
{history}

Current Query: {query}
######################
The `Output` should be in JSON format, with no other text before and after the JSON. Use the same language as `Current Query`.

Output: /no_think
"""

PROMPTS["keywords_extraction_examples"] = [
    """Example 1:

Query: "APT29如何利用计划任务横向移动？"

Output:
{
  "high_level_keywords": ["APT攻击", "计划任务", "横向移动", "APT攻击链"],
  "low_level_keywords": ["APT29", "T1053.005", "T1021.004", "PsExec", "Mimikatz"]
}
""",
"""Example 2:

Query: "APT-Q-27使用T1053.005和多个C2服务器（例如203.99.164[.]199和8.8.8[.]8）瞄准东南亚的博彩业"

Output:
{
  "high_level_keywords": ["APT攻击", "博彩业", "东南亚", "C2基础设施", "持久性"],
  "low_level_keywords": ["APT-Q-27", "T1053.005", "203.99.164.199", "8.8.8.8", "计划任务"]
}
""",
]

PROMPTS["naive_rag_response"] = """---Role---

You are a helpful assistant responding to user query about Document Chunks provided provided in JSON format below.

---Goal---

Generate a concise response based on Document Chunks and follow Response Rules, considering both the conversation history and the current query. Summarize all information in the provided Document Chunks, and incorporating general knowledge relevant to the Document Chunks. Do not include information not provided by Document Chunks.

When handling content with timestamps:
1. Each relationship has a "created_at" timestamp, which indicates when the knowledge was acquired. Do not consider this time.
2. When encountering conflicting relationships, consider both the semantic content and the timestamp associated with that content.
3. Do not automatically prioritize the most recently created relationship—use context for judgment.

---Conversation History---
{history}

---Document Chunks(DC)---
{content_data}

---Response Rules---

- Target format and length: {response_type}
- Use markdown formatting with appropriate section headings
- Please respond in the same language as the user's question.
- Ensure the response maintains continuity with the conversation history.
- List up to 5 most important reference sources at the end under "References" section. Clearly indicating each source from Document Chunks(DC), and include the file path if available, in the following format: [DC] file_path
- If you don't know the answer, just say so.
- Do not include information not provided by the Document Chunks.
- Addtional user prompt: {user_prompt}

Response: /no_think"""