import os
import json
import time
import traceback
from typing import Dict, Any
from dotenv import load_dotenv
from openai import OpenAI

from prompt import PROMPTS

load_dotenv()

def _load_json_input(s: str) -> Dict[str, float]:
    if os.path.exists(s) and os.path.isfile(s):
        with open(s, 'r', encoding='utf-8') as f:
            return json.load(f)
    return json.loads(s)

def load_retrieval_file(file_path: str) -> Dict[str, Dict[str, float]]:
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    result = {}
    for item in data:
        for chain_id, chain_data_str in item.items():
            try:
                try:
                    chain_data = json.loads(chain_data_str)
                except json.JSONDecodeError as e:
                    if 'Extra data' in str(e):
                        print(f"Error: 'Extra data' found in chain {chain_id}: {e}")
                        try:
                            decoder = json.JSONDecoder()
                            chain_data, _ = decoder.raw_decode(chain_data_str)
                            print(f"Successfully parsed with raw_decode for chain {chain_id}")
                        except json.JSONDecodeError:
                            try:
                                from collections import deque
                                bracket_stack = deque()
                                last_valid_pos = 0
                                for i, char in enumerate(chain_data_str):
                                    if char in '{[':
                                        bracket_stack.append(char)
                                    elif char in '}]':
                                        if bracket_stack:
                                            opening = bracket_stack.pop()
                                            # 检查括号是否匹配
                                            if (opening == '{' and char == '}') or (opening == '[' and char == ']'):
                                                if not bracket_stack:
                                                    last_valid_pos = i + 1
                                    if not bracket_stack and i > 0:
                                        break

                                if last_valid_pos > 0:
                                    print(f"Found valid JSON up to position {last_valid_pos}")
                                    truncated_data = chain_data_str[:last_valid_pos]
                                    chain_data = json.loads(truncated_data)
                                    print(f"Successfully parsed truncated JSON for chain {chain_id}")
                                else:
                                    raise e
                            except json.JSONDecodeError:
                                print(f"Failed to parse even after advanced truncation for chain {chain_id}")
                                continue
                    else:
                        raise e

                if isinstance(chain_data, list):
                    org_scores = {}
                    count = 0
                    for entry in chain_data:
                        if count > 0:  #取top3
                            break
                        if isinstance(entry, dict) and 'name' in entry and 'kb_score' in entry:
                            org_scores[entry['name']] = entry
                            del org_scores[entry['name']]['kb_score']
                            count += 1
                        else:
                            print(f"Warning: Invalid entry format in chain {chain_id}")
                elif isinstance(chain_data, dict):
                    if 'top5' in chain_data and isinstance(chain_data['top5'], list):
                        org_scores = {}
                        for entry in chain_data['top5']:
                            if isinstance(entry, dict) and 'name' in entry and 'kb_score' in entry:
                                org_scores[entry['name']] = entry['kb_score']
                            else:
                                print(f"Warning: Invalid entry in top5 for chain {chain_id}")
                    elif all(isinstance(v, (int, float)) for v in chain_data.values()):
                        org_scores = chain_data
                    else:
                        print(f"Warning: Unexpected dict format for chain {chain_id}")
                        continue
                else:
                    print(f"Warning: Unexpected format for chain {chain_id}: {type(chain_data)}")
                    continue

                if org_scores:
                    result[chain_id] = org_scores
                else:
                    print(f"Warning: No valid scores found for chain {chain_id}")
            except (json.JSONDecodeError, KeyError, TypeError) as e:
                print(f"Warning: Error processing chain {chain_id}: {e}")
                if isinstance(e, json.JSONDecodeError):
                    print(f"  JSON error at position {e.pos}: {e.msg}")
                    print(f"  Problematic text: {chain_data_str[e.pos-20:e.pos+20] if len(chain_data_str) > e.pos+20 else chain_data_str}")
                continue
    return result

def load_tool_file(file_path: str) -> Dict[str, Dict[str, float]]:
    """Load tool scores from apt_results format."""
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    result = {}
    
    if isinstance(data, list):
        for item in data:
            for chain_id, chain_data_str in item.items():
                try:
                    chain_data = json.loads(chain_data_str)
                    if 'top5' in chain_data:
                        tool_scores = {}
                        for entry in chain_data['top5']:
                            if 'name' in entry and 'tool_score' in entry:
                                tool_scores[entry['name']] = entry['tool_score']
                        result[chain_id] = tool_scores
                    else:
                        print(f"Warning: No 'top5' found for chain {chain_id}")
                except json.JSONDecodeError as e:
                    print(f"Warning: JSON decode error for chain {chain_id}: {str(e)}")
                except (KeyError, TypeError) as e:
                    print(f"Warning: Error processing chain {chain_id}: {str(e)}")
    elif isinstance(data, dict):
        for chain_id, chain_data in data.items():
            try:
                if 'total_scores' in chain_data:
                    result[chain_id] = chain_data['total_scores']
                elif 'top5' in chain_data:
                    tool_scores = {}
                    for entry in chain_data['top5']:
                        if 'name' in entry and 'tool_score' in entry:
                            tool_scores[entry['name']] = entry['tool_score']
                    result[chain_id] = tool_scores
                else:
                    print(f"Warning: No 'total_scores' or 'top5' found for chain {chain_id}")
            except (KeyError, TypeError) as e:
                print(f"Warning: Error processing chain {chain_id}: {str(e)}")
    else:
        print(f"Warning: Unexpected data format in tool file: {type(data)}")
    
    return result


class AgentConfig:
    def __init__(self, 
                 model_name="gpt-4.1", 
                 temperature=0.1, 
                 is_local=False, 
                 local_model_path=None):
        self.model_name = model_name
        self.temperature = temperature
        self.is_local = is_local
        self.local_model_path = local_model_path
        self.api_key = os.getenv("OPENAI_API_KEY")

class AttackChainJudgementAgent:
    def __init__(self, config: AgentConfig):
        self.config = config
        
        if config.is_local:
            # 初始化本地模型
            # self.model = Qwen()
            print("no local model")
        else:
            # 初始化OpenAI客户端
            self.client = OpenAI(api_key=config.api_key)
            if not self.client.api_key:
                raise ValueError("未找到OPENAI_API_KEY，请检查.env文件")

    def judge_chain(self, chain_data: Dict[str, Any]) -> Dict[str, Any]:
        """研判单个攻击链"""
        prompt = self._build_judgement_prompt(chain_data)
        
        if self.config.is_local:
            messages = [{"role": "user", "content": prompt}]
            response = self.model.generate_response(messages)
        else:
            messages = [
                {"role": "user", "content": prompt}
            ]
            response = self.client.chat.completions.create(
                model=self.config.model_name,
                messages=messages,
                temperature=self.config.temperature
            )
            response = response.choices[0].message.content.strip()

        try:
            result = response
            return result
        except json.JSONDecodeError:
            return {
                "error": "响应不是有效的JSON格式",
                "raw_response": response
            }
        except Exception as e:
            return {
                "error": f"处理响应时发生错误: {str(e)}",
                "traceback": traceback.format_exc(),
                "raw_response": response
            }

    def _build_judgement_prompt(self, chain_data: Dict[str, Any]) -> str:
        prompt = PROMPTS["explain_chains"].format(language=PROMPTS["DEFAULT_LANGUAGE"], fusion_output=json.dumps(chain_data['fusion_agent'], ensure_ascii=False), assoc_agent_output=json.dumps(chain_data['assoc_agent'], ensure_ascii=False), judge_agent_output=json.dumps(chain_data['judge_agent'], ensure_ascii=False), attr_agent_output=json.dumps(chain_data['attr_agent'], ensure_ascii=False))
        return prompt

    def process_file(self, fusion_file, assoc_agent_file, judge_agent_file, attr_agent_file, output_path: str):
        with open(fusion_file, 'r', encoding='utf-8') as f:
            fusion_data = json.load(f)

        with open(assoc_agent_file, 'r', encoding='utf-8') as f:
            assoc_agent_data = json.load(f)

        with open(judge_agent_file, 'r', encoding='utf-8') as f:
            judge_agent_data = json.load(f)

        attr_agent_data = load_retrieval_file(attr_agent_file)

        output_dir = os.path.dirname(output_path)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)

        if os.path.exists(output_path):
            with open(output_path, 'r', encoding='utf-8') as f:
                results = json.load(f)
        else:
            results = {}

        for chain_name, chain_data in assoc_agent_data.items():
            if chain_name in results:
                print(f"攻击链: {chain_name} 已存在，跳过")
                continue
            print(f"正在研判攻击链: {chain_name}")
            try:
                llm_chain_data = {}
                llm_chain_data['alerts_info'] = {"告警链信息和特征":chain_data['alerts_info']}

                llm_chain_data['assoc_agent'] = {}
                llm_chain_data['assoc_agent']["此攻击链关联的原因"] = chain_data['此攻击链关联的原因']
                llm_chain_data['assoc_agent']["此攻击链的关键事件和行为"] = chain_data['此攻击链的关键事件和行为']

                llm_chain_data['judge_agent'] = judge_agent_data[chain_name]
                del llm_chain_data['judge_agent']['level']
                del llm_chain_data['judge_agent']['risk_score']
                del llm_chain_data['judge_agent']['confidence']

                llm_chain_data['attr_agent'] = attr_agent_data[chain_name]
                llm_chain_data['fusion_agent'] = {}
                llm_chain_data['fusion_agent']['威胁程度'] = fusion_data['preds'][chain_name]['severity_label']
                llm_chain_data['fusion_agent']['威胁程度概率'] = fusion_data['preds'][chain_name]['severity_prob']

                llm_chain_data['fusion_agent']['是否是APT攻击'] = fusion_data['preds'][chain_name]['is_apt']
                llm_chain_data['fusion_agent']['APT攻击概率'] = fusion_data['preds'][chain_name]['apt_prob']
                llm_chain_data['fusion_agent']['APT组织TOP3'] = fusion_data['preds'][chain_name]['per_org_prob']
            except Exception as e:
                error_msg = f"处理攻击链 {chain_name} 时发生错误: {str(e)}"
                print(error_msg)
                results[chain_name] = {'error': error_msg, 'traceback': traceback.format_exc()}
                with open(output_path, 'w', encoding='utf-8') as f:
                    json.dump(results, f, ensure_ascii=False, indent=2)
                continue

            result = self.judge_chain(llm_chain_data)
            results[chain_name] = result
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(results, f, ensure_ascii=False, indent=2)
            
            time.sleep(1)

        print(f"研判完成，结果已保存至: {output_path}")
        return results

# 本地大模型研判接口
def judge_with_local_model(chain_data: Dict[str, Any], model_path=None) -> Dict[str, Any]:
    config = AgentConfig(is_local=True, local_model_path=model_path)
    agent = AttackChainJudgementAgent(config)
    return agent.judge_chain(chain_data)

# OpenAI模型研判接口
def judge_with_openai(chain_data: Dict[str, Any], model_name="gpt-4.1", temperature=0.1) -> Dict[str, Any]:
    config = AgentConfig(model_name=model_name, temperature=temperature, is_local=False)
    agent = AttackChainJudgementAgent(config)
    return agent.judge_chain(chain_data)

def main():
    import argparse
    parser = argparse.ArgumentParser(description="")
    parser.add_argument("--output", help="输出JSON文件路径", default="")
    parser.add_argument("--local", action="store_true", help="是否使用本地大模型")
    parser.add_argument("--model_name", default="gpt-4.1", help="OpenAI模型名称")
    parser.add_argument("--temperature", type=float, default=0.7, help="模型温度参数")
    args = parser.parse_args()

    # 创建配置
    config = AgentConfig(
        model_name=args.model_name,
        temperature=args.temperature,
        is_local=args.local
    )

    # 初始化智能体
    agent = AttackChainJudgementAgent(config)

    fusion_file = "file_path"
    assoc_agent_file = "file_path"
    judge_agent_file = "file_path"  
    attr_agent_file = "file_path"

    # 处理文件
    agent.process_file(fusion_file, assoc_agent_file, judge_agent_file, attr_agent_file, args.output)

if __name__ == "__main__":
    main()