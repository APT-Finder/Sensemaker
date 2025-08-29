import os
import json
import time
import traceback
from typing import Dict, Any
from dotenv import load_dotenv
from openai import OpenAI
from rag_query import query_rag

# 导入本地模型接口
#from judgement_llm.model import Qwen
from judgement_llm.prompt import PROMPTS

# 加载环境变量
load_dotenv()

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
            # 使用本地模型
            messages = [{"role": "user", "content": prompt}]
            response = self.model.generate_response(messages)
        else:
            # 使用OpenAI模型
            messages = [
                {"role": "user", "content": prompt}
            ]
            response = self.client.chat.completions.create(
                model=self.config.model_name,
                messages=messages,
                temperature=self.config.temperature
            )
            response = response.choices[0].message.content.strip()

        # 解析响应
        try:
            result = json.loads(response)
            return result
        except json.JSONDecodeError:
            return {
                "error": "响应不是有效的JSON格式",
                "raw_response": response
            }
        except Exception as e:
            return {
                "error": f"处理响应时发生错误: {str(e)}",
                "traceback": traceback.format_exc()
            }

    def _build_judgement_prompt(self, chain_data: Dict[str, Any]) -> str:
        """构建研判提示"""
        # 从PROMPTS中获取基础提示
        prompt = PROMPTS["judge_chains"].format(language=PROMPTS["DEFAULT_LANGUAGE"], inputtext=json.dumps(chain_data, ensure_ascii=False))
        return prompt

    def process_file(self, input_path: str, output_path: str):
        with open(input_path, 'r', encoding='utf-8') as f:
            input_data = json.load(f)

        output_dir = os.path.dirname(output_path)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)

        if os.path.exists(output_path):
            with open(output_path, 'r', encoding='utf-8') as f:
                results = json.load(f)
        else:
            results = {}

        for chain_name, chain_data in input_data.items():
            if chain_name in results:
                print(f"攻击链: {chain_name} 已存在，跳过")
                continue
            print(f"正在研判攻击链: {chain_name}")
            result = self.judge_chain(chain_data)
            results[chain_name] = result
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(results, f, ensure_ascii=False, indent=2)
            
            time.sleep(1)

        print(f"研判完成，结果已保存至: {output_path}")
        return results

# 本地大模型研判接口
def judge_with_local_model(chain_data: Dict[str, Any], model_path=None) -> Dict[str, Any]:
    """使用本地大模型进行攻击链研判"""
    config = AgentConfig(is_local=True, local_model_path=model_path)
    agent = AttackChainJudgementAgent(config)
    return agent.judge_chain(chain_data)

# OpenAI模型研判接口
def judge_with_openai(chain_data: Dict[str, Any], model_name="gpt-4.1", temperature=0.1) -> Dict[str, Any]:
    """使用OpenAI模型进行攻击链研判"""
    config = AgentConfig(model_name=model_name, temperature=temperature, is_local=False)
    agent = AttackChainJudgementAgent(config)
    return agent.judge_chain(chain_data)

def main():
    import argparse
    parser = argparse.ArgumentParser(description="攻击链研判智能体")
    parser.add_argument("--input", help="输入JSON文件路径", default="")
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

    # 处理文件
    agent.process_file(args.input, args.output)

if __name__ == "__main__":
    main()