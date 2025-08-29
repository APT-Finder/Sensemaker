import json
import os
import re
from typing import List, Dict, Any, Optional
from tools import AttackChainTools

class ChatGPTAgent:
    def __init__(self):
        self.tools = AttackChainTools()
        self.registered_tools = self._register_tools()
    
    def _register_tools(self) -> List[Dict[str, Any]]:
        tools = [
            {
                "name": "process_alert",
                "description": "处理告警数据，提取关键信息",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "alert_data": {
                            "type": "string",
                            "description": "告警数据，JSON格式"
                        }
                    },
                    "required": ["alert_data"]
                }
            },
            {
                "name": "mining_attack_chain",
                "description": "挖掘攻击链路",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "alert_data": {
                            "type": "string",
                            "description": "告警数据，JSON格式"
                        },
                        "start_time": {
                            "type": "string",
                            "description": "开始时间"
                        },
                        "end_time": {
                            "type": "string",
                            "description": "结束时间"
                        }
                    },
                    "required": ["alert_data", "start_time", "end_time"]
                }
            },
            {
                "name": "analyze_chain",
                "description": "分析攻击链路",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "chain_data": {
                            "type": "string",
                            "description": "攻击链路数据，JSON格式"
                        }
                    },
                    "required": ["chain_data"]
                }
            },
            {
                "name": "run_pipeline",
                "description": "运行完整的攻击链路处理流水线",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "alert_data": {
                            "type": "string",
                            "description": "告警数据，JSON格式"
                        },
                        "start_time": {
                            "type": "string",
                            "description": "开始时间"
                        },
                        "end_time": {
                            "type": "string",
                            "description": "结束时间"
                        }
                    },
                    "required": ["alert_data", "start_time", "end_time"]
                }
            }
        ]
        return tools
    
    def get_tools(self) -> List[Dict[str, Any]]:
        return self.registered_tools
    
    def execute_tool(self, tool_name: str, parameters: Dict[str, Any]) -> str:
        if tool_name == "process_alert":
            alert_data = json.loads(parameters["alert_data"])
            result = self.tools.process_alert(alert_data)
            return json.dumps(result)
        elif tool_name == "mining_attack_chain":
            alert_data = json.loads(parameters["alert_data"])
            start_time = parameters["start_time"]
            end_time = parameters["end_time"]
            result = self.tools.mining_attack_chain(alert_data, start_time, end_time)
            return json.dumps(result)
        elif tool_name == "analyze_chain":
            chain_data = json.loads(parameters["chain_data"])
            result = self.tools.analyze_chain(chain_data)
            return json.dumps(result)
        elif tool_name == "run_pipeline":
            alert_data = json.loads(parameters["alert_data"])
            start_time = parameters["start_time"]
            end_time = parameters["end_time"]
            result = self.tools.run_pipeline(alert_data, start_time, end_time)
            return json.dumps(result)
        else:
            return json.dumps({"error": "未知工具"})
    
    def process_query(self, query: str, use_tools: bool = True) -> str:
        if not use_tools:
            return f"处理查询: {query}"
        return "请使用工具处理此查询"

def main():
    agent = ChatGPTAgent()
    print("Agent初始化完成")
    print(f"已注册工具: {[tool['name'] for tool in agent.get_tools()]}")

if __name__ == "__main__":
    main()