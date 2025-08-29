import requests
import json
import os
from prompt import PROMPTS

def query_sgc(question, model="qwen3:32b", stream=False):   

    url = "http://localhost:8866/query"

    prompt = PROMPTS["group_chains_only_kb"].format(language=PROMPTS["DEFAULT_LANGUAGE"], apt_alias=PROMPTS["DEFAULT_alias"])
    payload = {
        "query": question,
        "model": "mix",
        "only_need_context": False,
        "top_k": 30,
        "user_prompt": prompt,
        "enable_rerank": True
    }
        headers = {
        "Content-Type": "application/json",
    }
    
    try:
        response = requests.post(url, headers=headers, data=json.dumps(payload), stream=stream)
        print(f"API响应状态码: {response.status_code}")
        
        if response.status_code == 200:
            if stream:
                lines = []
                for line in response.iter_lines():
                    if line:
                        lines.append(line.decode('utf-8'))
                full_response = "".join(lines)
                return json.loads(full_response)
            else:
                return response.json()
        else:
            print(f"错误: API返回状态码 {response.status_code}")
            print(f"响应内容: {response.text}")
            return {"error": f"API请求失败，状态码: {response.status_code}"}
    
    except Exception as e:
        print(f"发生错误: {str(e)}")
        return {"error": str(e)}


def batch_process():
    chain_info_path = "file_path"
    output_dir = "file_path"
    os.makedirs(output_dir, exist_ok=True)

    try:
        with open(chain_info_path, 'r', encoding='utf-8') as f:
            chain_info_data = json.load(f)
    except Exception as e:
        print(f"读取文件出错: {str(e)}")
        return

    all_results_path = "file_path"

    all_results = {}
    first_entry = True

    if os.path.exists(all_results_path):
        try:
            with open(all_results_path, 'r', encoding='utf-8') as f:
                all_results = json.load(f)
            print(f"已加载现有结果文件，包含 {len(all_results)} 个chain_id")
            first_entry = False  
        except json.JSONDecodeError:
            print("警告：结果文件格式无效，将重新创建")
            with open(all_results_path, 'w', encoding='utf-8') as f:
                f.write("[")
    else:
        with open(all_results_path, 'w', encoding='utf-8') as f:
            f.write("[")

    existing_ids = set()
    for item in all_results:
        for i in item.keys():
            existing_ids.add(i)
    existing_ids = list(existing_ids)
    
    all_results = {}
    for chain_id in chain_info_data:
        if chain_id in existing_ids:
            print(f"{chain_id} 已存在于结果文件中，跳过")
            continue

        alerts_info = chain_info_data[chain_id].get("alerts_info", [])
        new_question = "\n".join(alerts_info)
        print(f"处理 {chain_id}...")

        result = query_sgc(new_question)  # total_scores

        if 'response' in result:
            result_content = result["response"].replace("```json","").replace("```","").strip()
            all_results[chain_id] = result_content
        else:
            all_results[chain_id] = result
        print(all_results[chain_id])

        with open(all_results_path, 'a', encoding='utf-8') as f:
            if not first_entry:
                f.write(",")
            json.dump({chain_id: all_results[chain_id]}, f, ensure_ascii=False, indent=2)
            first_entry = False

        print(f"已实时存储 {chain_id} 的结果到 {all_results_path}")

    with open(all_results_path, 'a', encoding='utf-8') as f:
        f.write("]")

    print(f"批量处理完成，所有结果已实时存储在 {all_results_path}")


if __name__ == "__main__":
    batch_process()
