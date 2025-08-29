import json
import os
import re
import time
from typing import List, Dict, Any, Optional
from collections import defaultdict
from utils import *
from chain_extract import extract_chains_from_single_host
from chain_analysis import clean_chains_data
from alert_rules_merge import get_rules_dict
from pro_logfile import convert_multi_alerts_2_json

class FileLock:
    def __init__(self, path: str):
        self.path = path
        self._fh = None

    def __enter__(self):
        self._fh = open(self.path + ".lock", "a+b")
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(self._fh.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl
            fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX)
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(self._fh.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
        finally:
            self._fh.close()

class NDJSONStore:
    def __init__(self, path: str):
        self.path = path
        self.latest_offset: Dict[str, int] = {}
        # 确保文件存在
        if not os.path.exists(self.path):
            open(self.path, "a", encoding="utf-8").close()
        # 启动时构建索引
        self._build_index()

    def _build_index(self):
        self.latest_offset.clear()
        with open(self.path, "rb") as f:
            while True:
                offset = f.tell()
                line = f.readline()
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line.decode("utf-8"))
                    ip = rec.get("ip")
                    if ip:
                        self.latest_offset[ip] = offset
                except Exception:
                    # 跳过损坏行
                    continue

    def append(self, ip: str, data: Dict[str, Any]):
        payload = {"ip": ip, "data": data}
        line = (json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8")
        with FileLock(self.path):
            with open(self.path, "ab") as f:
                start = f.tell()
                f.write(line)
                f.flush()
                os.fsync(f.fileno())
                self.latest_offset[ip] = start

    def get_latest(self, ip: str) -> Optional[Dict[str, Any]]:
        off = self.latest_offset.get(ip)
        if off is None:
            return None
        with open(self.path, "rb") as f:
            f.seek(off)
            line = f.readline()
            rec = json.loads(line.decode("utf-8"))
            return rec.get("data")

    def dump_as_dict(self) -> Dict[str, Any]:
        result = {}
        with open(self.path, "rb") as f:
            for ip, off in self.latest_offset.items():
                f.seek(off)
                line = f.readline()
                rec = json.loads(line.decode("utf-8"))
                result[ip] = rec.get("data")
        return result

    def compact(self):
        fd, tmp_path = tempfile.mkstemp(prefix="ndjson_compact_", suffix=".ndjson")
        os.close(fd)
        try:
            with FileLock(self.path):
                with open(tmp_path, "wb") as out, open(self.path, "rb") as src:
                    for ip, off in self.latest_offset.items():
                        src.seek(off)
                        line = src.readline()
                        out.write(line)
                os.replace(tmp_path, self.path)
                # 替换后重建索引（偏移变化了）
                self._build_index()
        finally:
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass

class FileLock:
    def __init__(self, file_path):
        self.file_path = file_path
        self.lock_path = file_path + '.lock'
    
    def acquire(self):
        while os.path.exists(self.lock_path):
            time.sleep(0.1)
        with open(self.lock_path, 'w') as f:
            f.write(str(os.getpid()))
    
    def release(self):
        if os.path.exists(self.lock_path):
            os.remove(self.lock_path)
    
    def __enter__(self):
        self.acquire()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.release()

class NDJSONStore:
    def __init__(self, file_path):
        self.file_path = file_path
        self._ensure_file_exists()
    
    def _ensure_file_exists(self):
        if not os.path.exists(self.file_path):
            with open(self.file_path, 'w') as f:
                pass
    
    def read(self) -> List[Dict[str, Any]]:
        data = []
        try:
            with open(self.file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        data.append(json.loads(line))
        except Exception:
            pass
        return data
    
    def write(self, data: List[Dict[str, Any]]):
        with FileLock(self.file_path):
            with open(self.file_path, 'w', encoding='utf-8') as f:
                for item in data:
                    f.write(json.dumps(item, ensure_ascii=False) + '\n')
    
    def append(self, item: Dict[str, Any]):
        with FileLock(self.file_path):
            with open(self.file_path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(item, ensure_ascii=False) + '\n')

class AttackChainTools:
    def __init__(self, root_dir: str, openai_client):
        self.root_dir = root_dir
        self.output_path = "file_path"
        self.openai_client = openai_client
        pathExists(self.output_path, create=True)
        
        # 初始化文件路径
        self.rule_file = "file_path"
        self.alert_log_path = "file_path"
        self.correlation_llm_path = "file_path"
        self.chain_file = "file_path"
        self.simple_saved_path = "file_path"
        self.all_saved_path = "file_path"
        
    def process_alert(self, fast_log_files: List[str]) -> List[Dict[str, Any]]:
        if fileExists(self.alert_log_path):
            alert_log_data = ReadJsonData(self.alert_log_path)
            
        else:
            time_sta = time.time()
            rule_data = ReadJsonData(self.rule_file)
            
            alert_log_data = convert_multi_alerts_2_json(
                fastlogfiles=fast_log_files,
                rulefile=rule_data
            )
            
            Write2Json(self.alert_log_path, alert_log_data)
            print(f"[TIME] 处理告警数据时间：{time.time()-time_sta:.2f}秒")
        return alert_log_data

    def mining_attack_chain(self, alert_log_data: List[Dict[str, Any]], strategy: int = 0) -> Optional[Dict[str, Any]]:
        time_sta = time.time()
        cluster_path = os.path.join(self.output_path, 'clusterdata.json')
        hyper_cluster_path = os.path.join(self.output_path, 'hyper_clusterdata.json')
        
        if fileExists(hyper_cluster_path):
            hyper_clusterdata = ReadJsonData(hyper_cluster_path)
        else:
            clusterdata = cluster_by_ip(alert_log_data, savedpath=cluster_path)
            hyper_clusterdata = reconstruct_alert_2_hyperalerts(
                clusterdata, savedpath=hyper_cluster_path
            )

        store = NDJSONStore(self.correlation_llm_path)


        gpt_response_data = {}
        for ip, alerts in hyper_clusterdata.items():
            llm_input = extract_llm_input(alerts['TA0043'])

            prompt = PROMPTS["correlate_chains"].format(language=PROMPTS["DEFAULT_LANGUAGE"], inputtext=json.dumps(llm_input, ensure_ascii=False))

            try:
                response = self.openai_client.chat.completions.create(
                    model='gpt-4.1',   #'gpt-4o',
                    messages=[{'role': 'user', 'content': prompt}],
                    response_format={'type': 'json_object'}
                )
                # 解析JSON响应并按IP存储
                content = response.choices[0].message.content
                try:
                    parsed = json.loads(content)
                except json.JSONDecodeError:
                    print(f"GPT返回非JSON格式响应: {content}")
                    parsed = {"error": "无效的JSON响应"}

                gpt_response_data[ip] = parsed
                store.append(ip, parsed)
                print(ip)
            except Exception as e:
                print(f"IP {ip} 的 GPT API 调用失败: {str(e)}")
                err_obj = {"error": str(e)}
                gpt_response_data[ip] = err_obj
                # 异常也落盘，便于断点续跑
                try:
                    store.append(ip, err_obj)
                except Exception as se:
                    print(f"保存当前IP数据失败: {str(se)}")
                
        if not any(isinstance(v, dict) and "error" not in v for v in gpt_response_data.values()):
            print("所有IP的链路挖掘均失败")
            return None

        chain_data = find_chain_data(
            gpt_response_data, 
            hyperalerts=hyper_clusterdata,
            T=[strategy],
            notP=True,
            STEP_LENGTH=2
        )
        
        Write2Json(self.chain_file, chain_data)
        print(f"[TIME] 挖掘链路时间：{time.time()-time_sta:.2f}秒")
        return chain_data
    
    def analyze_chain(self, chain_data: Dict[str, Any]) -> bool:
        time_sta = time.time()
        rule_data = ReadJsonData(self.rule_file)
        
        success = extract_chain_data_for_anaylze_main(
            chain_data,
            rule_data,
            self.simple_saved_path,
            self.all_saved_path
        )
        
        print(f"[TIME] 分析链路时间：{time.time()-time_sta:.2f}秒")
        return success
    
    def run_pipeline(self, alert_data: Dict[str, Any], start_time: str, end_time: str) -> Dict[str, Any]:
        try:
            if isinstance(alert_data, str):
                alert_data = json.loads(alert_data)
            processed_alerts = [self.process_alert(alert) for alert in alert_data if isinstance(alert, dict)]
            mining_result = self.mining_attack_chain(processed_alerts, start_time, end_time)
            chains_data = mining_result.get('chains', [])
            analysis_result = self.analyze_chain(chains_data)
            result = {
                'pipeline_status': 'completed',
                'processed_alerts_count': len(processed_alerts),
                'chains_count': mining_result.get('count', 0),
                'analysis': analysis_result
            }
            return result
        except Exception as e:
            return {'error': str(e)}