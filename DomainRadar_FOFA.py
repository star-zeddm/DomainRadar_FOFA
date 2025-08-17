import os
import json
import base64
import random
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from datetime import datetime
import requests
from urllib.parse import urlparse
import socket
import webbrowser
import time
import hashlib
import ipaddress
from time import sleep
import configparser

# 用于存储配置的文件路径
CONFIG_FILE = "config.ini"

def Write_all_testdomain(domain_dic_list):
    print('fofa域名过滤:', domain_dic_list)
    with open('./data/all_subdomain.txt', 'r+', encoding='utf-8') as f:
        domains = [i.strip() for i in f if i.strip()]
        print('读取子域名文件:', domains)
        domain_dic_list = [i for i in domain_dic_list if i['domain'] not in domains]
        for i in domain_dic_list:
            f.write(i['domain'] + '\n')
        print(f'过滤后列表:{domain_dic_list}\n\n')
    return domain_dic_list


class ERP_Search:
    def __init__(self, ipc_list, data_dir, log_callback=None, stop_event=None):
        self.ipc_list = ipc_list
        self.data_dir = data_dir
        self.log_callback = log_callback
        self.stop_event = stop_event if stop_event else threading.Event()
        self.headers = {
            "Cookie": "BIDUPSID=E235731BA6B919F5F3C24FAA2ACDB65D; PSTM=1732673045; BAIDUID=E235731BA6B919F58D6B750BB22BBCFF:FG=1; H_PS_PSSID=60271_61027_61054_61135_61140_61156_61178_61218_61211_61214_61239_61287; BAIDUID_BFESS=E235731BA6B919F58D6B750BB22BBCFF:FG=1; in_source=; log_first_time=1737430791534; ppfuid=FOCoIC3q5fKa8fgJnwzbE67EJ49BGJeplOzf+4l4EOvDuu2RXBRv6R3A1AZMa49I27C0gDDLrJyxcIIeAeEhD8JYsoLTpBiaCXhLqvzbzmvy3SeAW17tKgNq/Xx+RgOdb8TWCFe62MVrDTY6lMf2GrfqL8c87KLF2qFER3obJGl54cTh3pOgTyao5J7yyxW7/VC+Kd/PngdwCv5WfV0iP3efldEnw4+7qfVzNX7X7ZvXEymXZ7vIeVtTSY2u6kADVgeLNEqiQqRHoDHn7huVqy2H/zju0tlHnG7joNOPEawxg3XduDu1LQGcI8Qah4c9Ks5+Bm57DHOG4XwLtn1ztW8tRqKUkqDhgP5FRw9NLXmTkwA5GQ/hyIdmdqG8e+8W8OdEuZ242+1RyigUrmZ4jUHv1DxZiH330Apc6oKkZo0Y6IJXad8xN1gQMZ1tOmckSecr9yhMSRLVoFktEC1isFW/ROI5v+vVAliVWJGW5HgFMb7+JFWxNGoA0JNiv6hCb0gkXpkEpISi6tVHh+hsQifjACGGz0MbLI9AAutvQNmLovQE8DrrUkOPSWZkiBwIUvxonSGS2lgiNZBxgK/Nad6P3sfvyvYhyXNwxm6SzH+Oja1l6cy9uoP7y446ILa1CLEOaV1jDkGoksNhRtn7B1VPovN1TRU04qLrmECuDGMBVR4vlhy8DqZQ1/LUEQ9mrM1XTShMu8Y6z7mcjIEx0SRhpMWhMo8MNW10I79rYiEZqj4cFtwDdJ/UZaa6iAMtQJsQN5mcP7l0phxlMCLHljdpCE44gtacKuIAL7fDTck9aMDA0wNIlJo9fK+rPw0T9+JIpQ6nVWxL4vL34i6mfzL4hLXcGAwm/blGCaj2qqlhN1cdi5hUk99gF8iC4u7PLY1O540Gbhx6NM0AEaGAyhwuOPgholqmaWjD3gGT2h9Asw5MktHEx3qmgMyCheA4RuK4Xh9wa58/i6DblN6kL37MoBk2+fk1Zu8uXMwS+/rrQ6U1O7Zv2wiyJOnrYyq/5Tv2IOghUDulefRvlX9eT7gQwEiclvXWS2pMTflyx6wORXYWMC8Ewe1rUuQprEZZNDywMI17CupLBOAx9qwTTBhEMNzi6OXbElHkA3erw56I0vmkH9G20tmAiqCABGBI1qeHlbtIIUXAPQK2AKm25kN9e++uG7KATaiQSHPJR405LDjC+5v0mQclI0YcJp8DvGLdRUpGcbUX7V27dvoxZNlkNAKwTxTOnYZkLWOYVTD5EoNlrqqJb8Op38LjSNcK; Hm_lvt_18ca88c840f4f94ef856298c2c8435a9=1737431002; HMACCOUNT=C9F0300199ABB3D0; login_id=373825955; device_type=dgtsale-h5; acc_id=373825955; GAT_QRNIGOL_FFA=cf1d3d9b1a82d2f87d633bd8a03423; log_last_time=1737431003121; sajssdk_2015_cross_new_user=1; BDPPN=ab93de6dadbbbee4eb393e067d662aad; login_type=passport; _t4z_qc8_=xlTM-TogKuTwd8lOkqB5L8VMHZ8qnveAtwmd; Hm_lpvt_18ca88c840f4f94ef856298c2c8435a9=1737431067; sensorsdata2015jssdkcross=%7B%22distinct_id%22%3A%22373825955%22%2C%22first_id%22%3A%2219486f533764b7-0da05e0dc9aa3e-1037357a-2073600-19486f533771231%22%2C%22props%22%3A%7B%7D%2C%22%24device_id%22%3A%2219486f533764b7-0da05e0dc9aa3e-1037357a-2073600-19486f533771231%22%7D; ab_sr=1.0.1_MTIyNzBjYTA5MjhmY2UyMjcxOGIyZTIzZjIzYTcyZWVkOGFhNjBlNjY0NDllZDJjNDJlZTI3MmNhMjI4MWEyYmY4ZWZmY2E4MTY5YTVhOGQ2MGIzOGNhZEU2YjQ1MWYwNzA1MWNhNzcxYTY0ODk5YzQwYTkzMzI2MTIwZTk1MmY2NjFlNjUyZmRmNTVjNjM4NDk1MjhmZmZmMzIyZWI4ZA==; BDUSS=NaTVNiVXh-YVlJSk1hTGlKemVNdXhHZnNOVWVLQ05WTkE3R0hVc0JDdy1wYlpuSVFBQUFBJCQAAAAAAQAAAAEAAAC~a1Z6v9rL42Jhc2U2NAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD4Yj2c-GI9ndD; BDUSS_BFESS=NaTVNiVXh-YVlJSk1hTGlKemVNdXhHZnNOVWVLQ05WTkE3R0hVc0JDdy1wYlpuSVFBQUFBJCQAAAAAAQAAAAEAAAC~a1Z6v9rL42Jhc2U2NAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD4Yj2c-GI9ndD; RT=z=1&dm=baidu.com&si=27896759-2464-488d-818c-d453abcab41a&ss=m65xfdf9&sl=m&tt=ui6&bcn=https%3A%2F%2Ffclog.baidu.com%2Flog%2Fweirwood%3Ftype%3Dperf&ld=709j",
            "Content-Length": "193",
            "Sec-Ch-Ua": '"Not-A.Brand";v="99", "Chromium";v="124"',
            "Auth-Type": "PAAS",
            "Sec-Ch-Ua-Mobile": "?0",
            "Env": "WEB",
            "Client-Version": "0",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.60 Safari/537.36",
            "Content-Type": "application/json;charset=UTF-8",
            "Accept": "application/json, text/plain, */*",
            "X-Sourceid": "24b43d846bd3bf470000550eb1425f8e",
            "X-Requested-With": "XMLHttpRequest",
            "Api-Version": "0",
            "User-Info": "uc_id=;uc_appid=585;acc_token=;acc_id=373825955;login_id=373825955;device_type=dgtsale-h5;paas_appid=18;version=12;login_type=passport",
            "Sec-Ch-Ua-Platform": '"Windows"',
            "Origin": "https://xunkebao.baidu.com",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
            "Referer": "https://xunkebao.baidu.com/index.html",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Priority": "u=1, i",
            "Connection": "close"
        }

    def log(self, message):
        if self.log_callback:
            self.log_callback(message)

    def get_keyid(self, enterprise_name):
        self.log(f'资产查询:{enterprise_name}')
        url = 'https://xunkebao.baidu.com/crm/web/aiqicha/bizcrm/enterprise/simpleSearch'

        json_data = {
            "params": {
                "searchTypeCode": "name",
                "searchValue": enterprise_name,
                "id": "",
                "isNeedHighLight": True,
                "highLightTag": "",
                "isNeedLoadUnlockStatus": True,
                "isIncludeDeleted": True
            }
        }

        try:
            response = requests.post(url=url, headers=self.headers, json=json_data, timeout=15)
            response.raise_for_status()
            rsp = response.json()
            data_list = rsp['data']["dataList"]

            data_dic = [{"id_num": str(data_list.index(i)), 'key_id': i['id'], 'name': i["name"]}
                        for i in data_list]

            enterprise_unlock = '0'
            end_dic = [i for i in data_dic if i['id_num'] == enterprise_unlock]

            if not end_dic:
                raise Exception("未找到匹配的企业")

            key_id = end_dic[0]["key_id"]
            self.log(f"企业ID获取成功: {key_id}")
            return key_id
        except Exception as e:
            self.log(f"获取企业ID失败: {str(e)}")
            return None

    def message_get(self, key_id):
        url = 'https://xunkebao.baidu.com/crm/web/aiqicha/bizcrm/enterprise/queryBaseInfoById'
        json_data = {
            "params": {
                "id": key_id,
                "isNeedLoadUnlockStatus": True,
                "isNeedLoadUpdownStreamRelationNum": True,
                "isNeedLoadBiddingNum": True,
                "isNeedLoadContactAbstract": True
            }
        }

        try:
            response = requests.post(url=url, headers=self.headers, json=json_data, timeout=15)
            response.raise_for_status()
            resp_d = response.json()["data"]
            registeredCapital = resp_d.get('registeredCapital', '未知')
            self.log(f"注册资本: {registeredCapital}")
            return registeredCapital
        except Exception as e:
            self.log(f"查询企业信息失败: {str(e)}")
            return '未知'

    def save_erp(self, filename, erp_list):
        output_path = os.path.join(self.data_dir, 'date', filename, 'ERP.json')
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(erp_list, f, ensure_ascii=False, indent=2)
            self.log(f"ERP信息已保存到: {output_path}")
            return True
        except Exception as e:
            self.log(f"保存ERP信息失败: {str(e)}")
            return False

    def main(self, filename):
        if not self.ipc_list:
            self.log("没有可查询的企业备案信息")
            return []

        erp_list = []
        total = len(self.ipc_list)

        for idx, enterprise in enumerate(self.ipc_list):
            if self.stop_event.is_set():
                self.log("ERP查询已被用户中断")
                return erp_list

            progress = (idx + 1) / total * 100
            self.log(f"正在处理 {idx + 1}/{total}: {enterprise.get('unitName', '未知企业')}")

            try:
                key_id = self.get_keyid(enterprise['unitName'])
                if not key_id:
                    continue

                registeredCapital = self.message_get(key_id)
                enterprise['registeredCapital'] = registeredCapital
                erp_list.append(enterprise)

                # 防止请求过于频繁
                time.sleep(1)

            except Exception as e:
                self.log(f"处理 {enterprise.get('unitName', '未知企业')} 失败: {str(e)}")
                continue

        if erp_list:
            self.save_erp(filename, erp_list)

        return erp_list


class IPC_Search:
    def __init__(self, domain_list, log_callback=None, stop_event=None):
        self.domain_list = domain_list
        self.log_callback = log_callback
        self.stop_event = stop_event if stop_event else threading.Event()
        self.progress_callback = None

    def log(self, message):
        if self.log_callback:
            self.log_callback(message)

    def update_progress(self, value):
        if self.progress_callback:
            self.progress_callback(value)

    def get_RandomIp(self):
        while True:
            ip = ipaddress.IPv4Address(random.randint(0, (1 << 32) - 1))
            if not (ip.is_private or ip.is_loopback or ip.is_multicast or ip.is_reserved):
                return str(ip)

    def get_token(self):
        ts = str(int(time.time() * 1000))
        auth_key = hashlib.md5(f'testtest{ts}'.encode()).hexdigest()

        headers = {
            "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36',
            'Referer': 'https://beian.miit.gov.cn/'
        }
        headers['CLIENT-IP'] = headers['X-FORWARDED-FOR'] = self.get_RandomIp()

        data = {'authKey': auth_key, 'timeStamp': ts}
        url = "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/auth"

        self.log("正在获取备案查询Token...")
        try:
            resp = requests.post(url=url, headers=headers, data=data, timeout=15)
            resp.raise_for_status()
            token = resp.json().get("params", {}).get("bussiness")
            refresh = resp.json().get("params", {}).get("refresh")

            if not token or not refresh:
                raise Exception("获取token失败")

            self.token = token
            self.refresh = refresh
            self.log("Token获取成功")
            return True
        except Exception as e:
            self.log(f"获取Token失败: {str(e)}")
            return False

    def get_ipcInfo(self, domain):
        url = "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/icpAbbreviateInfo/queryByCondition/"
        headers = {
            "Content-Type": "application/json",
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36',
            'Referer': 'https://beian.miit.gov.cn/',
            "Origin": "https://beian.miit.gov.cn/",
            'token': self.token,
            'Sign': self.refresh,
            'CLIENT-IP': self.get_RandomIp(),
            'X-FORWARDED-FOR': self.get_RandomIp()
        }

        json_data = {
            "pageNum": "1",
            "pageSize": "10",
            "unitName": domain,
            'serviceType': '1'
        }

        try:
            self.log(f"正在查询域名备案: {domain}")
            rsp = requests.post(url=url, headers=headers, json=json_data, timeout=15)
            rsp.raise_for_status()
            return rsp.json().get('params', {}).get("list", [])
        except Exception as e:
            self.log(f"查询备案失败: {str(e)}")
            return 'error'

    def main(self):
        if not self.get_token():
            return []

        filtered_domains = []
        total = len(self.domain_list)

        for idx, domain_info in enumerate(self.domain_list):
            if self.stop_event.is_set():  # 检查是否收到停止信号
                self.log("IPC查询已被用户中断")
                return filtered_domains

            domain = domain_info['topdomain']
            progress = (idx + 1) / total * 100
            self.update_progress(progress)
            self.log(f"正在处理 {idx + 1}/{total}: {domain}")

            retry_count = 3
            while retry_count > 0:
                time.sleep(5)  # 防止请求过于频繁
                ipc_info = self.get_ipcInfo(domain)

                if ipc_info == 'error':
                    retry_count -= 1
                    self.log(f"Token过期，尝试重新获取... (剩余尝试次数: {retry_count})")
                    if not self.get_token():
                        break
                    continue

                if not ipc_info:
                    self.log(f"未查询到备案信息: {domain}")
                    break

                if isinstance(ipc_info, list) and ipc_info:
                    ipc_info[0]['subdomain'] = domain_info['domain']
                    if ipc_info[0].get('natureName') == "企业":
                        filtered_domains.append(ipc_info[0])
                        self.log(f"找到企业备案: {domain}")
                    else:
                        self.log(f"非企业备案: {domain}")
                    break

                retry_count -= 1

        return filtered_domains


class FOFACollectorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("FOFA企业资产采集系统 v3.2")
        self.root.geometry("1300x900")
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        # 初始化
        self.data_dir = os.path.abspath('./data')
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)

        self.stop_event = threading.Event()
        self.worker_thread = None

        # 读取配置文件
        self.config = configparser.ConfigParser()
        self.config.read(CONFIG_FILE, encoding='utf-8')
        if 'FOFA' not in self.config:
            self.config['FOFA'] = {'email': '', 'api_key': ''}

        # 创建UI
        self.create_widgets()
        self.apply_styles()

    def create_widgets(self):
        # 主框架
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 控制面板
        control_frame = ttk.LabelFrame(main_frame, text="采集控制")
        control_frame.pack(fill=tk.X, pady=(0, 10))

        # FOFA API配置
        fofa_frame = ttk.Frame(control_frame)
        fofa_frame.pack(fill=tk.X, pady=5)

        ttk.Label(fofa_frame, text="FOFA邮箱:").grid(row=0, column=0, sticky='w')
        self.fofa_email_entry = ttk.Entry(fofa_frame, width=30)
        self.fofa_email_entry.grid(row=0, column=1, padx=5)
        self.fofa_email_entry.insert(0, self.config.get('FOFA', 'email'))

        ttk.Label(fofa_frame, text="FOFA API Key:").grid(row=0, column=2, padx=(10, 0))
        self.fofa_api_key_entry = ttk.Entry(fofa_frame, width=30)
        self.fofa_api_key_entry.grid(row=0, column=3)
        self.fofa_api_key_entry.insert(0, self.config.get('FOFA', 'api_key'))

        ttk.Button(fofa_frame, text="保存配置", command=self.save_fofa_config).grid(row=0, column=4, padx=5)

        # 查询设置
        query_frame = ttk.Frame(control_frame)
        query_frame.pack(fill=tk.X, pady=5)

        ttk.Label(query_frame, text="FOFA语法:").grid(row=0, column=0, sticky='w')
        self.query_entry = ttk.Entry(query_frame, width=60)
        self.query_entry.grid(row=0, column=1, padx=5)
        self.query_entry.insert(0, 'body="个人中心" && body="编辑" && body="旅游"')

        ttk.Label(query_frame, text="数量:").grid(row=0, column=2, padx=(10, 0))
        self.num_spin = ttk.Spinbox(query_frame, from_=1, to=10000, width=8)
        self.num_spin.grid(row=0, column=3)
        self.num_spin.set(500)

        # 过滤设置
        filter_frame = ttk.Frame(control_frame)
        filter_frame.pack(fill=tk.X, pady=5)

        ttk.Label(filter_frame, text="PC权重≥").grid(row=0, column=0)
        self.pc_br_spin = ttk.Spinbox(filter_frame, from_=0, to=10, width=3)
        self.pc_br_spin.grid(row=0, column=1, padx=5)
        self.pc_br_spin.set(1)

        ttk.Label(filter_frame, text="移动权重≥").grid(row=0, column=2, padx=(10, 0))
        self.m_br_spin = ttk.Spinbox(filter_frame, from_=0, to=10, width=3)
        self.m_br_spin.grid(row=0, column=3)
        self.m_br_spin.set(1)

        # 操作按钮
        btn_frame = ttk.Frame(control_frame)
        btn_frame.pack(fill=tk.X, pady=5)

        self.start_btn = ttk.Button(btn_frame, text="开始采集", command=self.start_process)
        self.start_btn.pack(side=tk.LEFT, padx=5)

        self.stop_btn = ttk.Button(btn_frame, text="停止", state=tk.DISABLED, command=self.stop_process)
        self.stop_btn.pack(side=tk.LEFT)

        ttk.Button(btn_frame, text="打开结果", command=self.open_result_dir).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="清空日志", command=self.clear_logs).pack(side=tk.LEFT)

        # 进度条框架
        progress_frame = ttk.Frame(control_frame)
        progress_frame.pack(fill=tk.X, pady=5)

        self.progress_label = ttk.Label(progress_frame, text="进度: 0%")
        self.progress_label.pack(side=tk.LEFT)

        self.progress = ttk.Progressbar(progress_frame, orient=tk.HORIZONTAL, mode='determinate')
        self.progress.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        # 主内容区
        content_frame = ttk.Frame(main_frame)
        content_frame.pack(fill=tk.BOTH, expand=True)

        # 文件树
        tree_frame = ttk.Frame(content_frame)
        tree_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))

        self.tree = ttk.Treeview(tree_frame, show='tree')
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.tree.bind("<Double-1>", self.on_tree_double_click)
        self.tree.bind("<Button-3>", self.show_context_menu)

        tree_scroll = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        tree_scroll.pack(side=tk.LEFT, fill=tk.Y)
        self.tree.configure(yscrollcommand=tree_scroll.set)

        # 右键菜单
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="打开", command=lambda: self.on_tree_double_click())
        self.context_menu.add_command(label="关闭", command=self.close_selected_file)

        # 内容显示区
        self.notebook = ttk.Notebook(content_frame)
        self.notebook.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # 权重显示
        weight_frame = ttk.Frame(self.notebook)
        self.weight_text = scrolledtext.ScrolledText(weight_frame, wrap=tk.WORD, font=('Consolas', 10))
        self.weight_text.pack(fill=tk.BOTH, expand=True)
        self.notebook.add(weight_frame, text="权重数据")

        # IPC日志显示
        self.ipc_frame = ttk.Frame(self.notebook)
        self.ipc_text = scrolledtext.ScrolledText(self.ipc_frame, wrap=tk.WORD, font=('Consolas', 10))
        self.ipc_text.pack(fill=tk.BOTH, expand=True)
        self.notebook.add(self.ipc_frame, text="IPC日志")

        # ERP日志显示
        self.erp_frame = ttk.Frame(self.notebook)
        self.erp_text = scrolledtext.ScrolledText(self.erp_frame, wrap=tk.WORD, font=('Consolas', 10))
        self.erp_text.pack(fill=tk.BOTH, expand=True)
        self.notebook.add(self.erp_frame, text="ERP日志")

        # 运行日志
        log_frame = ttk.Frame(self.notebook)
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, font=('Consolas', 10))
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.notebook.add(log_frame, text="运行日志")

        # 状态栏
        status_frame = ttk.Frame(self.root)
        status_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

        self.status_label = ttk.Label(status_frame, text="就绪")
        self.status_label.pack(side=tk.LEFT)

        github_label = ttk.Label(status_frame, text="GitHub", cursor="hand2")
        github_label.pack(side=tk.RIGHT)
        github_label.bind("<Button-1>", self.open_github)

        # 初始化
        self.refresh_file_tree()

    def apply_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('.', font=('Microsoft YaHei', 10))
        style.configure('TFrame', background='#f5f5f5')
        style.configure('TLabel', background='#f5f5f5')
        style.configure('TButton', padding=5)
        style.configure('Treeview', rowheight=25, font=('Microsoft YaHei', 10))
        style.configure('TNotebook.Tab', padding=[10, 5])

    def refresh_file_tree(self):
        self.tree.delete(*self.tree.get_children())
        self.build_tree(self.data_dir, "")

    def build_tree(self, parent_path, parent_node):
        try:
            for item in sorted(os.listdir(parent_path)):
                full_path = os.path.join(parent_path, item)
                node = self.tree.insert(parent_node, 'end', text=item, open=False)
                if os.path.isdir(full_path):
                    self.build_tree(full_path, node)
        except Exception as e:
            self.log(f"加载文件树错误: {str(e)}")

    def show_context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    def on_tree_double_click(self, event=None):
        try:
            selected = self.tree.selection()
            if not selected:
                return

            item = selected[0]
            path = [self.tree.item(item, "text")]
            parent = self.tree.parent(item)

            while parent:
                path.insert(0, self.tree.item(parent, "text"))
                parent = self.tree.parent(parent)

            full_path = os.path.join(self.data_dir, *path)
            if os.path.isfile(full_path):
                self.open_file(full_path)
        except Exception as e:
            self.log(f"打开文件错误: {str(e)}")

    def close_selected_file(self):
        try:
            selected = self.tree.selection()
            if not selected:
                return

            item_text = self.tree.item(selected[0], "text")
            for tab in self.notebook.tabs():
                if self.notebook.tab(tab, "text") == item_text:
                    self.notebook.forget(tab)
                    break
        except Exception as e:
            self.log(f"关闭文件错误: {str(e)}")

    def open_file(self, file_path):
        try:
            file_name = os.path.basename(file_path)

            # 检查是否已打开
            for tab in self.notebook.tabs():
                if self.notebook.tab(tab, "text") == file_name:
                    self.notebook.select(tab)
                    return

            # 创建新标签页
            new_tab = ttk.Frame(self.notebook)
            text = scrolledtext.ScrolledText(new_tab, wrap=tk.WORD, font=('Consolas', 10))
            text.pack(fill=tk.BOTH, expand=True)

            # 添加关闭按钮
            close_btn = ttk.Button(new_tab, text="×", width=2,
                                   command=lambda: self.notebook.forget(new_tab))
            close_btn.place(relx=1.0, x=-25, y=5, anchor=tk.NE)

            # 加载文件内容
            if file_path.endswith('.json'):
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    text.insert(tk.END, json.dumps(data, indent=2, ensure_ascii=False))
            else:
                with open(file_path, 'r', encoding='utf-8') as f:
                    text.insert(tk.END, f.read())

            text.config(state=tk.DISABLED)
            self.notebook.add(new_tab, text=file_name)
            self.notebook.select(new_tab)

        except Exception as e:
            self.log(f"打开文件错误: {str(e)}")

    def clear_logs(self):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.DISABLED)
        self.weight_text.config(state=tk.NORMAL)
        self.weight_text.delete(1.0, tk.END)
        self.weight_text.config(state=tk.DISABLED)
        self.ipc_text.config(state=tk.NORMAL)
        self.ipc_text.delete(1.0, tk.END)
        self.ipc_text.config(state=tk.DISABLED)
        self.erp_text.config(state=tk.NORMAL)
        self.erp_text.delete(1.0, tk.END)
        self.erp_text.config(state=tk.DISABLED)
        self.status_label.config(text="日志已清空")

    def log(self, message):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.config(state=tk.DISABLED)
        self.log_text.see(tk.END)
        self.status_label.config(text=message)
        self.root.update()

    def log_ipc(self, message):
        self.ipc_text.config(state=tk.NORMAL)
        self.ipc_text.insert(tk.END, message + "\n")
        self.ipc_text.config(state=tk.DISABLED)
        self.ipc_text.see(tk.END)
        self.root.update()

    def log_erp(self, message):
        self.erp_text.config(state=tk.NORMAL)
        self.erp_text.insert(tk.END, message + "\n")
        self.erp_text.config(state=tk.DISABLED)
        self.erp_text.see(tk.END)
        self.root.update()

    def update_progress(self, value, message=None):
        self.progress['value'] = value
        self.progress_label.config(text=f"进度: {int(value)}%")
        if message:
            self.status_label.config(text=message)
        self.root.update()

    def open_result_dir(self):
        try:
            date_dir = os.path.join(self.data_dir, 'date')
            if os.path.exists(date_dir):
                os.startfile(date_dir)
            else:
                messagebox.showinfo("提示", "尚未生成任何结果")
        except Exception as e:
            messagebox.showerror("错误", f"无法打开目录: {str(e)}")

    def is_ip_address(self, address):
        try:
            socket.inet_aton(address)
            return True
        except socket.error:
            return False

    def fofa_search(self, grammar, num):
        email = self.config.get('FOFA', 'email')
        api_key = self.config.get('FOFA', 'api_key')
        api_url = "https://fofa.red/api/v1/search/all?email={}&key={}&qbase64={}&size={}"

        flag = base64.b64encode(grammar.encode()).decode()
        full_url = api_url.format(email, api_key, flag, num)

        try:
            self.update_progress(0, "正在执行FOFA搜索...")
            response = requests.get(full_url, timeout=15)
            response.raise_for_status()
            results = response.json()['results']
            self.log(f"共搜索到 {len(results)} 条记录！")

            return ["http://" + i[0] if not i[0].startswith(('http://', 'https://')) else i[0] for i in results]
        except requests.exceptions.RequestException as e:
            self.log(f"FOFA搜索失败: {str(e)}")
            raise

    def domain_filtration(self, ip_list):
        domain_dic = []
        tmp_list = []
        total = len(ip_list)

        for idx, i in enumerate(ip_list):
            if self.stop_event.is_set():
                return []

            progress = (idx + 1) / total * 33  # FOFA搜索占33%
            self.update_progress(progress, "正在过滤域名...")

            tmp_dic = {}
            parsed_url = urlparse(i)
            domain_ip = parsed_url.netloc
            tmp_del = None

            if ':' in i:
                tmp_del = domain_ip
                domain_ip = domain_ip.split(':')[0]

            if not self.is_ip_address(domain_ip):
                top_domain = domain_ip.split('.')[-2:]
                top_domain = '.'.join(top_domain)

                if top_domain not in tmp_list:
                    tmp_list.append(top_domain)
                    tmp_dic['topdomain'] = top_domain
                    tmp_dic['domain'] = tmp_del if tmp_del else domain_ip
                    domain_dic.append(tmp_dic)

        return domain_dic

    def get_baidu_rank(self, domain_dic_list):
        # 增加子域名处理
        domain_dic_list = Write_all_testdomain(domain_dic_list)
        self.log(f"过滤后的子域名{len(domain_dic_list)}")

        all_list = []
        key_list = ['82e9b2e08887d76d940880b8b12662ca', '73f64db05b879c7bea11127b41b2a9e3',
                    'bdb2538fbfc149e04c108fd14f1903ed', 'ac770ae0d668c4ca1bd64d42fb18cc41',
                    '3f5a7c1ec2ebbe29f7d7a19841bd2a52']

        total = len(domain_dic_list)
        for idx, domain_info in enumerate(domain_dic_list):
            if self.stop_event.is_set():
                return []

            # 更新进度 (33-66%范围)
            progress = 33 + (idx + 1) / total * 33
            self.update_progress(progress, "正在查询百度权重...")

            random_key = random.choice(key_list)
            url = f"http://apistore.aizhan.com/baidurank/siteinfos/{random_key}?domains={domain_info['topdomain']}"

            try:
                resp = requests.get(url, timeout=10)
                data_j = resp.json()
                domain_info['pc_br'] = data_j['data']['success'][0]["pc_br"]
                domain_info['m_br'] = data_j['data']['success'][0]["m_br"]

                # 显示权重信息
                weight_info = (f"域名: {domain_info['domain']}\n"
                               f"主域名: {domain_info['topdomain']}\n"
                               f"PC权重: {domain_info['pc_br']}\n"
                               f"移动权重: {domain_info['m_br']}\n"
                               "------------------------\n")
                self.weight_text.config(state=tk.NORMAL)
                self.weight_text.insert(tk.END, weight_info)
                self.weight_text.see(tk.END)
                self.weight_text.config(state=tk.DISABLED)

                min_pc = int(self.pc_br_spin.get())
                min_m = int(self.m_br_spin.get())
                if domain_info['pc_br'] >= min_pc or domain_info['m_br'] >= min_m:
                    all_list.append(domain_info)
            except Exception as e:
                self.log(f"处理 {domain_info['domain']} 错误: {str(e)}")
                continue

        return all_list

    def save_results(self, br_list):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = os.path.join(self.data_dir, 'date', timestamp)
        os.makedirs(output_dir, exist_ok=True)

        # 保存URL列表
        url_path = os.path.join(output_dir, 'url.txt')
        with open(url_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(['http://' + i['domain'] for i in br_list]))

        # 保存权重数据
        weights_path = os.path.join(output_dir, 'weights.json')
        with open(weights_path, 'w', encoding='utf-8') as f:
            weight_data = [            {
                'domain': item['domain'],
                'topdomain': item['topdomain'],
                'pc_br': item['pc_br'],
                'm_br': item['m_br']
            } for item in br_list]
            json.dump(weight_data, f, ensure_ascii=False, indent=2)

        # IPC查询
        self.update_progress(66, "正在查询IPC备案信息...")
        ipc = IPC_Search(br_list, self.log_ipc, self.stop_event)
        ipc.progress_callback = lambda v: self.update_progress(66 + v * 0.24)
        ipc_list = ipc.main()

        # 保存IPC数据
        ipc_path = os.path.join(output_dir, 'IPC.json')
        with open(ipc_path, 'w', encoding='utf-8') as f:
            json.dump(ipc_list, f, ensure_ascii=False, indent=2)

        # ERP查询
        if ipc_list:
            self.update_progress(90, "正在查询企业资产信息...")
            erp = ERP_Search(ipc_list, self.data_dir, self.log_erp, self.stop_event)  # 传入data_dir
            erp_list = erp.main(timestamp)
            self.log("企业资产查询完成")

        # 保存其他文件
        domain_path = os.path.join(output_dir, 'domain.txt')
        with open(domain_path, 'w') as f:
            for i in ipc_list:
                f.write(i['domain'] + '\n')

        ipc_url_path = os.path.join(output_dir, 'IPC_url.txt')
        with open(ipc_url_path, 'w') as f:
            for i in ipc_list:
                f.write(i['subdomain'] + '\n')

        self.update_progress(100, "正在保存结果...")
        self.log(f"结果已保存到: {output_dir}")
        self.refresh_file_tree()

    def start_process(self):
        try:
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            self.weight_text.config(state=tk.NORMAL)
            self.weight_text.delete(1.0, tk.END)
            self.ipc_text.config(state=tk.NORMAL)
            self.ipc_text.delete(1.0, tk.END)
            self.erp_text.config(state=tk.NORMAL)
            self.erp_text.delete(1.0, tk.END)
            self.stop_event.clear()

            grammar = self.query_entry.get()
            num = int(self.num_spin.get())

            if not grammar:
                messagebox.showwarning("警告", "请输入查询语法！")
                return

            # 在单独线程中执行
            self.worker_thread = threading.Thread(
                target=self.run_scan_task,
                args=(grammar, num),
                daemon=True
            )
            self.worker_thread.start()

        except Exception as e:
            self.log(f"启动失败: {str(e)}")
            self.reset_ui_state()

    def run_scan_task(self, grammar, num):
        try:
            ip_list = self.fofa_search(grammar, num)

            if self.stop_event.is_set():
                return

            domain_dic_list = self.domain_filtration(ip_list)

            if self.stop_event.is_set():
                return

            br_list = self.get_baidu_rank(domain_dic_list)

            if self.stop_event.is_set():
                return

            self.save_results(br_list)

            self.update_progress(100, "采集任务完成！")

        except Exception as e:
            error_msg = str(e)
            self.root.after(0, lambda: self.log(f"发生错误: {error_msg}"))
            self.root.after(0, lambda: messagebox.showerror("错误", error_msg))
        finally:
            self.root.after(0, self.reset_ui_state)

    def stop_process(self):
        self.stop_event.set()
        self.log("正在停止当前任务...")
        self.stop_btn.config(state=tk.DISABLED)

    def reset_ui_state(self):
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.progress['value'] = 0
        self.progress_label.config(text="进度: 0%")
        self.weight_text.config(state=tk.DISABLED)
        self.ipc_text.config(state=tk.DISABLED)
        self.erp_text.config(state=tk.DISABLED)
        self.status_label.config(text="就绪")

    def on_close(self):
        self.stop_event.set()
        if self.worker_thread and self.worker_thread.is_alive():
            self.worker_thread.join(timeout=1)
        self.root.destroy()

    def save_fofa_config(self):
        email = self.fofa_email_entry.get()
        api_key = self.fofa_api_key_entry.get()
        self.config['FOFA'] = {'email': email, 'api_key': api_key}
        with open(CONFIG_FILE, 'w', encoding='utf-8') as configfile:
            self.config.write(configfile)
        messagebox.showinfo("提示", "FOFA配置已保存")

    def open_github(self, event):
        github_url = "https://github.com/star-zeddm/DomainRadar_FOFA/"
        webbrowser.open(github_url)
        self.log(f"打开GitHub地址: {github_url}")
if __name__ == '__main__':
    root = tk.Tk()
    app = FOFACollectorApp(root)
    root.mainloop()