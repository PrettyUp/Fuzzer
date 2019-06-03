import configparser
import logging
import re
import requests
import json
from common.logger import LogConfig
from common.login import GetSessionAndToken

# configparser.ConfigParser的optionxform方法返回的是名称的小写，但我们这是的名称是区分大小写的
# 所以我们需要重写其optionxform方法，直接保持名称原大小写返回
class MyConfigParser(configparser.ConfigParser):
    # python不会自己调用父类init方法，所以需要手动调用一下
    def __init__(self, defaults=None):
        configparser.ConfigParser.__init__(self, defaults=defaults)

    def optionxform(self, optionstr):
        # return optionstr.lower()
        return optionstr

class Fuzzer:
    def __init__(self, fuzz_config_file ="api.ini"):
        # 读取配置文件
        self.config = MyConfigParser()
        self.config.read(f'../apis/{fuzz_config_file}', encoding="utf-8-sig")
        self.fuzz_payload_dict = json.loads(self.config["server_info"]["fuzz_payload_dict"])
        self.proxies = json.loads(self.config["server_info"]["proxies"])

        # 设置日志格式
        log_type = self.config["server_info"]["log_type"]
        log_file_prefix = self.config["server_info"]["log_file_prefix"]
        LogConfig(log_type=log_type, log_file_prefix=log_file_prefix)

        # 设置登录URL、用户名、密码，并获取session和cookie
        # 需要根据自己系统修改登录逻辑，session和token的获取可能也要修复
        url = f'{self.config["server_info"]["server_type"]}://{self.config["server_info"]["server_ip"]}:{self.config["server_info"]["server_port"]}/#login'
        username = self.config["server_info"]["username"]
        password = self.config["server_info"]["password"]
        obj = GetSessionAndToken(url,username,password)
        sessionid = obj.get_sessionid()
        self.token = obj.get_token()
        self.fuzz_headers = {
            'Host': f'{self.config["server_info"]["server_ip"]}',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:60.0) Gecko/20100101 Firefox/60.0',
            'Accept': 'application/xml, text/xml, */*; q=0.01',
            'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
            'Accept-Encoding': 'gzip, deflate',
            'Referer': f'{self.config["server_info"]["server_type"]}://{self.config["server_info"]["server_ip"]}',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'X-Requested-With': 'XMLHttpRequest',
            'Cookie': f'Secure; sessionId={sessionid}',
            'Connection': 'close',
        }


    # 主要的遍历逻辑
    def exec_fuzz(self):
        url_pre = f'{self.config["server_info"]["server_type"]}://{self.config["server_info"]["server_ip"]}:{self.config["server_info"]["server_port"]}/'
        regexp = "fuzzer_var\([^\)]*\)"
        # 循环所有api
        for api in self.config["protocol"]:
            url = url_pre + api
            org_api_data = self.config["protocol"][f"{api}"]
            # 在开头插入token，如果自己系统token不是这么插入的则根据自己系统进行修改
            org_api_data = org_api_data.replace("""clientType="WEB">""",f"""clientType="WEB"><token>{self.token}</token>""")
            # 循环模糊测试类型
            for payload_type,payload_file in self.fuzz_payload_dict.items():
                logging.info(f"start to test {payload_type}")
                # 找出所有fuzz_var()
                fuzz_vars = re.findall(regexp, org_api_data)
                # 使用set去重使用list变回列表

                fuzz_vars = list(set(fuzz_vars))
                # 遍历所有fuzz_var()
                for fuzz_var in fuzz_vars:

                    # 对该变量循环具体测试类型的载荷
                    for fuzz_payload in open(f"../payloads/{payload_file}","r",encoding="utf-8"):
                        fuzz_payload = fuzz_payload.strip("\n")
                        # 排除空载荷情况，因为payload文件中为了方例使用了很多空行，不排除的话空载荷会反复多次进行测试
                        if fuzz_payload.strip() != "":
                            # 如果是缓冲区溢出，由于我这里payload使用"A"*10等形式，所以需要先使用eval动态执行转成最终的字符串
                            if payload_type == "overflow":
                                fuzz_payload = eval(fuzz_payload)
                            # 为了后边的空载荷不再把发送代码写一遍，所以这里独立出了一个参数复杂的发送函数，但自己一般不用修改所以还行吧
                            self.send_payload(url, org_api_data, regexp, fuzz_payload,api,payload_type,fuzz_var)
                    # 最后单独对空载荷进行测试
                    fuzz_payload = ""
                    self.send_payload(url,org_api_data, regexp, fuzz_payload,api,payload_type,fuzz_var)

    # 最终的发送函数
    def send_payload(self,url,org_api_data,regexp,fuzz_payload,api,payload_type,fuzz_var):
        # 将前遍历到的fuzz_var()修改成fuzz_var\(\),因为括号在正则中是特殊字符需要先转义才能是本身
        fuzz_var_fix = fuzz_var.replace("(", "\(").replace(")", "\)")
        # 获取当前遍历项的匹配个数
        count = re.findall(fuzz_var_fix,org_api_data).__len__()
        # 获取当前遍历项的原始值
        start_pos = re.search("\(", fuzz_var).end()
        end_pos = re.search("\)", fuzz_var).start()
        org_value = fuzz_var[start_pos:end_pos]
        # 如果匹配处不只一处
        for i in range(count):
            # 将目标位置前的匹配项都还原成原始值
            if i != 0:
                tt = re.sub(fuzz_var_fix, org_value, org_api_data,i)
                # 将目标位置替换成payload，最后的1表示只替换一次，这是关键
                tt = re.sub(fuzz_var_fix, fuzz_payload, tt,1)
            else:
                try:
                    # 如果目标项是第一个匹配，那么tt来自于org_api_data
                    tt = re.sub(fuzz_var_fix, fuzz_payload, org_api_data, 1)
                except:
                    logging.warning(f"exception occur-{api}-{payload_type}-{fuzz_var}-{fuzz_payload}")
                    continue
            # 对于剩下的所有fuzz_var\(\)，进行直接删除处理
            tt = re.sub(regexp, self.delete_var_sign, tt)
            logging.info(f"{api}-{payload_type}-{fuzz_var}-{fuzz_payload}")
            # 检测是否使用代理
            if self.config["server_info"]["use_proxy"] == "True":
                response = requests.post(url=url, headers=self.fuzz_headers, data=tt.encode('utf-8'), verify=False, proxies=self.proxies)
            else:
                response = requests.post(url=url, headers=self.fuzz_headers, data=tt.encode('utf-8'), verify=False)
            logging.info(f"{api}-{payload_type}-{fuzz_var}-{fuzz_payload}-{response.status_code}")

    # 用于删除fuzz_var\(\)，这里的\是正则中的转义
    def delete_var_sign(self,matched):
        value_org = matched.group()
        start_pos = re.search("\(",value_org).end()
        end_pos = re.search("\)",value_org).start()
        value = value_org[start_pos:end_pos]
        return value


if __name__ == "__main__":
    fuzzer = Fuzzer()
    fuzzer.exec_fuzz()
