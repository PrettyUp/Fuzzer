import logging
import re
import socket
import hashlib
import base64
import time
from common.logger import LogConfig

config_dict = {
    'server_username': 'admin',  # RTSP用户名
    'server_password': '123456',  # RTSP用户名对应密码
    'server_ip': '10.10.6.93',  # RTSP服务器IP地址
    'server_port': 554,  # RTSP服务器使用端口
    'server_path': '/chIP=1/',  # URL中端口之后的部份，测试发现不同服务器对这部份接受的值是不一样的，也就是说自己使用时很可能得自己修改这部份的值
    'cseq': 2,  # RTSP使用的请求起始序列码，不需要改动
    'user_agent': 'LibVLC/3.0.2 (LIVE555 Streaming Media v2016.11.28)',  # 自定义请求头部
    'buffer_len': 1024,  # 用于接收服务器返回数据的缓冲区的大小
    'auth_method': 'Digest',  # RTSP使用的认证方法，Basic/Digest
    # OPTIONS/FIRST_DESCRIBE/SECOND_DESCRIBE/FIRST_SETUP/SECOND_SETUP/PLAY/GET_PARAMETER/TEARDOWN/ALL
    # 如果不是以上任何一个值那么就会一路正常请求
    'fuzz_step': 'SECOND_DESCRIBE',
    'fuzz_extern_header': False, # 是否对每个请求模糊测试额外的头部
    # 'header_normal_modify_allow': False,  # 是否允许拼接其他协议规定的请求头的总开关，请些请求头的值为正常值（大多是RFC给出的示例）
    # 'header_overload_modify_allow': False,  # 是否允许拼接其他协议规定的请求头的总开关，请些请求头的值为超长字符串
    # 'options_header_modify': True,  # OPTIONS请求中，是否允许拼接其他协议规定的请求头的开关
    # 'describe_header_modify': True,  # 第一次DESCRIBE请求中，是否允许拼接其他协议规定的请求头的开关
    # 'describe_auth_header_modify': True,  # 第二次DESCRIBE请求中，是否允许拼接其他协议规定的请求头的开关
    # 'setup_header_modify': True,  # 第一次SETUP请求中，是否允许拼接其他协议规定的请求头的开关
    # 'setup_session_header_modify': True,  # 第二次SETUP请求中，是否允许拼接其他协议规定的请求头的开关
    # 'play_header_modify': True,  # PLAY请求中，是否允许拼接其他协议规定的请求头的开关
    # 'get_parameter_header_modify': True,  # GET PARAMETER请求中，是否允许拼接其他协议规定的请求头的开关
    # 'teardown_header_modify': True  # TEARDOWN请求中，是否允许拼接其他协议规定的请求头的开关
    'log_type': 'console',
    'log_file_prefix': 'rtsp'
}


class RtspFuzzer():
    def __init__(self):
        global config_dict
        # self.socket_send = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # self.socket_send.settimeout(5)
        # self.socket_send.connect((config_dict['server_ip'], config_dict['server_port']))
        # self.config_dict = config_dict
        self.socket_send = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket_send.settimeout(5)
        self.socket_send.connect((config_dict['server_ip'], config_dict['server_port']))
        log_type = config_dict["log_type"]
        log_file_prefix = config_dict["log_file_prefix"]
        # LogConfig(log_type="file",test_protocol="tvt")
        LogConfig(log_type=log_type, log_file_prefix=log_file_prefix)
        self.regexp = "fuzzer_var\([^\)]*\)"
        self.fuzz_payload_dict = {
            "overflow": "overflow.txt",
            "format_string": "format_string.txt",
            "random_num": "random_num.txt",
            "special_char": "special_char.txt",
            "unicode": "unicode.txt",
        }
        self.uri = f"rtsp://{config_dict['server_ip']}:{config_dict['server_port']}{config_dict['server_path']}"
        pass

    # 用于Digest认证方式时生成response的值
    def gen_digest_response_value(self, uri, method, realm, nonce):
        HA1 = hashlib.md5((f"{config_dict['server_username']}:{realm }:{config_dict['server_password']}").encode()).hexdigest()
        HA2 = hashlib.md5((f"{method}:{uri}").encode()).hexdigest()
        response_value = hashlib.md5((f"{HA1}:{nonce}:{HA2}").encode()).hexdigest()
        return response_value

    # 生成options请求头部
    def gen_options_header(self):
        global config_dict
        str_options_header = (f"""OPTIONS fuzzer_var(rtsp):fuzzer_var(//)fuzzer_var({config_dict['server_ip']})fuzzer_var(:)fuzzer_var({config_dict['server_port']}){config_dict['server_path']}fuzzer_var() fuzzer_var(RTSP)/fuzzer_var(1.0)\r\n"""
                              f"""CSeq: fuzzer_var({config_dict['cseq']})\r\n"""
                              f"""User-Agent: fuzzer_var({config_dict['user_agent']})\r\n"""
                              f"""\r\n"""
                             )
        return str_options_header

    # 生成first describe请求头部
    def gen_first_describe_header(self):
        global config_dict
        str_describe_header = (f"""DESCRIBE fuzzer_var(rtsp):fuzzer_var(//)fuzzer_var({config_dict['server_ip']})fuzzer_var(:)fuzzer_var({config_dict['server_port']}){config_dict['server_path']}fuzzer_var() fuzzer_var(RTSP)/fuzzer_var(1.0)\r\n"""
                               f"""CSeq: fuzzer_var({config_dict['cseq'] + 1})\r\n"""
                               f"""User-Agent: fuzzer_var({config_dict['user_agent']})\r\n"""
                               f"""Accept: fuzzer_var(application/sdp)\r\n"""
                               f"""\r\n"""
                              )
        return str_describe_header

    # 生成second describe请求头部
    def gen_second_describe_header(self, realm, nonce):
        global config_dict
        method = 'DESCRIBE'
        str_describe_auth_header = (f"""{method} rtsp://{config_dict['server_ip']}:{config_dict['server_port']}{config_dict['server_path']} RTSP/1.0\r\n"""
                                    f"""CSeq: fuzzer_var({config_dict['cseq'] + 2})\r\n""")
        if config_dict['auth_method'] == 'Basic':
            auth_64 = base64.b64encode((f"{config_dict['server_username']}:{config_dict['server_password']}").encode("utf-8")).decode()
            str_describe_auth_header += f"""Authorization: fuzzer_var(Basic) fuzzer_var({auth_64})\r\n"""
        else:
            response_value = self.gen_digest_response_value(self.uri, method, realm, nonce)
            str_describe_auth_header += f"""Authorization: Digest username="{config_dict['server_username']}", realm="{realm}", nonce="{nonce}", uri="{self.uri}", response="{response_value}"\r\n"""
        str_describe_auth_header += (f"""User-Agent: fuzzer_var({config_dict['user_agent']})\r\n"""
                                     f"""Accept: fuzzer_var(application/sdp)\r\n"""
                                     f"""\r\n"""
                                     )
        return str_describe_auth_header

    # 生成first setup请求头部
    def gen_first_setup_header(self,realm, nonce):
        global config_dict
        method = 'SETUP'
        str_setup_header = (f"""{method} fuzzer_var(rtsp):fuzzer_var(//)fuzzer_var({config_dict['server_ip']}):fuzzer_var({config_dict['server_port']}){config_dict['server_path']}trackID=fuzzer_var(0) trackID=fuzzer_var(0) fuzzer_var(RTSP)/fuzzer_var(1.0)\r\n"""
                            f"""CSeq: {config_dict['cseq'] + 3}\r\n""")
        if config_dict['auth_method'] == 'Basic':
            auth_64 = base64.b64encode((f"{config_dict['server_username']}:{config_dict['server_password']}").encode("utf-8")).decode()
            str_setup_header += f"""Authorization: Basic fuzzer_var({auth_64})\r\n"""
        else:
            response_value = self.gen_digest_response_value(self.uri, method, realm, nonce)
            str_setup_header += f"""Authorization: Digest username="fuzzer_var({config_dict['server_username']})", realm="fuzzer_var({realm})", nonce="fuzzer_var({nonce})", uri="fuzzer_var({self.uri})", response="fuzzer_var({response_value})"\r\n"""
        str_setup_header += (f"""User-Agent: fuzzer_var({config_dict['user_agent']})\r\n"""
                             f"""Transport: fuzzer_var(RTP/AVP);fuzzer_var(unicast);client_port=fuzzer_var(50166)-50167\r\n"""
                             f"""\r\n"""
                             )
        return str_setup_header

    # 生成second setup请求头部
    def gen_second_setup_header(self, realm, nonce, session):
        global config_dict
        method = 'SETUP'
        str_setup_session_header = (f"""{method} fuzzer_var(rtsp)://fuzzer_var({config_dict['server_ip']}):fuzzer_var({config_dict['server_port']}){config_dict['server_path']}trackID=fuzzer_var(1) trackID=fuzzer_var(1) fuzzer_var(RTSP)/fuzzer_var(1.0)\r\n"""
                                    f"""CSeq: fuzzer_var({config_dict['cseq'] + 4})\r\n""")
        if config_dict['auth_method'] == 'Basic':
            auth_64 = base64.b64encode((f"{config_dict['server_username']}:{config_dict['server_password']}").encode("utf-8")).decode()
            str_setup_session_header += f"Authorization: Basic fuzzer_var({auth_64})\r\n"
        else:
            response_value = self.gen_digest_response_value(self.uri, method, realm, nonce)
            str_setup_session_header += f"""Authorization: Digest username="fuzzer_var({config_dict['server_username']})", realm="fuzzer_var({realm})", nonce="fuzzer_var({nonce})", uri="fuzzer_var({self.uri})", response="fuzzer_var({response_value})"\r\n"""
        str_setup_session_header += (f"""User-Agent: fuzzer_var({config_dict['user_agent']})\r\n"""
                                     f"""Transport: fuzzer_var(RTP/AVP);unicast;client_port=fuzzer_var(50168)-fuzzer_var(50169)\r\n"""
                                     f"""Session: fuzzer_var({session})\r\n"""
                                     f"""\r\n"""
                                     )
        return str_setup_session_header

    # 生成play请求头部
    def gen_play_header(self, realm, nonce, session):
        global config_dict
        method = 'PLAY'
        str_play_header = (f"""{method} fuzzer_var(rtsp)://fuzzer_var({config_dict['server_ip']}):fuzzer_var({config_dict['server_port']}){config_dict['server_path']} fuzzer_var(RTSP)/fuzzer_var(1.0)\r\n"""
                           f"""CSeq: fuzzer_var({config_dict['cseq'] + 5})\r\n""")
        if config_dict['auth_method'] == 'Basic':
            auth_64 = base64.b64encode((f"{config_dict['server_username']}:{config_dict['server_password']}").encode("utf-8")).decode()
            str_play_header += f"Authorization: Basic fuzzer_var({auth_64})\r\n"
        else:
            response_value = self.gen_digest_response_value(self.uri, method, realm, nonce)
            str_play_header += f"""Authorization: fuzzer_var(Digest) username="fuzzer_var({config_dict['server_username']})", realm="fuzzer_var({realm})", nonce="fuzzer_var({nonce})", uri="fuzzer_var({self.uri})", response="fuzzer_var({response_value})"\r\n"""
        str_play_header += (f"""User-Agent: fuzzer_var({config_dict['user_agent']})\r\n"""
                            f"""Session: fuzzer_var({session})\r\n"""
                            f"""Range: npt=fuzzer_var(0.000-)\r\n"""
                            f"""\r\n"""
                            )
        return str_play_header

    # 生成GET_PARAMETER请求头部
    def gen_get_parameter_header(self, realm, nonce, session):
        global config_dict
        method = 'GET_PARAMETER'
        str_get_parameter_header = (f"""{method} fuzzer_var(rtsp)://fuzzer_var({config_dict['server_ip']}):fuzzer_var({config_dict['server_port']}){config_dict['server_path']} fuzzer_var(RTSP)/fuzzer_var(1.0)\r\n"""
                                    f"""CSeq: fuzzer_var({config_dict['cseq'] + 6})\r\n""")
        if config_dict['auth_method'] == 'Basic':
            auth_64 = base64.b64encode((f"{config_dict['server_username']}:{config_dict['server_password']}").encode("utf-8")).decode()
            str_get_parameter_header += f"Authorization: Basic fuzzer_var({auth_64})\r\n"
        else:
            response_value = self.gen_digest_response_value(self.uri, method, realm, nonce)
            str_get_parameter_header += f"""Authorization: Digest username="fuzzer_var({config_dict['server_username']})", realm="fuzzer_var({realm})", nonce="fuzzer_var({nonce})", uri="fuzzer_var({self.uri})", response="fuzzer_var({response_value})"\r\n"""
        str_get_parameter_header += (f"""User-Agent: fuzzer_var({config_dict['user_agent']})\r\n"""
                                     f"""Session: fuzzer_var({session})\r\n"""
                                     f"""\r\n"""
                                     )
        return str_get_parameter_header

    # 生成teardown请求头部
    def gen_teardown_header(self, realm, nonce, session):
        global config_dict
        method = 'TEARDOWN'
        str_teardown_header = (f"""{method} fuzzer_var(rtsp)://fuzzer_var({config_dict['server_ip']}):fuzzer_var({config_dict['server_port']}){config_dict['server_path']} fuzzer_var(RTSP)/fuzzer_var(1.0)\r\n"""
                               f"""CSeq: fuzzer_var({config_dict['cseq'] + 11})\r\n""")
        if config_dict['auth_method'] == 'Basic':
            auth_64 = base64.b64encode((f"{config_dict['server_username']}:{config_dict['server_password']}").encode("utf-8")).decode()
            str_teardown_header += f"Authorization: Basic fuzzer_var({auth_64})\r\n"
        else:
            response_value = self.gen_digest_response_value(self.uri, method, realm, nonce)
            str_teardown_header += f"""Authorization: Digest username="fuzzer_var({config_dict['server_username']})", realm="fuzzer_var({realm})", nonce="fuzzer_var({nonce})", uri="fuzzer_var({self.uri})", response="fuzzer_var({response_value})"\r\n"""
        str_teardown_header += (f"""User-Agent: fuzzer_var({config_dict['user_agent']})\r\n"""
                                f"""Session: fuzzer_var({session})\r\n"""
                                f"""\r\n"""
                                )
        return str_teardown_header

    # 拼接rtsp协议的其他请求头，以测试程序对这些请求头部的处理是否有问题；这个方法与add_overload_header_according_to_protocol是互斥的
    def add_extern_protocol(self, str_header):
        str_header = str_header[0:len(str_header) - 2]
        str_header += ('Accept: fuzz_var(application/rtsl), fuzz_var(application/sdp);level=fuzz_var(-2)'
                        'Accept-Encoding: fuzz_var(gzip);q=fuzz_var(1.0), identity; q=fuzz_var(0.5), fuzz_var(*);q=fuzz_var(0)\r\n'
                        'Accept-Language: fuzz_var(da), en-gb;q=fuzz_var(0.8), en;q=fuzz_var(0.7)\r\n'
                        'Bandwidth: fuzz_var(4000) \r\n'
                        'Blocksize: fuzz_var(4000) \r\n'
                        'Cache-Control: fuzz_var(no-cache);fuzz_var(max-stale) \r\n'
                        'Conference: fuzz_var(199702170042.SAA08642@obiwan.arl.wustl.edu%20Starr) \r\n'
                        'Connection: fuzz_var(close)\r\n'
                        'Content-Base: fuzz_var(gzip)\r\n'
                        'Content-Encoding: fuzz_var(gzip)\r\n'
                        'Content-Language: fuzz_var(mi),fuzz_var(en)\r\n'
                        'Content-Length: fuzz_var(2034953454546565) \r\n'
                        'Content-Location: fuzz_var(/etc/passwd)\r\n'
                        'Content-Type: fuzz_var(text/html); charset=fuzz_var(ISO-8859-4gg)\r\n'
                        'Date: fuzz_var(Tue, 15 Nov 1995x 08:12:31 GMT)\r\n'
                        'Expires: fuzz_var(Thu, 01 Dec 1994 16:00:00 GMT) \r\n'
                        'From: fuzz_var(webmaster@w3.org)\r\n'
                        'If-Modified-Since: fuzz_var(Sat, 29 Oct 1994 19:43:31 GMT) \r\n'
                        'Last-Modified: fuzz_var(Tue, 15 Nov 1994 12:45:26 GMT)\r\n'
                        'Proxy-Require: fuzz_var(funky-feature)\r\n'
                        'Referer: fuzz_var(http://www.w3.org/hypertext/DataSources/Overview.html)\r\n'
                        'Require: fuzz_var(funky-feature) \r\n'
                        'Scale: fuzz_var(-3.5) \r\n'
                        'Speed: fuzz_var(2.5) \r\n'
                        'Transport: fuzz_var(RTP/AVP);fuzz_var(unicast);fuzz_var(client_port=3456-3457);mode="fuzz_var(PLAY)" \r\n'
                        'Via: fuzz_var(1.0 fred), fuzz_var(1.1 nowhere.com) (Apache/1.1)\r\n'
                        'Range: npt=fuzz_var(2)\r\n'
                        '\r\n'
                       )
        return str_header

    def delete_var_sign(self,matched):
        value_org = matched.group()
        start_pos = re.search("\(",value_org).end()
        end_pos = re.search("\)",value_org).start()
        value = value_org[start_pos:end_pos]
        return value

    # 从服务器返回结果中提取出realm值
    def extract_realm_value(self,msg_recv):
        realm_pos = msg_recv.find('realm')
        realm_value_begin_pos = msg_recv.find('"', realm_pos) + 1
        realm_value_end_pos = msg_recv.find('"', realm_pos + 8)
        realm_value = msg_recv[realm_value_begin_pos:realm_value_end_pos]
        return realm_value

    # 从服务器返回结果中提取出nonce值
    def extract_nonce_value(self,msg_recv):
        nonce_pos = msg_recv.find('nonce')
        nonce_value_begin_pos = msg_recv.find('"', nonce_pos) + 1
        nonce_value_end_pos = msg_recv.find('"', nonce_pos + 8)
        nonce_value = msg_recv[nonce_value_begin_pos:nonce_value_end_pos]
        return nonce_value

    # 从服务器返回结果中提取出session值
    def extract_session_value(self,msg_recv):
        session_pos = msg_recv.find('Session')
        session_value_begin_pos = msg_recv.find(' ', session_pos + 8) + 1
        session_value_end_pos = msg_recv.find(';', session_pos + 8)
        session_value = msg_recv[session_value_begin_pos:session_value_end_pos]
        return session_value

    # fuzz的真正发包函数，被traverse_fuzz_var()调用
    def send_payload(self, org_step_header, fuzz_payload, step, payload_type, fuzz_var):
        # 将当前被遍历的fuzz_var()改为fuzz_var\(\)以和其他未遍历的fuzz_var()区分
        fuzz_var_fix = fuzz_var.replace("(", "\(").replace(")", "\)")
        count = re.findall(fuzz_var_fix, org_step_header).__len__()
        # 获取当前遍历项的原始值
        start_pos = re.search("\(", fuzz_var).end()
        end_pos = re.search("\)", fuzz_var).start()
        org_value = fuzz_var[start_pos:end_pos]

        # 先将当前遍历的fuzz_var()替换成测试载荷
        for i in range(count):
            # 将目标位置前的匹配项都还原成原始值
            if i != 0:
                tt = re.sub(fuzz_var_fix, org_value, org_step_header,i)
                # 将目标位置替换成payload，最后的1表示只替换一次，这是关键
                tt = re.sub(fuzz_var_fix, fuzz_payload, tt,1)
            else:
                try:
                    # 如果目标项是第一个匹配，那么tt来自于org_step_header
                    tt = re.sub(fuzz_var_fix, fuzz_payload, org_step_header, 1)
                except:
                    logging.warning(f"exception occur-{step}-{payload_type}-{fuzz_var}-{fuzz_payload}")
                    continue
            # 对于剩下的所有fuzz_var\(\)，进行直接删除处理
            tt = re.sub(self.regexp, self.delete_var_sign, tt)
            logging.info(f"{step}-{payload_type}-{fuzz_var}-{fuzz_payload}")

            # try:
            #     self.socket_send.send(tt.encode('utf-8'))
            # except:
            #     logging.info(f"{step}-{payload_type}-{fuzz_var}-{fuzz_payload}-{tt}")
            #     self.socket_send.connect((config_dict['server_ip'], config_dict['server_port']))
            #     self.socket_send.send(tt.encode('utf-8'))
            # 需要暂停一下，因为发现一直发送时服务端会返回continues一直让客户端发送数据不返回，最后就直接fin把连接给关了
            # 但似乎也只能延缓一下？
            time.sleep(1)
            self.socket_send.send(tt.encode('utf-8'))
            try:
                msg_recv = self.socket_send.recv(config_dict['buffer_len']).decode()
            except:
                msg_recv = "recv time out"
            msg_recv_dict = msg_recv.split('\r\n')
            logging.info(f"{step}-{payload_type}-{fuzz_var}-{fuzz_payload}-{msg_recv_dict[0]}")

    # 遍历所有要模糊测试的变量
    def traverse_fuzz_var(self, step, org_step_header):
        # 如果要模糊测试额外头部，则给传过来的头部先加上
        if config_dict["fuzz_extern_header"]:
            org_step_header = self.add_extern_protocol(org_step_header)
        for payload_type, payload_file in self.fuzz_payload_dict.items():
            logging.info(f"start to test {payload_type}")
            # payload_file_obj = open(f"{payload_file}","a",encoding="utf-8")
            # org_step_header = self.gen_options_header()
            # 全部被fuzz_var()包含的位置
            fuzz_vars = re.findall(self.regexp, org_step_header)
            # 遍历所有被fuzz_var()包含的位置
            for fuzz_var in fuzz_vars:

                # 对该变量循环具体测试类型的载荷
                for fuzz_payload in open(f"../payloads/{payload_file}", "r", encoding="utf-8"):
                    fuzz_payload = fuzz_payload.strip("\n")
                    # 排除空载荷情况
                    if fuzz_payload.strip() != "":
                        # 如果是缓冲区溢出，由于我这里payload使用"A"*10等形式，所以需要先使用eval动态执行转成最终的字符串
                        if payload_type == "overflow":
                            fuzz_payload = eval(fuzz_payload)
                        self.send_payload( org_step_header, fuzz_payload, step, payload_type, fuzz_var)
                # 最后单独对空载荷进行测试
                # 前面排除这里进行是因为载荷中为了方便使用了很多空行
                fuzz_payload = ""
                self.send_payload( org_step_header, fuzz_payload, step, payload_type, fuzz_var)

    # 正确执行OPTIONS请求
    def exec_options_step(self):
        # logging.info('now start to check options operation')
        str_options_header = self.gen_options_header()
        # 删除所有fuzz_var()标志
        str_options_header = re.sub(self.regexp, self.delete_var_sign, str_options_header)
        self.socket_send.send(str_options_header.encode())
        msg_recv = self.socket_send.recv(config_dict['buffer_len']).decode()
        if '200 OK' in msg_recv:
            logging.info('OPTIONS is ok, next first DESCRIBE')
            return msg_recv,2000
        else:
            logging.info('OPTIONS request is BAD')
            return msg_recv,4000

    # 模糊测试OPTIONS请求
    def fuzz_options_step(self):
        step = "OPTIONS"
        org_options_header = self.gen_options_header()
        self.traverse_fuzz_var(step,org_options_header)

    # 正确执行first describe请求
    def exec_first_describe_step(self):
        str_describe_header = self.gen_first_describe_header()
        str_describe_header = re.sub(self.regexp, self.delete_var_sign, str_describe_header)
        self.socket_send.send(str_describe_header.encode())
        msg_recv = self.socket_send.recv(config_dict['buffer_len']).decode()
        if msg_recv.find('401 Unauthorized') != -1:
            logging.info('first DESCRIBE is ok, next second DESCRIBE')
            return msg_recv,2000
        else:
            msg_recv_dict = msg_recv.split('\r\n')
            logging.info('first DESCRIBE occur error: ')
            logging.info(msg_recv_dict[0])
            return msg_recv,4000

    # 模糊测试first describe请求
    def fuzz_first_describe_step(self):
        step = "FIRST DESCRIBE"
        org_first_describe_header = self.gen_first_describe_header()
        self.traverse_fuzz_var(step,org_first_describe_header)

    # 正确执行second describe请求
    def exec_second_describe_step(self,realm, nonce):
        str_describe_auth_header = self.gen_second_describe_header(realm, nonce)
        str_describe_auth_header = re.sub(self.regexp, self.delete_var_sign, str_describe_auth_header)
        self.socket_send.send(str_describe_auth_header.encode())
        msg_recv = self.socket_send.recv(config_dict['buffer_len']).decode()
        if msg_recv.find('200 OK') != -1:
            logging.info('second DESCRIBE is ok, next first SETUP')
            return msg_recv,2000
        else:
            msg_recv_dict = msg_recv.split('\r\n')
            logging.info('second DESCRIBE request occur error: ')
            logging.info(msg_recv_dict[0])
            return msg_recv, 4000

    # 模糊测试second describe请求
    def fuzz_second_describe_step(self, realm, nonce):
        step = "SECOND DESCRIBE"
        org_second_describe_header = self.gen_second_describe_header(realm, nonce)
        self.traverse_fuzz_var(step,org_second_describe_header)


    # 正确执行first setup请求
    def exec_first_setup_step(self, realm, nonce):
        # logging.info('second DESCRIBE is ok, next first SETUP')
        str_setup_header = self.gen_first_setup_header(realm, nonce)
        str_setup_header = re.sub(self.regexp, self.delete_var_sign, str_setup_header)
        self.socket_send.send(str_setup_header.encode())
        msg_recv = self.socket_send.recv(config_dict['buffer_len']).decode()
        if msg_recv.find('200 OK') != -1:
            logging.info('first SETUP is ok, next second SETUP')
            return msg_recv, 2000
        else:
            msg_recv_dict = msg_recv.split('\r\n')
            logging.info('first SETUP request occur error: ')
            logging.info(msg_recv_dict[0])
            return msg_recv, 4000

    # 模糊测试first setup请求
    def fuzz_first_setup_step(self, realm, nonce):
        step = "FIRST_SETUP"
        org_first_setup_header = self.gen_first_setup_header(realm, nonce)
        self.traverse_fuzz_var(step, org_first_setup_header)

    # 正确执行second setup请求
    def exec_second_setup_step(self, realm, nonce, session):
        str_setup_session_header = self.gen_second_setup_header(realm, nonce, session)
        str_setup_session_header = re.sub(self.regexp, self.delete_var_sign, str_setup_session_header)
        self.socket_send.send(str_setup_session_header.encode())
        msg_recv = self.socket_send.recv(config_dict['buffer_len']).decode()
        if msg_recv.find('200 OK') != -1:
            logging.info('second SETUP is ok, next PLAY')
            return msg_recv, 2000
        else:
            msg_recv_dict = msg_recv.split('\r\n')
            logging.info('second SETUP request occur error: ')
            logging.info(msg_recv_dict[0])
            return msg_recv, 4000

    # 模糊测试second setup请求
    def fuzz_second_setup_step(self, realm, nonce, session):
        step = "SECOND_SETUP"
        org_second_setup_header = self.gen_second_setup_header(realm, nonce, session)
        self.traverse_fuzz_var(step, org_second_setup_header)

    # 正确执行play请求
    def exec_play_step(self, realm, nonce, session):
        str_play_header = self.gen_play_header(realm, nonce, session)
        str_play_header = re.sub(self.regexp, self.delete_var_sign, str_play_header)
        self.socket_send.send(str_play_header.encode())
        msg_recv = self.socket_send.recv(config_dict['buffer_len']).decode()
        if msg_recv.find('200 OK') != -1:
            logging.info('PLAY is ok, next GET_PARAMETER')
            return msg_recv, 2000
        else:
            msg_recv_dict = msg_recv.split('\r\n')
            logging.info('PLAY request occur error: ')
            logging.info(msg_recv_dict[0])
            return msg_recv, 4000

    # 模糊测试play请求
    def fuzz_play_step(self, realm, nonce, session):
        step = "PLAY"
        org_play_header = self.gen_play_header(realm, nonce, session)
        self.traverse_fuzz_var(step, org_play_header)

    # 正确执行get parameter请求
    def exec_get_parameter_step(self,realm, nonce, session):
        str_get_parameter_header = self.gen_get_parameter_header(realm, nonce, session)
        str_get_parameter_header = re.sub(self.regexp, self.delete_var_sign, str_get_parameter_header)
        self.socket_send.send(str_get_parameter_header.encode())
        msg_recv = self.socket_send.recv(config_dict['buffer_len']).decode()
        if msg_recv.find('200 OK') != -1:
            logging.info('GET_PARAMETER is ok, next TEARDOWN')
            return msg_recv, 2000
        else:
            msg_recv_dict = msg_recv.split('\r\n')
            logging.info('GET_PARAMETER error: ')
            logging.info(msg_recv_dict[0])
            return msg_recv, 4000

    # 模糊测试get parameter请求
    def fuzz_get_parameter_step(self,realm, nonce, session):
        step = "GET_PARAMETER"
        org_get_parameter_header = self.gen_get_parameter_header(realm, nonce, session)
        self.traverse_fuzz_var(step, org_get_parameter_header)

    # 正确执行teardown请求
    def exec_teardown_step(self,realm, nonce, session):
        str_teardown_header = self.gen_teardown_header(realm, nonce, session)
        str_teardown_header = re.sub(self.regexp, self.delete_var_sign, str_teardown_header)
        self.socket_send.send(str_teardown_header.encode())
        msg_recv = self.socket_send.recv(config_dict['buffer_len']).decode()
        if msg_recv.find('200 OK') != -1:
            logging.info('TEARDOWN is ok, next finish')
            return msg_recv, 2000
        else:
            msg_recv_dict = msg_recv.split('\r\n')
            logging.info('TEARDOWN occur error: ')
            logging.info(msg_recv_dict[0])
            return msg_recv, 4000

    # 模糊测试teardown请求
    def fuzz_teardown_step(self,realm, nonce, session):
        step = "TEARDOWN"
        org_teardown_header = self.gen_teardown_header(realm, nonce, session)
        self.traverse_fuzz_var(step, org_teardown_header)

    # 当为ALL时组织所有步骤进行模糊测试
    def exec_fuzz_rtsp(self):
        if config_dict["fuzz_step"] == "ALL":
            fuzz_steps = ["OPTIONS", "FIRST_DESCRIBE", "SECOND_DESCRIBE", "FIRST_SETUP", "SECOND_SETUP", "PLAY", "GET_PARAMETER", "TEARDOWN"]
            for fuzz_step in fuzz_steps:
                self.exec_fuzz_rtsp_flow(fuzz_step)
        else:
            fuzz_step = config_dict["fuzz_step"]
            self.exec_fuzz_rtsp_flow(fuzz_step)

    # 主要的模糊测试流程
    def exec_fuzz_rtsp_flow(self, fuzz_step):

        # 这些if是顺序性的，如果不是对该步进行模糊测试则该步要正确执行，以便服务器允许进入下一步
        # 如果要模糊测试OPTIONS请求，则模糊测试后直接退出
        if fuzz_step == "OPTIONS":
            self.fuzz_options_step()
            return True
        else:
            msg_recv,result_flag = self.exec_options_step()
        # 如果要模糊测试FIRST DESCRIBE请求，则模糊测试后直接退出
        if fuzz_step == "FIRST_DESCRIBE":
            self.fuzz_first_describe_step()
            return True
        else:
            msg_recv, result_flag = self.exec_first_describe_step()
            # 从FIRST_DESCRIBE返回结果中提取realm和nonce
            # 在RTSP中后续的请求这两个值都是不变的
            realm = self.extract_realm_value(msg_recv)
            nonce = self.extract_nonce_value(msg_recv)

        # 如果要模糊测试SECOND DESCRIBE请求，则模糊测试后直接退出
        if fuzz_step == "SECOND_DESCRIBE":
            self.fuzz_second_describe_step(realm,nonce)
            return True
        else:
            msg_recv, result_flag = self.exec_second_describe_step(realm,nonce)

        # 如果要模糊测试FIRST_SETUP请求，则模糊测试后直接退出
        if fuzz_step == "FIRST_SETUP":
            self.fuzz_first_setup_step(realm, nonce)
            return True
        else:
            msg_recv, result_flag = self.exec_first_setup_step(realm,nonce)
            # 从FIRST_SETUP返回结果中提取session
            session = self.extract_session_value(msg_recv)

        # 如果要模糊测试SECOND_SETUP请求，则模糊测试后直接退出
        if fuzz_step == "SECOND_SETUP":
            self.fuzz_second_setup_step(realm, nonce, session)
            return True
        else:
            msg_recv, result_flag = self.exec_second_setup_step(realm, nonce, session)

        # 如果要模糊测试PLAY请求，则模糊测试后直接退出
        if fuzz_step == "PLAY":
            self.fuzz_play_step(realm, nonce, session)
            return True
        else:
            self.exec_play_step(realm, nonce, session)

        # 如果要模糊测试GET_PARAMETER请求，则模糊测试后直接退出
        if fuzz_step == "GET_PARAMETER":
            self.fuzz_get_parameter_step(realm, nonce, session)
            return True
        else:
            msg_recv, result_flag = self.exec_get_parameter_step(realm, nonce, session)

        # 如果要模糊测试TEARDOWN请求，则模糊测试后直接退出
        if fuzz_step == "TEARDOWN":
            self.fuzz_teardown_step(realm, nonce, session)
            return True
        else:
            self.exec_teardown_step(realm, nonce, session)
        return True

    def __del__(self):
        self.socket_send.close()
        pass


if __name__ == '__main__':
    rtsp_client = RtspFuzzer()
    # OPTIONS/FIRST_DESCRIBE/SECOND_DESCRIBE/FIRST_SETUP/SECOND_SETUP/PLAY/GET_PARAMETER/TEARDOWN
    # step = "OPTIONS"
    rtsp_client.exec_fuzz_rtsp()
    # rtsp_client.exec_full_request()
    # rtsp_client.exec_force_request()
    # uri = "rtsp://10.10.6.93:554/chIP=1/"
    # nonce = "3a260a0da860c9b55b8dbde939962287"
    # realm = "RTSP SERVER"
    # method = "DESCRIBE"
    # result = rtsp_client.gen_digest_response_value(uri, method, realm, nonce)
    # pass