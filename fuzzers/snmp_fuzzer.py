import binascii
import logging
from scapy.all import *
from common.logger import LogConfig

class SnmpFuzzer():
    def __init__(self):
        # snmp模糊测试的主要配置项
        # target_ip--snmp服务主机ip地址
        # target_port--snmp服务端口
        # snmp_hex_string--snmp应用层数据的十六进制字符串，我随便从一个snmp数据包截这来的
        # log_type--日志类型，console将日志打印到控制台，file将日志写入到文件
        # log_file_prefix--日志文件前辍，console时不生效
        self.config = {
            "target_ip":"10.10.6.98",
            "target_port":161,
            "snmp_hex_string":"302202010104067075626c6963a01502047c07ac6c0201000201003007300506012b0500",
            'log_type': 'console',
            'log_file_prefix': 'snmp'
        }
        # 设置日志格式
        LogConfig(log_type=self.config["log_type"], log_file_prefix=self.config["log_file_prefix"])

    def fuzzSnmp(self):
        snmp_hex_string_lenght = self.config["snmp_hex_string"].__len__()
        # 遍历每个字节
        for index in range(int(snmp_hex_string_lenght/2)):
            # 每个字节遍历0-255
            for value in range(0xff):
                # 遍历字节之前的部分
                snmp_hex_string_payload_pre = binascii.a2b_hex(self.config["snmp_hex_string"][0:index*2])
                # 当前遍历到的字节
                value_hex = value.to_bytes(1,"big")
                # 遍历字节之后的部分
                snmp_hex_string_payload_post = binascii.a2b_hex(self.config["snmp_hex_string"][index*2+2:])
                # 构造snmp应用层数据
                snmp_hex_string_payload = snmp_hex_string_payload_pre + value_hex + snmp_hex_string_payload_post
                # 构造最终要发送的snmp数据包
                udp_packet = IP(dst=self.config["target_ip"])/UDP(sport=9876,dport=self.config["target_port"])/snmp_hex_string_payload
                # 发送数据包并接收响应
                response_packet = sr1(udp_packet)
                logging.info(f"{index *2}-{value_hex}-{response_packet.show()}")


if __name__ == "__main__":
    snmp_fuzzer = SnmpFuzzer()
    snmp_fuzzer.fuzzSnmp()
