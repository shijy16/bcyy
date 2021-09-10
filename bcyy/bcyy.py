# -*- coding: utf-8 -*-
from __future__ import print_function
import requests
import json
from datetime import datetime
import sys
import base64
from Crypto.Cipher import AES
from binascii import b2a_hex
import argparse

def pkcs7padding(text):
    """
    明文使用PKCS7填充
    最终调用AES加密方法时，传入的是一个byte数组，要求是16的整数倍，因此需要对明文进行处理
    :param text: 待加密内容(明文)
    :return:
    """
    bs = AES.block_size  # 16
    length = len(text)
    bytes_length = len(bytes(text, encoding='utf-8'))
    # tips：utf-8编码时，英文占1个byte，而中文占3个byte
    padding_size = length if (bytes_length == length) else bytes_length
    padding = bs - padding_size % bs
    # tips：chr(padding)看与其它语言的约定，有的会使用'\0'
    padding_text = chr(padding) * padding
    return text + padding_text


def pkcs7unpadding(text):
    """
    处理使用PKCS7填充过的数据
    :param text: 解密后的字符串
    :return:
    """
    length = len(text)
    unpadding = ord(text[length - 1])
    return text[0:length - unpadding]


def encrypt(content):
    """
    AES加密
    key,iv使用同一个
    模式cbc
    填充pkcs7
    :param key: 密钥
    :param content: 加密内容
    :return:
    """
    key_bytes = bytes('0102030405060708', encoding='utf-8')
    cipher = AES.new(key_bytes, AES.MODE_CBC, key_bytes)
    # 处理明文
    content_padding = pkcs7padding(content)
    # 加密
    encrypt_bytes = cipher.encrypt(bytes(content_padding, encoding='utf-8'))
    # 重新编码
    return str(b2a_hex(encrypt_bytes), encoding='ascii').upper()


def decrypt(key, content):
    """
    AES解密
     key,iv使用同一个
    模式cbc
    去填充pkcs7
    :param key:
    :param content:
    :return:
    """
    key_bytes = bytes(key, encoding='utf-8')
    iv = key_bytes
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    # base64解码
    encrypt_bytes = base64.b64decode(content)
    # 解密
    decrypt_bytes = cipher.decrypt(encrypt_bytes)
    # 重新编码
    result = str(decrypt_bytes, encoding='utf-8')
    # 去除填充内容
    result = pkcs7unpadding(result)
    return result

parser = argparse.ArgumentParser()
parser.add_argument('-username', type=str, required=True, help='username')
parser.add_argument('-passwd', type=str, required=True, help='user password')
args = parser.parse_args()

username = args.username
passwd = args.passwd

session = requests.session()
now = datetime.now()
tomorrow = datetime.fromtimestamp(now.timestamp() + 60 * 60 * 24)

if now.weekday() > 5:
    # 周六和周日，不约班车
    print('周末了')
    sys.exit(0)

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36',
    'Origin': 'http://bcyy.iie.ac.cn',
    'Content-Type': 'application/json',
}
data = {
    "idserial": username,  # ARP号
    "password": passwd,  # 密码
    "method": "/mobile/login/userLoginCheck"
}
if data['idserial'] == '***':
    print('先填写ARP卡号和密码')
    sys.exit(1)
data = {
    'item': encrypt(json.dumps(data))
}
# 登录
login_resp = session.post('http://bcyy.iie.ac.cn/dataForward', json.dumps(data), headers=headers)
print(login_resp.json())
# 通过http 头部的 X-Token字段判断登录状态的
headers['X-Token'] = encrypt(login_resp.json()['data']['token'])

tickets = [
    # 益园-回龙观
    {"goodspriceFen":"0","goodsdetail":"益园-回龙观","goodsprice":"0.00","alightposition":"回龙观","boardposition":"益园(其中20:20京香发车一辆)","terminus":"回龙观","selldate":now.strftime('%Y-%m-%d'),"endtime":"21:35","goodsname":"20:35益园-回龙观","id":429,"starttime":"20:35"},
    {"goodspriceFen":"0","goodsdetail":"益园-回龙观","goodsprice":"0.00","alightposition":"回龙观","boardposition":"益园(其中21:20京香发车一辆)","terminus":"回龙观","selldate":now.strftime('%Y-%m-%d'),"endtime":"22:35","goodsname":"21:35益园-回龙观","id":479,"starttime":"21:35"},
    # 回龙观-益园
    {"goodspriceFen":"0","goodsdetail":"回龙观-益园","goodsprice":"0.00","alightposition":"益园(第一辆经过京香)","boardposition":"回龙观","terminus":"益园","selldate":now.strftime('%Y-%m-%d'),"endtime":"09:00","goodsname":"08:00回龙观-益园","id":329,"starttime":"08:00"},
    {"goodspriceFen":"0","goodsdetail":"回龙观-益园","goodsprice":"0.00","alightposition":"益园（其中一辆经过京香）","boardposition":"回龙观","terminus":"益园","selldate":now.strftime('%Y-%m-%d'),"endtime":"08:30","goodsname":"07:30回龙观-益园","id":279,"starttime":"07:30"},

    # 到总部基地的车
    {"goodspriceFen": "0", "goodsdetail": "总部基地-益园", "goodsprice": "0.00", "alightposition": "益园（其中1辆至京香）",
     "boardposition": "总部基地", "terminus": "益园", "selldate": now.strftime('%Y-%m-%d'), "endtime": "08:00",
     "goodsname": "7:30总部基地-益园", "id": 13, "starttime": "07:30"},
    {"goodspriceFen": "0", "goodsdetail": "总部基地-益园", "goodsprice": "0.00", "alightposition": "益园（其中1辆至京香）",
     "boardposition": "总部基地", "terminus": "益园", "selldate": now.strftime('%Y-%m-%d'), "endtime": "08:45",
     "goodsname": "8:00总部基地-益园", "id": 15, "starttime": "08:00"},
    {"goodspriceFen": "0", "goodsdetail": "益园-总部基地", "goodsprice": "0.00", "alightposition": "总部基地",
     "boardposition": "益园（其中17:00京香发车1辆）", "terminus": "总部基地", "selldate": now.strftime('%Y-%m-%d'), "endtime": "18:00",
     "goodsname": "17:15益园-总部基地", "id": 16, "starttime": "17:15"},
    {"goodspriceFen": "0", "goodsdetail": "益园-总部基地", "goodsprice": "0.00", "alightposition": "总部基地",
     "boardposition": "益园（其中20:00京香发车1辆）", "terminus": "总部基地", "selldate": now.strftime('%Y-%m-%d'), "endtime": "21:00",
     "goodsname": "20:15益园-总部基地", "id": 14, "starttime": "20:15"},
    {"goodspriceFen": "0", "goodsdetail": "益园-总部基地", "goodsprice": "0.00", "alightposition": "总部基地",
     "boardposition": "益园（其中21:15京香发车一辆）", "terminus": "总部基地", "selldate": now.strftime('%Y-%m-%d'), "endtime": "22:00",
     "goodsname": "21:30益园-总部基地", "id": 22, "starttime": "21:30"},

    # 到张仪村的车
    {"goodspriceFen": "0", "goodsdetail": "张仪村-益园", "goodsprice": "0.00", "alightposition": "益园（其中1辆至京香）",
     "boardposition": "张仪", "terminus": "益园", "selldate": now.strftime('%Y-%m-%d'), "endtime": "08:30",
     "goodsname": "8:00张仪村-益园", "id": 20, "starttime": "08:00"},
    {"goodspriceFen": "0", "goodsdetail": "益园-张仪村", "goodsprice": "0.00", "alightposition": "张仪村",
     "boardposition": "益园（其中17:15京香发车1辆）", "terminus": "张仪村", "selldate": now.strftime('%Y-%m-%d'), "endtime": "18:00",
     "goodsname": "17:30益园-张仪村", "id": 30, "starttime": "17:30"},
    {"goodspriceFen": "0", "goodsdetail": "益园-张仪村", "goodsprice": "0.00", "alightposition": "张仪村",
     "boardposition": "益园（其中20:15京香发车1辆）", "terminus": "张仪村", "selldate": now.strftime('%Y-%m-%d'), "endtime": "21:00",
     "goodsname": "20:30益园-张仪村", "id": 31, "starttime": "20:30"},
    {"goodspriceFen": "0", "goodsdetail": "益园-张仪村", "goodsprice": "0.00", "alightposition": "张仪村",
     "boardposition": "益园（其中21:30京香发车1辆）", "terminus": "张仪村", "selldate": now.strftime('%Y-%m-%d'), "endtime": "22:00",
     "goodsname": "21:45益园-张仪村", "id": 32, "starttime": "21:45"},

    # 到叠翠的车
    {"goodspriceFen": "0", "goodsdetail": "叠翠-益园", "goodsprice": "0.00", "alightposition": "益园（其中1辆至京香）",
     "boardposition": "叠翠", "terminus": "益园", "selldate": now.strftime('%Y-%m-%d'), "endtime": "08:25",
     "goodsname": "8:00叠翠-益园", "id": 23, "starttime": "08:00"},
    {"goodspriceFen": "0", "goodsdetail": "益园-叠翠", "goodsprice": "0.00", "alightposition": "叠翠",
     "boardposition": "益园（其中17:30京香发车1辆）", "terminus": "叠翠", "selldate": now.strftime('%Y-%m-%d'), "endtime": "18:15",
     "goodsname": "17:45益园-叠翠", "id": 34, "starttime": "17:45"},
    {"goodspriceFen": "0", "goodsdetail": "益园-叠翠", "goodsprice": "0.00", "alightposition": "叠翠",
     "boardposition": "益园（其中20:30京香发车1辆）", "terminus": "叠翠", "selldate": now.strftime('%Y-%m-%d'), "endtime": "21:15",
     "goodsname": "20:45益园-叠翠", "id": 35, "starttime": "20:45"},
    {"goodspriceFen": "0", "goodsdetail": "益园-叠翠", "goodsprice": "0.00", "alightposition": "叠翠",
     "boardposition": "益园（其中21:45京香发车1辆）", "terminus": "叠翠", "selldate": now.strftime('%Y-%m-%d'), "endtime": "22:30",
     "goodsname": "22:00益园-叠翠", "id": 36, "starttime": "22:00"},

    # 到玉泉路的车
    {"goodspriceFen": "0", "goodsdetail": "玉泉路-益园", "goodsprice": "0.00", "alightposition": "益园（其中1辆至京香）",
     "boardposition": "玉泉路", "terminus": "益园", "selldate": now.strftime('%Y-%m-%d'), "endtime": "08:30",
     "goodsname": "8:00玉泉路-益园", "id": 18, "starttime": "08:00"},
    {"goodspriceFen": "0", "goodsdetail": "益园-玉泉路", "goodsprice": "0.00", "alightposition": "玉泉路",
     "boardposition": "益园（其中17:15京香发车1辆）", "terminus": "玉泉路", "selldate": now.strftime('%Y-%m-%d'), "endtime": "18:00",
     "goodsname": "17:30益园-玉泉路", "id": 26, "starttime": "17:30"},
    {"goodspriceFen": "0", "goodsdetail": "益园-玉泉路", "goodsprice": "0.00", "alightposition": "玉泉路",
     "boardposition": "益园（其中20:15京香发车1辆）", "terminus": "玉泉路", "selldate": now.strftime('%Y-%m-%d'), "endtime": "21:00",
     "goodsname": "20:30益园-玉泉路", "id": 27, "starttime": "20:30"},
    {"goodspriceFen": "0", "goodsdetail": "益园-玉泉路", "goodsprice": "0.00", "alightposition": "玉泉路",
     "boardposition": "益园（其中21:30京香发车1辆）", "terminus": "玉泉路", "selldate": now.strftime('%Y-%m-%d'), "endtime": "22:00",
     "goodsname": "21:45益园-玉泉路", "id": 28, "starttime": "21:45"}
]
# 约车系统对时间的限制，是在前端界面完成的
# 直接掉接口，不受时间的限制，可以约其他天的车票。
# 约车系统有一个限制
# 同一天只能有一张为出行的车票
# 如果约了早上的车，但早上的车还没发车，是不能约晚上的车的！！
# 可以每天中午约当天晚上的车和第二天早上的车
# 修改selldate 字段，可以预约其他日期的车

# 当天21.35 益园到回龙观的票
ticket_evening = tickets[1]
# 第二天8.00 回龙观到益园的票
ticket_tomorrow_morning = tickets[2]

# 修改selldate 字段，可以预约其他日期的车
#ticket_evening['selldate'] = tomorrow.strftime('%Y-%m-%d')
ticket_tomorrow_morning['selldate'] = tomorrow.strftime('%Y-%m-%d')

ticket_evening['method'] = '/mobile/pay/toPaySelf'
ticket_tomorrow_morning['method'] = '/mobile/pay/toPaySelf'
# 购票
print('当天晚上班车预约: {}'.format(ticket_evening))
print('第二天早上班车预约: {}'.format(ticket_tomorrow_morning))
ticket_evening = {
    'item': encrypt(json.dumps(ticket_evening))
}
ticket_tomorrow_morning = {
    'item': encrypt(json.dumps(ticket_tomorrow_morning))
}
ticket_resp_evening = session.post('http://bcyy.iie.ac.cn/dataForward', json.dumps(ticket_evening), headers=headers)
ticket_resp_morning = session.post('http://bcyy.iie.ac.cn/dataForward', json.dumps(ticket_tomorrow_morning), headers=headers)

print(ticket_resp_evening.json())
print(ticket_resp_morning.json())
