import socket
from threading import Thread
import time
import psutil
import re
import win32evtlog
import win32con
import win32evtlogutil
import win32security
import winerror
import yagmail


result = []
data = open('output_information_localhost.log', 'w', encoding="utf-8")


def scaner():
    sockfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sockfd.settimeout(0.1)
    print(f'正在检测{host}:{p}...')
    tryConn = sockfd.connect_ex((host, p))
    if not tryConn:  # 返回0表示连接成功
        result.append(p)
    else:
        sockfd.close()


if __name__ == '__main__':
    com_name = socket.getfqdn(socket.gethostname())
    ip = str(socket.gethostbyname(com_name))
    host = ip
    while True:  # 尝试对端口范围进行验证
        startPort = 1
        endPort = 600
        if startPort >= 65536 or endPort >= 65536:
            print('端口号不能大于65535')
        else:
            break
    startTime = time.time()
    threads = []  # 线程列表
    for p in range(startPort, endPort + 1):
        t = Thread(target=scaner)
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    print('端口扫描完毕，端口开放结果如下')
    result.sort()  # 排序
    for p in result:  # 打印结果
        print(f'{host}:{p}', file=data)
    endTime = time.time()  # 计时
    print(f'本次端口扫描用时{endTime-startTime}秒', file=data)
# 获取进程
print("计算机所有进程如下：", file=data)
for x in psutil.process_iter():
    print(x, file=data)
data.close()
f = open('output_information_localhost.log', 'r', encoding='utf-8')
result = open('final_result.log', 'w', encoding='utf-8')
information = f.readlines()
pattern = re.compile(r'(pid=\d+.*name=\S*\')')
pattern_port = re.compile(r'192.168.*')
pattern_white = re.compile(r'.*Registry.* | .*svchost.* | .*smss.* | .*System.*')
print('---汇总信息如下---：''\n' + '端口开放汇总：''\n', file=result)
for info in information:
    if pattern_port.findall(info):
        for port in pattern_port.findall(info):
            print(port+'\n', file=result)
print('当前所有可疑进程及对应pid：''\n', file=result)
for info in information:
    if pattern.findall(info):
        for isue in pattern.findall(info):
            if not pattern_white.findall(info):
                print(isue + '\n', file=result)

def date2sec(evt_date):
    """把格式为Tue Jun 16 22:37:00 2020时间格式换算成距离1970的秒数"""
    sec = time.mktime(time.strptime(evt_date,"%a %b %d %H:%M:%S %Y"))
    return sec

# 日志显示方式为：
flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
# 提高日志的可读性
evt_dict = {win32con.EVENTLOG_AUDIT_FAILURE: 'EVENTLOG_AUDIT_FAILURE',
                win32con.EVENTLOG_AUDIT_SUCCESS: 'EVENTLOG_AUDIT_SUCCESS',
                win32con.EVENTLOG_INFORMATION_TYPE: 'EVENTLOG_INFORMATION_TYPE',
                win32con.EVENTLOG_WARNING_TYPE: 'EVENTLOG_WARNING_TYPE',
                win32con.EVENTLOG_ERROR_TYPE: 'EVENTLOG_ERROR_TYPE'}
# 只提取安全日志（管理员权限，登录审核成功审核失败）
logtype = 'Security'
# 返回当前距离1970的秒数
begin_sec = time.time()
# 获取日志
hand = win32evtlog.OpenEventLog('localhost', logtype)
print(logtype + 'events found in the last 8 hours since now:'"\n", file=result)
try:
    events=1
    while events:
        events=win32evtlog.ReadEventLog(hand, flags, 0)
        for ev_obj in events:
            """检查日志是否为最近3day的"""
            seconds = time.time()
            the_time = ev_obj.TimeGenerated.Format() # 显示格式：# Tue Jun 16 22:37:00 2020
            if date2sec(the_time) < seconds-259200:
                break
            """时间符合八个小时以内"""
            eve_id = int(winerror.HRESULT_CODE(ev_obj.EventID))
            eve_type = str(evt_dict[ev_obj.EventType])
            msg = str(win32evtlogutil.SafeFormatMessage(ev_obj, logtype))
            if eve_id == 4624 or eve_id == 4625:
                print(eve_id, file=result)
                print("Event Date/Time: %s\n" % the_time, file=result)
                print(eve_type, file=result)
                print(msg, file=result)
except:
    print('error')

finally:
    result.close()
    com_name = socket.getfqdn(socket.gethostname()) + 'information'
    contents = ['Here is all information ']
    yag = yagmail.SMTP(user='15010102609@163.com', password='xxxxxxxxxx', host='smtp.163.com')
    yag.send('1126457628@qq.com', com_name + 'information', contents, ['final_result.log'])
