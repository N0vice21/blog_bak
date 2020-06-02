---
title: GKCTF2020 write up
date: 2020-05-24 23:53:36
tags: CTF
---
GK可太难了，连着两天打比赛，今天的打不动了  
我隐约记得当时宣传的时候说的是新生赛  
防灾的师傅们就是这样对新生的？  
pwn一个都做不出，被迫做misc  
# Reverse    
## Check_1n  
签到题  
打开长这样  
![](1.png)
开机让输入密码，  
用IDA打开找密码  
![](2.png)
![](3.png)
![](4.png)
![](5.png)
输进去  
![](6.png)
选择打砖块  
等他结束  
![](7.png)
flag就出来🌶  
# Misc  
## Pokémon  
直接玩游戏就好了，走到103号街就看到了  
图我都懒得找了，拿一张别人的图  
![](8.png)
# Crypto  
听说密码学是个小姐姐出的，比较简单  
## 小学生的密码学  
长这样
![](9.png)
仿射密码  
直接网上搜个脚本跑了  
```python  
#coding=utf-8
#仿射密码解密
#改进欧几里得算法求线性方程的x与y
def get(a, b):
    if b == 0:
        return 1, 0
    else:
        k = a //b
        remainder = a % b
        x1, y1 = get(b, remainder)
        x, y =y1, x1 - k * y1
    return x, y
 
s = input("请输入解密字符：").upper()
a = int(input("请输入a："))
b = int(input("请输入b："))
 
#求a关于26的乘法逆元
x, y = get(a, 26)
a1 = x % 26
 
l= len(s)
for i in range(l):
    cipher = a1 * (ord(s[i])- 65 - b) % 26
    res=chr(cipher + 65)
    print(res, end='')
```  
弄出来长这样  
![](10.png)
base64加密一下就彳亍  
## 汉字的秘密  
打开是个docx  
![](11.png)
都啥玩意儿  
Google搜一下发现是当铺加密  
解出来之后，ASCII码依次加1,2,3,4……完了之后长这样  
![](12.png)
python里chr一个个转了就是flag🌶  
</br>
这次比赛，可能是因为前一天搞了DASCTF，也有很大一部分原因是因为我菜，所以一个pwn都没弄出来  
后续有空复现吧，最近实在没时间了  