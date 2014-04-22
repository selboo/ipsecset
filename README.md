ipsecset
========
windows自带的命令行工具netsh ipsec static add filter不支持批量添加，还会添加重复的规则进去。我用python编写了ipsecset解决了上述问题，支持批量添加，同一个列表里避免重复的规则。

为了方便使用，已编译成exe，源码和程序在下面的链接里

语法：

参数和netsh ipsec static add filter的参数是一样的,不区分大小写

必要参数：

srcaddr=(me/any/特定ip/网段)

dstaddr=（me/any/特定ip/网段）

dstport=（0/特定端口）

默认参数:

srcport=0

srcmask=255.255.255.255

dstmask=255.255.255.255

protocol=TCP

mirrored=YES

filterlist="选用规则"

description="add by script {time_now}"

批量操作：

"-"和","两种操作符，可混合使用

支持批量操作的参数：srcport,dstport,srcaddr,dstaddr

其中srcaddr和dstaddr仅最后一个段支持

列如，srcport=1000-1003,1007,1009

srcaddr=1.1.1.10-13,15

样例：

ipsecset srcport=1.1.1.1 dstport=2.2.2.2-30,31 dstport=8080 filterlist="基础规则"

ipsecset srcport=me dstport=any dstport=81-85,87

ipsecset srcport=me dstport=10.1.1.0 dstmask=255.255.255.0  dstport=6161 protocol=udp

欢迎提交bug^-^
