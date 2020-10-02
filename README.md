# Packet_Capture_used_NFQUEUE
iptablesのNFQUEUEを用いてc言語でパケットキャプチャを行う  

c言語ライブラリのlibnetfilter-queueを用いることで、c言語でNEQUEUEに送られたパケットを見ることができる。  
print()ではレイヤ3のipヘッダ, icmoヘッダと、レイヤ4のtcpヘッダ, udpヘッダの中身を表示する。  

### libnetfilter-queue-devをインストールしておく
[How to install libnetfilter-queue-dev on Ubuntu 14.04 (Trusty Tahr)](https://www.howtoinstall.co/en/ubuntu/trusty/libnetfilter-queue-dev)
```
$ sudo apt update
$ sudo apt install libnetfilter-queue-dev
```

### コンパイル
```
$ gcc print-queue.c -o print-queue -lnetfilter_queue
```

### 予想されるエラー
```
In file included from print-queue.c:8:0:
/usr/include/libnetfilter_queue/pktbuff.h:24:1: error: unknown type name ‘bool’; did you mean ‘_Bool’?
```
と出た場合は
`/usr/include/libnetfilter_queue/pktbuff.h`の
```
bool pktb_mangled(const struct pkt_buff *pktb);
```
を
```
_Bool pktb_mangled(const struct pkt_buff *pktb);
```
に変更します

### iptablesにルール（PCに入ってくるパケット監視）追加
```
# iptables -A INPUT -j NFQUEUE --queue-num 1
```

### 実行
```
# ./print-queue
```
