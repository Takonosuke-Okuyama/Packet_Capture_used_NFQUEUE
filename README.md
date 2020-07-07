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

### iptablesにルール（PCに入ってくるパケット監視）追加
```
# iptables -A INPUT -j NFQUEUE --queue-num 1
```

### 実行
```
# ./print-queue
```
