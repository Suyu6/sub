{% if request.target == "clash" or request.target == "clashr" %}

mixed-port: {{ default(global.clash.http_port, "7890") }}
allow-lan: {{ default(global.clash.allow_lan, "true") }}
mode: rule
log-level: {{ default(global.clash.log_level, "info") }}
external-controller: :9090
experimental:
  ignore-resolve-fail: true
{% if exists("request.tun") %}
  {% if request.tun == "windows" %}
script:
  engine: expr
  shortcuts:
    bilibilishit: "any(['biliapi', 'bilibili'], host contains #) and any(['-live-tracker-', 'p2p', 'pcdn', 'stun'], host contains #)"
    douyushit: (network == 'udp' or host contains 'p2p') and host contains 'douyu'
    quic: network == 'udp' and dst_port in [443]
    tailscale: network == 'udp' and dst_port in [12345]
    discord_UDP: resolve_process_name() in ['Discord.exe'] and network == 'udp'
    discord_TCP: resolve_process_name() in ['Discord.exe'] and network == 'tcp'
    Download_!=CN: resolve_process_name() in ['DownloadServer.exe', 'IDMan.exe'] and geoip(dst_ip) != 'CN'
    Mail: dst_port in [465, 993, 995] and geoip(dst_ip) != 'CN'
tun:
  enable: true
  stack: mixed
  dns-hijack:
    - any:53
  auto-route: true
  auto-detect-interface: true
  {% else %}
    {% if request.tun == "open" %}
clash-for-android:
  ui-subtitle-pattern: '[一-龥]{2,4}'
tun:
  enable: true
  stack: mixed
  dns-hijack:
    - tcp://any:53
  auto-route: false
  auto-detect-interface: false
    {% else %}
      {% if request.tun == "stash" %}
http:
  # 以 PKCS #12 编码的 CA 证书
  ca: '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'
  # 证书密码
  ca-passphrase: '3DM67UCM'

tun:
  enable: true
  stack: system
  dns-hijack:
    - tcp://any:53
  auto-route: false
  auto-detect-interface: false
      {% else %}
      {% endif %}
    {% endif %}
  {% endif %}
{% endif %}

listeners:
- name: ss-2022-in
  type: shadowsocks
  port: 8888
  listen: 0.0.0.0
  cipher: 2022-blake3-aes-128-gcm
  password: ebhPeDlnQ+ZlLBhaWzptVA==
  udp: true
- name: ss-in
  type: shadowsocks
  port: 8889
  listen: 0.0.0.0
  cipher: rc4-md5
  password: 9GP35MZ48B2AEW
  udp: true

{% if exists("request.dns") %}
  {% if request.dns == "fake" %}
dns:
  enable: true
  ipv6: false
  enhanced-mode: fake-ip
  listen: 1053
  nameserver:
    - 119.29.29.29
    - 223.5.5.5
  fallback:
    - https://sm2.doh.pub/dns-query
  fallback-filter:
    geoip: false
    ipcidr:
      - 0.0.0.0/32
  fake-ip-filter:
    - '.lan'
    - '+.local'
    - localhost.ptlogin2.qq.com
    - '+.nip.io'
    - '+.market.xiaomi.com'
    - ntp.ntsc.ac.cn
    - pool.ntp.org
    ## Windows
    - dns.msftncsi.com
    - www.msftncsi.com
    - www.msftconnecttest.com
    ## onetap
    - '+.onetap.su'
    - '+.onetap.com'
    ## neverlose
    - '+.neverlose.cc'
    - '+.neverlose.com'
    ## EO
    - '+.engineowning.com'
    - '+.engineowning.to'
    ## bgx
    - '+.bgx.gg'
    ## gamesense
    - '+.gamesense.pub'
    ## interwebz
    - '+.interwebz-cheats.com'
    ## aimware
    - '+.aimware.net'
    ## fatality
    - '+.fatality.win'
    ## legendsen
    - '+.legendsen.se'
    ## memesense
    - '+.memesense.gg'
    ## midnight
    - '+.midnight.im'
    ## primordial
    - '+.primordial.gay'
    ## pokerstars
    - '+.ps.im'
    ## 加速器
    - '+.verykuai.com'
    - '+.nn.com'
    - '+.leigod.com'
    - '+.xunyou.com'
    ## pubg
    - '+.pubg.com'
    - 'pubg1.battleye.com'
    - 'battlenet.com.cn'
    ## pve
    - '+.proxmox.com'
  nameserver-policy:
    'raw.githubusercontent.com': '8.8.8.8'
    '+.meiquankongjian.com': '8.8.8.8'
    '+.getxlx.com': '8.8.8.8'
    '+.nachoneko.shop': '8.8.8.8'
    '+.ptrecord.com': '8.8.8.8'
    '+.bing.cn': '1.1.1.1'
    '+.bing.com': '1.1.1.1'

    # > Modify Contents
    'blog.google': '119.29.29.29' # Google Blog
    'googletraveladservices.com': '119.29.29.29' # Google Flights
    'dl.google.com': '119.29.29.29' # Google Download
    'dl.l.google.com': '119.29.29.29' # Google Download
    'clientservices.googleapis.com': '119.29.29.29' # Google Chrome
    'update.googleapis.com': '119.29.29.29' # Google Update
    'translate.googleapis.com': '119.29.29.29' # Google Translate
    'fonts.googleapis.com': '119.29.29.29' # Google Fonts
    'fonts.gstatic.com': '119.29.29.29' # Google Fonts

    # > Apple
    # refer: https://support.apple.com/zh-cn/HT210060
    'networking.apple': 'https://doh.dns.apple.com/dns-query' # Apple
    '+.icloud.com': 'https://doh.dns.apple.com/dns-query' # iCloud.com

    # > 百度
    # refer: https://dudns.baidu.com/support/localdns/Address/index.html
    '+.baidu': '180.76.76.76' # 百度
    '+.baidu.com': '180.76.76.76' # 百度
    '+.bdimg.com': '180.76.76.76' # 百度 静态资源
    '+.bdstatic.com': '180.76.76.76' # 百度 静态资源
    '+.baidupcs.*': '180.76.76.76' # 百度网盘
    '+.baiduyuncdn.*': '180.76.76.76' # 百度云CDN
    '+.baiduyundns.*': '180.76.76.76' # 百度云DNS
    '+.bdydns.*': '180.76.76.76' # 百度云 DNS
    '+.bdycdn.*': '180.76.76.76' # 百度云 CDN
    '+.bdysite.com': '180.76.76.76' # 百度云 域名
    '+.bdysites.com': '180.76.76.76' # 百度云 域名
    '+.baidubce.*': '180.76.76.76' # 百度智能云
    '+.bcedns.*': '180.76.76.76' # 百度智能云 DNS
    '+.bcebos.com': '180.76.76.76' # 百度智能云 对象存储BOS
    '+.bcevod.com': '180.76.76.76' # 百度智能云 播放器服务
    '+.bceimg.com': '180.76.76.76' # 百度智能云 图片服务
    '+.bcehost.com': '180.76.76.76' # 百度智能云 主机
    '+.bcehosts.com': '180.76.76.76' # 百度智能云 主机
    'dwz.cn': '180.76.76.76' # 百度短网址

    # > 360
    # refer: https://sdns.360.net/dnsPublic.html#course
    '+.360.cn': 'https://doh.360.cn/dns-query' # 360安全中心
    '+.360safe.com': 'https://doh.360.cn/dns-query' # 360安全卫士
    '+.360kuai.com': 'https://doh.360.cn/dns-query' # 360快资讯
    '+.so.com': 'https://doh.360.cn/dns-query' # 360搜索
    '+.360webcache.com': 'https://doh.360.cn/dns-query' # 360网页快照服务
    '+.qihuapi.com': 'https://doh.360.cn/dns-query' # 奇虎api
    '+.qhimg.com': 'https://doh.360.cn/dns-query' # 360图床
    '+.qhimgs.com': 'https://doh.360.cn/dns-query' # 360图床
    '+.qhimgs?.com': 'https://doh.360.cn/dns-query' # 360图床
    '+.qhmsg.com': 'https://doh.360.cn/dns-query' # 360
    '+.qhres.com': 'https://doh.360.cn/dns-query' # 奇虎静态资源
    '+.qhres?.com': 'https://doh.360.cn/dns-query' # 奇虎静态资源
    '+.dhrest.com': 'https://doh.360.cn/dns-query' # 导航静态文件
    '+.qhupdate.com': 'https://doh.360.cn/dns-query' # 360
    '+.yunpan.cn': 'https://doh.360.cn/dns-query' # 360安全云盘
    '+.yunpan.com.cn': 'https://doh.360.cn/dns-query' # 360安全云盘
    '+.yunpan.com': 'https://doh.360.cn/dns-query' # 360安全云盘
    'urlqh.cn': 'https://doh.360.cn/dns-query' # 360短网址

    # > Bytedance
    # refer: https://www.volcengine.com/docs/6758/179060
    '+.amemv.com': '180.184.1.1' # 艾特迷
    '+.bdxiguaimg.com': '180.184.1.1' # 西瓜 图片服务
    '+.bdxiguastatic.com': '180.184.1.1' # 西瓜 静态资源
    '+.byted-static.com': '180.184.1.1' # 字节跳动 UNPKG
    '+.bytedance.*': '180.184.1.1' # 字节跳动
    '+.bytedns.net': '180.184.1.1' # 字节跳动 DNS
    '+.bytednsdoc.com': '180.184.1.1' # 字节跳动 CDN 文件存储
    '+.bytegoofy.com': '180.184.1.1' # 字节跳动 Goofy
    '+.byteimg.com': '180.184.1.1' # 字节跳动 图片服务
    '+.bytescm.com': '180.184.1.1' # 字节跳动 SCM
    '+.bytetos.com': '180.184.1.1' # 字节跳动 TOS
    '+.bytexservice.com': '180.184.1.1' # 飞书企业服务平台
    '+.douyin.com': '180.184.1.1' # 抖音
    '+.douyinpic.com': '180.184.1.1' # 抖音 静态资源
    '+.douyinstatic.com': '180.184.1.1' # 抖音 静态资源
    '+.douyinvod.com': '180.184.1.1' # 抖音 静态资源
    '+.feelgood.cn': '180.184.1.1' # FeelGood平台
    '+.feiliao.com': '180.184.1.1' # 飞聊官网
    '+.gifshow.com': '180.184.1.1' # 快手
    '+.huoshan.com': '180.184.1.1' # 火山网
    '+.huoshanzhibo.com': '180.184.1.1' # 火山直播
    '+.ibytedapm.com': '180.184.1.1' # 抖音 dapm
    '+.iesdouyin.com': '180.184.1.1' # 抖音 CDN
    '+.ixigua.com': '180.184.1.1' # 西瓜视频
    '+.kspkg.com': '180.184.1.1' # 快手
    '+.pstatp.com': '180.184.1.1' # 抖音 静态资源
    '+.snssdk.com': '180.184.1.1' # 今日头条
    '+.toutiao.com': '180.184.1.1' # 今日头条
    '+.toutiao13.com': '180.184.1.1' # 今日头条
    '+.toutiao???.???': '180.184.1.1' # 今日头条 静态资源
    '+.toutiaocloud.cn': '180.184.1.1' # 头条云
    '+.toutiaocloud.com': '180.184.1.1' # 头条云
    '+.toutiaopage.com': '180.184.1.1' # 今日头条 建站
    '+.wukong.com': '180.184.1.1' # 悟空
    '+.zijieapi.com': '180.184.1.1' # 字节跳动 API
    '+.zijieimg.com': '180.184.1.1' # 字节跳动 图片服务
    '+.zjbyte.com': '180.184.1.1' # 今日头条 网页版
    '+.zjcdn.com': '180.184.1.1' # 字节跳动 CDN

    # > BiliBili
    'upos-sz-mirrorali.bilivideo.com': 'https://dns.alidns.com/dns-query' # BiliBili upos视频服务器（阿里云）
    'upos-sz-mirrorali?.bilivideo.com': 'https://dns.alidns.com/dns-query' # BiliBili upos视频服务器（阿里云）
    'upos-sz-mirrorali??.bilivideo.com': 'https://dns.alidns.com/dns-query' # BiliBili upos视频服务器（阿里云）
    'upos-sz-mirrorbos.bilivideo.com': '180.76.76.76' # BiliBili upos视频服务器（百度云）
    'upos-sz-mirrorcos.bilivideo.com': 'https://doh.pub/dns-query' # BiliBili upos视频服务器（腾讯云）
    'upos-sz-mirrorcos?.bilivideo.com': 'https://doh.pub/dns-query' # BiliBili upos视频服务器（腾讯云）
    'upos-sz-mirrorcos??.bilivideo.com': 'https://doh.pub/dns-query' # BiliBili upos视频服务器（腾讯云）
    'upos-sz-upcdnbd??.bilivideo.com': '180.76.76.76' # BiliBili upos视频服务器（百度云）
    'upos-sz-upcdntx.bilivideo.com': 'https://doh.pub/dns-query' # BiliBili upos视频服务器（腾讯云）

    # > 🇹🇼 TWN
    # 中华电信
    '+.cht.com.tw': 'https://dns.hinet.net/dns-query' # 中华电信
    '+.hinet.net': 'https://dns.hinet.net/dns-query' # 中华电信HiNet
    '+.emome.net': 'https://dns.hinet.net/dns-query' # 中华电信emome
    # So-net
    '+.tw': 'https://dns.twnic.tw/dns-query' # TWNIC DNS
    '+.taipei': 'https://dns.twnic.tw/dns-query' # TWNIC DNS

    # > 🇺🇸 USA
    # Hurricane Electric
    '+.he.net': 'https://ordns.he.net/dns-query' # HE.net
  {% else %}
    {% if request.dns == "host" %}
dns:
  enable: true
  ipv6: false
  enhanced-mode: fake-ip
  listen: 1053
  nameserver:
    - 119.29.29.29
    - 223.5.5.5
  fallback:
    - https://doh.pub/dns-query
  fallback-filter:
    geoip: false
    ipcidr:
      - 0.0.0.0/32
  fake-ip-filter:
    - '+.*'
  nameserver-policy:
    'raw.githubusercontent.com': '8.8.8.8'
    '+.meiquankongjian.com': '8.8.8.8'
    '+.getxlx.com': '8.8.8.8'
    '+.nachoneko.shop': '8.8.8.8'
    '+.ptrecord.com': '8.8.8.8'
    '+.bing.cn': '1.1.1.1'
    '+.bing.com': '1.1.1.1'
    {% else %}
    {% endif %}
  {% endif %}
{% endif %}


{% if local.clash.new_field_name == "true" %}
proxies: ~
proxy-groups: ~
rules: ~
{% else %}
Proxy: ~
Proxy Group: ~
Rule: ~
{% endif %}

{% endif %}
{% if request.target == "surge" %}

[General]
loglevel = notify
bypass-system = true
skip-proxy = 127.0.0.1,192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,100.64.0.0/10,localhost,*.local,e.crashlytics.com,captive.apple.com,::ffff:0:0:0:0/1,::ffff:128:0:0:0/1
#DNS设置或根据自己网络情况进行相应设置
bypass-tun = 192.168.0.0/16,10.0.0.0/8,172.16.0.0/12
dns-server = 119.29.29.29,223.5.5.5

[Script]
http-request https?:\/\/.*\.iqiyi\.com\/.*authcookie= script-path=https://raw.githubusercontent.com/NobyDa/Script/master/iQIYI-DailyBonus/iQIYI.js

{% endif %}
{% if request.target == "loon" %}

[General]
#!date = 2026-5-1
# IPV6 启动与否
ip-mode = ipv4-only
ipv6-vif = off
# udp 类的 dns 服务器，用,隔开多个服务器，system 表示系统 dns
dns-server = system, 119.29.29.29, 223.5.5.5, 192.168.3.1
# DNS over HTTPS服务器，用,隔开多个服务器
# doh-server = https://223.5.5.5/resolve, https://sm2.doh.pub/dns-query
# 当 UDP 的流量规则匹配到相关节点，但该节点不支持 UDP 或未未开启 UDP 转发时使用的策略，可选 DIRECT、REJECT
udp-fallback-mode = DIRECT
# 域名拒绝规则执行的阶段
domain-reject-mode = DNS
# 在 DNS 阶段拒绝域名时采用的方式
dns-reject-mode = LoopbackIP
# 是否开启局域网代理访问(其他 IOS 手机连接的时候需要再 HTTP 代理里面去设置)
allow-wifi-access = true
# 开启局域网访问后的 http 代理端口
wifi-access-http-port = 7892
# 开启局域网访问后的 socks5 代理端口
wifi-access-socks5-port = 7893
# 测速所用的测试链接，如果策略组没有自定义测试链接就会使用这里配置的
internet-test-url = http://connectivitycheck.platform.hicloud.com/generate_204
proxy-test-url = http://www.gstatic.com/generate_204
# 节点测速时的超时秒数
test-timeout = 2
# 指定流量使用哪个网络接口进行转发
interface-mode = auto
# 禁用 stun 是否禁用 stun 协议的 udp 数据，禁用后可以有效解决 webrtc 的 ip 泄露
sni-sniffing = true
disable-stun = false
# 策略改变时候打断连接
disconnect-on-policy-change = true
# 一个节点连接失败几次后会进行节点切换，默认 3 次
switch-node-after-failure-times = 3
# 订阅资源解析器链接
resource-parser = https://raw.githubusercontent.com/sub-store-org/Sub-Store/release/sub-store-parser.loon.min.js
# 自定义 geoip 数据库的 url
geoip-url = https://raw.githubusercontent.com/misakaio/chnroutes2/master/chnroutes.mmdb
ipasn-url = https://geodata.kelee.one/GeoLite2-ASN-P3TERX.mmdb
# 配置了该参数，那么所配置的这些IP段、域名将不会转发到Loon，而是由系统处理
skip-proxy = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost, *.local, captive.apple.com, e.crashlynatics.com, www.baidu.com, yunbusiness.ccb.com, wxh.wo.cn, gate.lagou.com, www.abchina.com.cn, www.shanbay.com, login-service.mobile-bank.psbc.com, mobile-bank.psbc.com
# 配置了该参数，那么所配置的这些IP段、域名就会不交给Loon来处理，系统直接处理
bypass-tun = 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24, 192.168.0.0/16, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 239.255.255.250/32, 255.255.255.255/32
# 当切换到某一特定的WiFi下时改变Loon的流量模式，如"loon-wifi5g":DIRECT，表示在loon-wifi5g这个wifi网络下使用直连模式，"cellular":PROXY，表示在蜂窝网络下使用代理模式，"default":RULE，默认使用分流模式
{% if exists("request.who") %}
   {% if request.who == "Suyu" %}
ssid-trigger = "桃桃桃的家":PROXY,"桃桃桃的家-5":PROXY,"cellular":RULE,"default":RULE
   {% else %}
   {% endif %}
  {% endif %}
{% endif %}

[Proxy]

[Remote Proxy]
Free = https://gist.githubusercontent.com/Fvr9W/b13795c35c2ba2d3bdade1807691bc92/raw/FREE.YAML,parser-enabled = true,udp=false,fast-open=default,vmess-aead=true,skip-cert-verify=true,enabled=true,flexible-sni=true

[Remote Filter]

[Proxy Group]

Premium=select, direct, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Nex.png
Game=select, direct, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/game.png
Daily=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Daily.png
Epicgames=select, direct, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/epic.png
Blizzard=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Game.png
Garena=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Game.png
PlayStation=select, direct, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/PSN.png
Rockstar=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Game.png
SteamChina=select, direct, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/steam.png
SteamGlobal=select, direct, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/steam.png
Ubisoft=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Game.png
Xboxlive=select, direct, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Microsoft.png
Microsoft=select, direct, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Microsoft.png
Riot=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/League_of_Legends.png
Hax=select, direct, img-url=https://raw.githubusercontent.com/Suyu6/sub/master/rules/onetap.png
Other Games=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Game.png
B1gProxy=select, direct, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Global.png
Trading=select, direct, img-url=https://raw.githubusercontent.com/Suyu6/sub/master/rules/trading.png
Telegram=select, direct, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Telegram.png
Discord=select, direct, img-url=https://raw.githubusercontent.com/Suyu6/sub/master/rules/discord.png
Spotify=select, direct, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Spotify.png
Tiktok=select, direct, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/TikTok.png
Netflix=select, direct, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Netflix.png
GlobalMedia=select, direct, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Streaming.png
GlobalGameDownload=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Download.png
PrivateTracker=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Download.png
SougouInput=select, direct, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Advertising.png
Hijacking=select, direct, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Advertising.png
HK 🇭🇰=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Hong_Kong.png
FastLHK 🇭🇰=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Hong_Kong.png
NexHK 🇭🇰=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Hong_Kong.png
CnixHK 🇭🇰=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Hong_Kong.png
AutoHK 🇭🇰=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Hong_Kong.png
AutoHK1 🇭🇰=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Hong_Kong.png
AutoHK2 🇭🇰=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Hong_Kong.png
MajorHK 🇭🇰=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Hong_Kong.png
MinorHK 🇭🇰=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Hong_Kong.png
TW 🇨🇳=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/CN.png
AutoTW 🇨🇳=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/CN.png
MajorTW 🇨🇳=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/CN.png
MinorTW 🇨🇳=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/CN.png
KR 🇰🇷=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/KR.png
NexKR 🇰🇷=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/KR.png
AutoKR 🇰🇷=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/KR.png
MajorKR 🇰🇷=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/KR.png
MinorKR 🇰🇷=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/KR.png
JP 🇯🇵=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Japan.png
AutoJP 🇯🇵=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Japan.png
AutoJP1 🇯🇵=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Japan.png
AutoJP2 🇯🇵=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Japan.png
CnixJP 🇯🇵=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Japan.png
NexJP 🇯🇵=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Japan.png
MajorJP 🇯🇵=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Japan.png
MinorJP 🇯🇵=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Japan.png
SGP 🇸🇬=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Singapore.png
AutoSGP 🇸🇬=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Singapore.png
AutoSG 🇸🇬=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Singapore.png
NexSG 🇸🇬=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Singapore.png
MajorSG 🇸🇬=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Singapore.png
MinorSG 🇸🇬=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Singapore.png
SEA 🌏=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/IPLC.png
AutoSEA 🌏=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/IPLC.png
MajorSEA 🌏=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/IPLC.png
MinorSEA 🌏=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/IPLC.png
AU 🇦🇺=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/IPLC.png
AutoAU 🇦🇺=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/IPLC.png
MajorAU 🇦🇺=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/IPLC.png
MinorAU 🇦🇺=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/IPLC.png
RU 🇷🇺=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Russia.png
AutoRU 🇷🇺=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Russia.png
MajorRU 🇷🇺=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Russia.png
MinorRU 🇷🇺=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Russia.png
EU 🇪🇺=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/EU.png
AutoEU 🇪🇺=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/EU.png
MajorEU 🇪🇺=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/EU.png
MinorEU 🇪🇺=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/EU.png
CA 🇨🇦=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Canada.png
AutoCA 🇨🇦=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Canada.png
MajorCA 🇨🇦=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Canada.png
MinorCA 🇨🇦=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Canada.png
NA 🇺🇲=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/United_States.png
AutoNA 🇺🇲=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/United_States.png
AutoNA1 🇺🇲=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/United_States.png
AutoNA2 🇺🇲=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/United_States.png
FastLNA 🇺🇲=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/United_States.png
CnixNA 🇺🇲=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/United_States.png
NexNA 🇺🇲=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/United_States.png
MajorNA 🇺🇲=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/United_States.png
MinorNA 🇺🇲=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/United_States.png

ALL=select, direct, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Nex.png
NEX=select, direct, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Nex.png
TAG=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/TAG.png
CNIX=select, direct, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/CNIX.png
FastL=select, direct, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Fastlink.png
FREE=select, direct, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Team.png

[Rule]

[Remote Rule]

[Rewrite]

[Host]
# 改善 App Store下载速度
iosapps.itunes.apple.com = iosapps.itunes.apple.com.download.ks-cdn.com

[Script]


[Plugin]
#跳过部分应用代理检测
https://raw.githubusercontent.com/mieqq/mieqq/master/skip-proxy-lists.sgmodule, tag=跳过部分应用代理检测, enabled = true

# 解锁
http://script.hub/file/_start_/https://raw.githubusercontent.com/Suyu6/sub/master/rules/Unlock.qxrewrite/_end_/Unlock.plugin?type=qx-rewrite&target=loon-plugin, tag=「合集1」会员破解, enabled = true
http://script.hub/file/_start_/https://raw.githubusercontent.com/yqc007/QuantumultX/master/LightBeautyCamCrack.js/_end_/LightBeautyCamCrack.plugin?type=qx-rewrite&target=loon-plugin, tag=「轻颜相机5.2.1」会员破解, enabled = false
https://raw.githubusercontent.com/Keywos/rule/main/loon/TikTok.plugin, policy = GlobalMedia, tag=「TikTok」解锁区域, enabled = false
https://raw.githubusercontent.com/app2smile/rules/master/plugin/spotify.plugin, tag=「Spotify」解锁, enabled = true
https://raw.githubusercontent.com/NobyDa/Script/master/Surge/JS/Polarr.js, tag=「泼辣修图」解锁, enabled = true
# 功能增强
https://github.com/BiliUniverse/Enhanced/releases/latest/download/BiliBili.Enhanced.plugin, tag=自定义「哔哩哔哩粉白」主界面, enabled = true
https://github.com/BiliUniverse/Global/releases/latest/download/BiliBili.Global.plugin, tag=自动化「哔哩哔哩粉白」线路及全区搜索, enabled = true
https://github.com/BiliUniverse/Redirect/releases/latest/download/BiliBili.Redirect.plugin, tag=重定向「哔哩哔哩」线路, enabled = true
https://github.com/DualSubs/Universal/releases/latest/download/DualSubs.Universal.plugin, tag=「流媒体平台」字幕增强及双语模块, enabled = true
https://github.com/DualSubs/Spotify/releases/latest/download/DualSubs.Spotify.plugin, tag=「Spotify」歌词增强及双语模块, enabled = true
https://kelee.one/Tool/Loon/Lpx/Google.lpx, tag=「Google」重定向, enabled = false
https://kelee.one/Tool/Loon/Lpx/Block_HTTPDNS.lpx, tag=「HTTPDNS」禁止, enabled = true
https://kelee.one/Tool/Loon/Lpx/LoonGallery.lpx, policy = B1gProxy, enabled = false
https://kelee.one/Tool/Loon/Lpx/Fileball_mount.lpx, tag=「Fileball」挂载增强, enabled = false
https://kelee.one/Tool/Loon/Lpx/JD_Price.lpx, tag=「京东」比价脚本, enabled = true
https://github.com/NSRingo/WeatherKit/releases/latest/download/iRingo.WeatherKit.plugin, tag=自定义「天气Kit」功能, enabled = true
https://github.com/NSRingo/Weather/raw/main/modules/Weather.plugin, tag=自定义「天气」功能, enabled = true
https://github.com/NSRingo/LocationService/releases/latest/download/iRingo.LocationService.plugin, tag=自定义「定位服务」功能, enabled = true
https://github.com/NSRingo/Maps/releases/latest/download/iRingo.Maps.plugin, tag=自定义「地图」功能, enabled = true
https://github.com/NSRingo/Siri/releases/latest/download/iRingo.Siri.plugin, tag=自定义「Siri」功能, enabled = true
https://github.com/NSRingo/Siri/releases/latest/download/iRingo.Search.plugin, tag=自定义「聚焦搜索」功能, enabled = true
https://github.com/NSRingo/TV/releases/latest/download/iRingo.TV.plugin, tag=自定义「AppleTV」功能, enabled = true
https://github.com/NSRingo/News/releases/latest/download/iRingo.News.plugin, policy = AutoNA 🇺🇲, tag=自定义「AppleNews」功能, enabled = true
https://github.com/NSRingo/TestFlight/releases/latest/download/iRingo.TestFlight.plugin, tag=自定义「TestFlight」功能, enabled = false
https://kelee.one/Tool/Loon/Lpx/QuickSearch.lpx, tag=「QuickSearch」增强, enabled = false
https://kelee.one/Tool/Loon/Lpx/Node_detection_tool.lpx, tag=「节点」检测, enabled = true
http://script.hub/file/_start_/https://gist.githubusercontent.com/RavelloH/68ed0626dae69a1ce7c8ad6887087ea1/raw/main.snippet/_end_/main.plugin?type=qx-rewrite&target=loon-plugin&del=true&jqEnabled=truet, tag=「reddit」翻译增强, enabled = true
https://raw.githubusercontent.com/DemoJameson/Loon.Plugins/main/trakt_simplified_chinese/trakt_simplified_chinese.plugin, tag=「trakt」增强, enabled = true
https://kelee.one/Tool/Loon/Lpx/WARP_Node_Query.lpx, tag=「WARP」节点查询, enabled = false
https://kelee.one/Tool/Loon/Lpx/Weixin_external_links_unlock.lpx, tag=「微信」外链增强, enabled = true
# 去广告合集
http://script.hub/file/_start_/https://raw.githubusercontent.com/Suyu6/sub/master/rules/Remix.snippet/_end_/Remix.plugin?type=qx-rewrite&target=loon-plugin, tag=「合集1」去广告, enabled = true
https://raw.githubusercontent.com/RuCu6/Loon/main/Plugins/myblockads.plugin, tag=「合集2」去广告, enabled = false
https://kelee.one/Tool/Loon/Lpx/BlockAdvertisers.lpx, tag=「合集3」去广告, enabled = true
https://kelee.one/Tool/Loon/Lpx/Remove_ads_by_keli.lpx, tag=「合集4」去广告, enabled = true
# 去广告单独
https://kelee.one/Tool/Loon/Lpx/12306_remove_ads.lpx, tag=「12306」去广告, enabled = true
https://kelee.one/Tool/Loon/Lpx/Aiinquiry_remove_ads.lpx, tag=「爱企查」去广告, enabled = true
https://kelee.one/Tool/Loon/Lpx/Amap_remove_ads.lpx, tag=「高德地图」去广告, enabled = true
https://kelee.one/Tool/Loon/Lpx/Baidu_input_method_remove_ads.lpx, tag=「百度输入法」去广告, enabled = true
https://kelee.one/Tool/Loon/Lpx/BaiduNetDisk_remove_ads.lpx, tag=「百度网盘」去广告, enabled = true
https://kelee.one/Tool/Loon/Lpx/BaiduMap_remove_ads.lpx, tag=「百度地图IPA版」去广告, enabled = false
https://kelee.one/Tool/Loon/Lpx/Cainiao_remove_ads.lpx, tag=「菜鸟裹裹」去广告, enabled = true
https://kelee.one/Tool/Loon/Lpx/DiDi_remove_ads.lpx, tag=「滴滴出行」去广告, enabled = true
https://kelee.one/Tool/Loon/Lpx/DouBan_remove_ads.lpx, tag=「豆瓣7.76」去广告, enabled = false
https://kelee.one/Tool/Loon/Lpx/Douyu_remove_ads.lpx, tag=「斗鱼」去广告, enabled = false
https://kelee.one/Tool/Loon/Lpx/Daily_remove_ads.lpx, tag=「剑网3推栏」去广告, enabled = false
https://kelee.one/Tool/Loon/Lpx/HKDouYin_remove_ads.lpx, tag=「香港抖音」去广告, enabled = false
https://kelee.one/Tool/Loon/Lpx/FenBi_remove_ads.lpx, tag=「粉笔」去广告, enabled = true
https://kelee.one/Tool/Loon/Lpx/FlyerTea_remove_ads.lpx, tag=「飞客茶馆」去广告, enabled = true
https://kelee.one/Tool/Loon/Lpx/GaoDing_remove_ads.lpx, tag=「稿定设计」去广告, enabled = false
https://kelee.one/Tool/Loon/Lpx/DragonRead_remove_ads.lpx, tag=「番茄小说」去广告, enabled = false
https://raw.githubusercontent.com/honue/rules/master/Loon/plugin/FanQieNovel.plugin, tag=「番茄小说」去广告2, enabled = true
https://kelee.one/Tool/Loon/Lpx/Himalaya_remove_ads.lpx, tag=「喜马拉雅」去广告, enabled = true
https://kelee.one/Tool/Loon/Lpx/IThome_remove_ads.lpx, tag=「IThome」去广告, enabled = true
https://kelee.one/Tool/Loon/Lpx/Keep_remove_ads.lpx, tag=「Keep」去广告, enabled = true
https://kelee.one/Tool/Loon/Lpx/KOOK_remove_ads.lpx, tag=「Kook」去广告, enabled = true
https://kelee.one/Tool/Loon/Lpx/KuaiShou_remove_ads.lpx, tag=「快手」去广告, enabled = true
https://kelee.one/Tool/Loon/Lpx/MaFengWo_remove_ads.lpx, tag=「马蜂窝」去广告, enabled = true
https://kelee.one/Tool/Loon/Lpx/NeteaseCloudMusic_remove_ads.lpx, tag=「网易云音乐」去广告, enabled = true
https://kelee.one/Tool/Loon/Lpx/TV_Assistant_remove_ads.lpx, tag=「乐播投屏」去广告, enabled = true
https://kelee.one/Tool/Loon/Lpx/QiDian_remove_ads.lpx, tag=「起点」去广告, enabled = true
https://kelee.one/Tool/Loon/Lpx/QQMusic_remove_ads.lpx, tag=「QQ音乐」去广告, enabled = true
https://kelee.one/Tool/Loon/Lpx/RedPaper_remove_ads.lpx, tag=「小红书」去广告, enabled = true
https://kelee.one/Tool/Loon/Lpx/smzdm_remove_ads.lpx, tag=「什么值得买」去广告, enabled = true
https://kelee.one/Tool/Loon/Lpx/Tieba_remove_ads.lpx, tag=「百度贴吧」去广告, enabled = true
https://kelee.one/Tool/Loon/Lpx/Reddit_remove_ads.lpx, tag=「红迪」去广告, enabled = true
https://kelee.one/Tool/Loon/Lpx/TubeMax_remove_ads.lpx, policy = B1gProxy, tag=「TubeMax」去广告, enabled = false
https://kelee.one/Tool/Loon/Lpx/Weibo_remove_ads.lpx, tag=「微博国内版」去广告, enabled = true
https://kelee.one/Tool/Loon/Lpx/Weixin_Official_Accounts_remove_ads.lpx, tag=「微信公众号」去广告, enabled = true
https://kelee.one/Tool/Loon/Lpx/WexinMiniPrograms_Remove_ads.lpx, tag=「部分微信小程序」去广告, enabled = true
https://kelee.one/Tool/Loon/Lpx/Snowball_remove_ads.lpx, tag=「雪球」去广告, enabled = true
https://kelee.one/Tool/Loon/Lpx/Soul_remove_ads.lpx, tag=「Soul」去广告, enabled = true
https://kelee.one/Tool/Loon/Lpx/PinDuoDuo_remove_ads.lpx, tag=「拼多多」去广告, enabled = true
https://kelee.one/Tool/Loon/Lpx/XiaoHeiHe_remove_ads.lpx, tag=「小黑盒」去广告, enabled = true
https://kelee.one/Tool/Loon/Lpx/XiaomiSpeaker_remove_ads.lpx, tag=「小米音响」去广告, enabled = true
https://kelee.one/Tool/Loon/Lpx/FleaMarket_remove_ads.lpx, tag=「咸鱼」去广告, enabled = true
https://kelee.one/Tool/Loon/Lpx/YY_Voice_remove_ads.lpx, tag=「YY」去广告, enabled = true
https://kelee.one/Tool/Loon/Lpx/Zhihu_remove_ads.lpx, tag=「知乎」去广告, enabled = true
https://kelee.one/Tool/Loon/Lpx/ValorantBible_remove_ads.lpx, tag=「掌上瓦」去广告, enabled = true
https://kelee.one/Tool/Loon/Lpx/LOL_Bible_remove_ads.lpx, tag=「掌上撸」去广告, enabled = true
https://github.com/fmz200/wool_scripts/raw/main/Loon/plugin/XWebAds.plugin, tag=「X」网页版去广告, enabled = true
# 视频网站
https://kelee.one/Tool/Loon/Lpx/YouTube_remove_ads.lpx, tag=「YouTube」去广告, enabled = true
https://github.com/DualSubs/YouTube/releases/latest/download/DualSubs.YouTube.plugin, tag=「YouTube」字幕增强及双语模块, enabled = true
https://github.com/BiliUniverse/ADBlock/releases/latest/download/BiliBili.ADBlock.plugin, tag=「哔哩哔哩粉白」去广告, enabled = true
https://kelee.one/Tool/Loon/Lpx/iQiYi_Video_remove_ads.lpx, tag=「爱奇艺」去广告, enabled = true
https://kelee.one/Tool/Loon/Lpx/Tencent_Video_remove_ads.lpx, tag=「腾讯视频」去广告, enabled = true
https://kelee.one/Tool/Loon/Lpx/MangoTV_remove_ads.lpx, tag=「芒果」去广告, enabled = true
https://kelee.one/Tool/Loon/Lpx/YouKu_Video_remove_ads.lpx, tag=「优酷」去广告, enabled = true
# 签到
http://script.hub/file/_start_/https://raw.githubusercontent.com/Suyu6/sub/master/rules/GetCookie.conf/_end_/GetCookie.plugin?type=qx-rewrite&target=loon-plugin, tag=「合集」签到CK一体化, enabled = true
# 基础
https://raw.githubusercontent.com/chavyleung/scripts/master/box/rewrite/boxjs.rewrite.loon.plugin, policy = B1gProxy, tag = BoxJS, enabled = true
https://raw.githubusercontent.com/sub-store-org/Sub-Store/master/config/Loon.plugin, policy = B1gProxy, tag = SubStore, enabled = true
https://raw.githubusercontent.com/Script-Hub-Org/Script-Hub/main/modules/script-hub.loon.plugin, policy = B1gProxy, tag = ScriptHub, enabled = true

[MITM]
hostname = 
{% if exists("request.who") %}
{% if request.who == "Suyu" %}
ca-passphrase = 3DM67UCM
ca-p12 = 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
{% endif %}
{% else %}
ca-passphrase = DlerCloud
ca-p12 = MIIJKQIBAzCCCO8GCSqGSIb3DQEHAaCCCOAEggjcMIII2DCCA48GCSqGSIb3DQEHBqCCA4AwggN8AgEAMIIDdQYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQYwDgQI3fJWfZaNaxgCAggAgIIDSCr2zGhO28dMTINwrCLFUrAePu+yc98x5cpqeACRV6fgBYfamVTP705koLsh0Ex98azK5w5yTm5kVeW2kBsTN23j6sYYy8mvYzsECYzjPy6EUnTjcvAazejxofO/p5mB/ErHDGNXhS++2Q/bvMHTIDpmuvCPnjVePpiBz3E8kAV0CqW+XNWMjMVyITWEJF729LC9IxttznCISZzENzoYHMLBXJExEOnia68Mv4PezOah+Op1ZcJfXZb/f5gSmdCJKmVTDl2fKS7BCPltDgttgBFCHRbgEP2DVsWHuZnnvDoW0GgR+WAdFQnv+Rf6tZ2Y4TIg4T/ko+yLLSbUludm6Ymueb06OXWrM7bqmBR5RqrQRQkIbzDJZ7mnyzYJySp7Jt9IhTmavl3O+vH7bfWD0VmNVOI54yVFETfGq+L+crDdL2MosKMxlKnQa2DrOHVFahwocQd0S5y5I25hieODjoogGOndS08tax7BDNC6YE/H/rQ+F3Eb9kK8ec1mj/HSwvKSX6/360ftR9/f96mAQ+SFi+TF7Y6S8RBtUhy9ioJGV5adQqnHcDkYxRM/ajhPF4KCLSpSqNclZ7jRBmNi48GeDV6CmqaR9CFERzEY/5jn5cDJjskHvmB3O0v2CPZq6EiAQP8r29GBq3RoSjIQCRM0lozGedaXlfWJZq9XAoGGyICeLfLdnbOemRBEreAzhQBdhz1NUygpUU1tI9UaqYy2a8M8hUKsl/AkaMs816iIV6IXfAl5jTbj68S1zgn0pPqDYEPLpjniMAqr6iCmUv07oJJrb3Ybe3oQ+Bb3XKgTQo98s50sBYNw9mOHSTfYxGMCCQXzXUH6lGviy7AW18T0b85RUtWrRCTnH2xKqE/0m70KCkLzNjLJCPuQIkzZ5VraPGKqsWtOt+4aOfwqyY5n7bxl41C7FFlW1Xyl4QGuKOD/BCB3R0gekgXfD9fIKZdany0YhI9DWyWLvzqar0i0e/6t0DborLfLSuDZfbXI7rkcdM76ApC12Io0yo12XxZkgejYeTri3vjMbtKVYZ0R99OikMimPs+GIg5KAB79u0Mj9c3D4/eYw8NpGrlwrpko0sjlC99WZIpJe0tQlNaWKh0lGH29VDCCBUEGCSqGSIb3DQEHAaCCBTIEggUuMIIFKjCCBSYGCyqGSIb3DQEMCgECoIIE7jCCBOowHAYKKoZIhvcNAQwBAzAOBAhaEE/1daqfgQICCAAEggTIceK6BIQs8ZhGQ04mZ3BOqELL08KS3sYlGskG4EhCUawbsUI3TXFoXuJV1A9je0uWw2drTdicIK9unJJkxsvNLkJsQnORQBFyNS3XIiRbUrJka7SvF0p7fqB+eVM1jiG1CEP2sQ4uQ0BrtZZ0Aaqv7Pi33OrR/9w79K1iGWYGOD/eqp4UmIPCuFWPJ3zta9iD1lTXhl7FlDBlW6JY1/b5lRqsh2CP4W5rvXvyFoL5XjDHshFVtVC/Z/wKdI5m8zCOh6a/D94gk5qiRYGPqlAra56Sebe7b2a/iDKe2rNqL76DQj2PgeqnrVL95L8lgkDoWD0FUpTt4TwyWiK8DIEwux/MqtYJYuqxHzg1NSalNLBcDN/GDaGB3HkQ7L9Fm6eQnqQUXqJ9UrBy+UqhlnAGagoYrkUkrlzFSGE8CIvBi/L1gSND9dVzi8at5FglA2fV57Xg3McN2h/ox5C/uafFYuoBDrDtNE8J7s6zGGlWwqysuvMnmic5wiu4hHYn6Ydiw/BMfNjlnNSQjis7KDoon9yght7Gaot3Of5fgmJ+sAZSqHsZ3EcgIiEBPLjtMWY+gyOJ3HDhcc3Xobi/aIBfoYKTJR/Uox3oH4wL5iLHbF33aJBDC53Zb6/jxZow1esx+qdf+aXWhto9BPWpl/ZupOLuC5w0QPVmbIniCW3OzywxD1jK2HbNfQvDR+vTVaXCakp8B9dnHnj9I9DQYRdpQ39WmU+vt/x8tNJj31aivIg097YcgKfvfRm1bZ3xk9tKGQvxtftvmZAPN/MCRugptz7UH2QS2hjiOIpAbQHoyLpcLMEeOXokD2ITaYeZRjHe2v/BsWg5nbIb/eknFA5TJb51VJwjJJayrlT+jSvpF4RhNe6xm9I45fUPxfByDibzvAZByfXXLZRccNr0VQxBUIyaIVnqJZjcE+6e5PSc1jmK4qft6U1cwJKJTbcQUOsfW9HYP3705tm1+YN1DcdTrCzBIY6P/YeqYvtWaVoQPKHkWTmitOyvmK7+ebtB+0BU4/kgKzgkg5/Be/6ylGfkGYeKMUwe3Ir/edze55sbDaNHpj/mm2FOimNTS6BPBjjjmSwZYNEInOoVIVBVJ3Gyk9gspoZhOBfZN94+eqaCGjlmN354Sowxn4qYkpG1iU/Ta+1rNQoiGPKpKQw/P10rwss6FqC92OsPVGx0m9ba1lWW4UZKuhSkaYFfQwREt5R4ULdbToUOGVug5dq27rquGaP75E+gRAqVqmNb+oUPUW4qc8+jg3qr9AEulf0iCgTrMKirVAuqVDYTaxDgiDZNSAVZVzM43QRa7eXoX8Q16BU3T2h4Ug2H52vFC8xHARnpKgHO+5IY+Jmcu1CyDZD6sjwrSBSSWSvek+L4/8Wx8/IqyADnifA0VL5BcBIZ0TBn1+J8n72zqyf//Jo8ArsAdXZQjsMlncIj0ExJLz81s2eRurz6zSSCyryZDVp63i4odCrcQEbwtU0AvGToh+juch4JS7lQUuzFdrlmCNVTBLTMVEMUeNDd35a0Jp/n1fDnu5gYfX1JLlcDCEvVgGGXcPk5Naz2KzKCP3L8ghjTUxCNuo9qCIX+NZ0aNkRmDOzdqYbO4XIwpIjxZlVGW79CP4hiK2qjYUWEMSUwIwYJKoZIhvcNAQkVMRYEFE3xOZ+wrYQDW41V+Cj2OUJ6emEQMDEwITAJBgUrDgMCGgUABBTROXmDbpHtaAz/G0iTdJ3JDfw2DAQI59HRQ27QxqYCAggA
{% endif %}
skip-server-cert-verify = false
{% endif %}

{% if request.target == "quan" %}

[SERVER]

[SOURCE]

[BACKUP-SERVER]

[SUSPEND-SSID]

[POLICY]

[DNS]
1.1.1.1

[REWRITE]

[URL-REJECTION]

[TCP]

[GLOBAL]

[HOST]

[STATE]
STATE,AUTO

[MITM]

{% endif %}


{# 
Target : Quantumult X
Request: who (self, lulu, tira, xty, biu, leo, none)
         tf (true, false)
#}
{% if request.target == "quanx" %}
[general]
#!date = 2025-12-01 14:44:25
network_check_url=http://www.baidu.com
server_check_url=http://connectivitycheck.gstatic.com
excluded_routes=192.168.0.0/16, 193.168.0.0/24, 10.0.0.0/8, 172.16.0.0/12, 100.64.0.0/10, 17.0.0.0/8
dns_exclusion_list = +.lan, +.local, localhost.ptlogin2.qq.com, +.nip.io
resource_parser_url= https://fastly.jsdelivr.net/gh/KOP-XIAO/QuantumultX@master/Scripts/resource-parser.js
geo_location_checker=http://ip-api.com/json/?lang=zh-CN, https://raw.githubusercontent.com/KOP-XIAO/QuantumultX/master/Scripts/IP_API.js

# 指定在某个 Wi-Fi 下暂停 Quantumult X
{% if exists("request.who") %}
    {% if request.who == "Suyu" %}
running_mode_trigger=filter, filter, 桃桃桃的家:all_proxy, 桃桃桃的家-5:all_proxy
    {% else %}
    {% endif %}
  {% endif %}
{% endif %}

[dns]
no-system
no-ipv6
server=223.5.5.5
server=119.29.29.29

[policy]
static=Premium, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Nex.png
static=Game, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/game.png
static=Daily, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Daily.png
static=Blizzard, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Game.png
static=Garena, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Game.png
static=PlayStation, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/PSN.png
static=Rockstar, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Game.png
static=SteamChina, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/steam.png
static=SteamGlobal, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/steam.png
static=Ubisoft, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Game.png
static=Xboxlive, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Microsoft.png
static=Microsoft, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Microsoft.png
static=Riot, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/League_of_Legends.png
static=Hax, img-url=https://raw.githubusercontent.com/Suyu6/sub/master/rules/onetap.png
static=Other Games, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Game.png
static=B1gProxy, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Global.png
static=Trading, img-url=https://raw.githubusercontent.com/Suyu6/sub/master/rules/trading.png
static=Telegram, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Telegram.png
static=Discord, img-url=https://raw.githubusercontent.com/Suyu6/sub/master/rules/discord.png
static=Spotify, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Spotify.png
static=Netflix, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Netflix.png
static=GlobalMedia, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Streaming.png
static=GlobalGameDownload, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Download.png
static=PrivateTracker, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Download.png
static=SougouInput, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Advertising.png
static=Hijacking, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Advertising.png
static=HK 🇭🇰, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Hong_Kong.png
static=FastLHK 🇭🇰, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Hong_Kong.png
static=CnixHK 🇭🇰, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Hong_Kong.png
static=AutoHK 🇭🇰, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Hong_Kong.png
static=TW 🇨🇳, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/CN.png
static=AutoTW 🇨🇳, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/CN.png
static=KR 🇰🇷, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/KR.png
static=AutoKR 🇰🇷, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/KR.png
static=JP 🇯🇵, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Japan.png
static=AutoJP 🇯🇵, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Japan.png
static=SGP 🇸🇬, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Singapore.png
static=AutoSGP 🇸🇬, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Singapore.png
static=AutoSG 🇸🇬, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Singapore.png
static=SEA 🌏, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/IPLC.png
static=AutoSEA 🌏, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/IPLC.png
static=AU 🇦🇺, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/IPLC.png
static=AutoAU 🇦🇺, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/IPLC.png
static=RU 🇷🇺, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Russia.png
static=AutoRU 🇷🇺, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Russia.png
static=EU 🇪🇺, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/EU.png
static=AutoEU 🇪🇺, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/EU.png
static=CA 🇨🇦, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Canada.png
static=AutoCA 🇨🇦, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Canada.png
static=NA 🇺🇲, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/United_States.png
static=AutoNA 🇺🇲, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/United_States.png
static=FastLNA 🇺🇲, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/United_States.png
static=CnixNA 🇺🇲, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/United_States.png

static=NEX, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Nex.png
static=TAG, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/TAG.png
static=CNIX, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/CNIX.png
static=FastL, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Fastlink.png
static=FREE, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Team.png

[server_remote]

[filter_remote]

[rewrite_remote]
# 从下到上，重要程度
# 去广告
https://raw.githubusercontent.com/fmz200/wool_scripts/main/QuantumultX/rewrite/rewrite.snippet, tag=「合集」去广告, update-interval=172800, opt-parser=false, enabled=true
https://raw.githubusercontent.com/fmz200/wool_scripts/main/QuantumultX/rewrite/weibo.snippet, tag=「微博」去广告, update-interval=172800, opt-parser=false, enabled=true

# Cookie
https://raw.githubusercontent.com/fmz200/wool_scripts/main/QuantumultX/rewrite/cookies.snippet, tag = 「合集2」CK获取, update-interval=172800, opt-parser=false, enabled = false
https://raw.githubusercontent.com/Suyu6/sub/master/rules/GetCookie.conf, tag = 「合集1」CK获取, update-interval=172800, opt-parser=true, enabled = true

# 功能增强
https://raw.githubusercontent.com/DemoJameson/Loon.Plugins/main/trakt_simplified_chinese/trakt_simplified_chinese.snippet, tag=「trakt」增强, update-interval=172800, opt-parser=true, enabled=true
https://raw.githubusercontent.com/mw418/Loon/main/script/jd_price.js, tag=「京东」比价脚本, update-interval=172800, opt-parser=true, enabled=true
https://raw.githubusercontent.com/Orz-3/QuantumultX/master/Netflix_ratings.conf, tag=「Netflix」评分, update-interval=172800, opt-parser=false, enabled=true
https://raw.githubusercontent.com/zZPiglet/Task/master/zhihu.conf, tag=「知乎」不跳转, update-interval=86400, opt-parser=false, enabled=true
https://raw.githubusercontent.com/zZPiglet/Task/master/UnblockURLinWeChat.conf, tag=「微信」链接助手, update-interval=86400, opt-parser=false, enabled=true
https://github.com/DualSubs/Universal/releases/latest/download/DualSubs.Universal.snippet, tag=「流媒体平台」字幕增强及双语模块, update-interval=86400, opt-parser=false, enabled=true
https://github.com/DualSubs/YouTube/releases/latest/download/DualSubs.YouTube.snippet, tag=「YouTube」字幕增强及双语模块, update-interval=86400, opt-parser=false, enabled=true
https://github.com/DualSubs/Spotify/releases/latest/download/DualSubs.Spotify.snippet, tag=「Spotify」歌词增强及双语模块, update-interval=86400, opt-parser=false, enabled=true
https://github.com/NSRingo/WeatherKit/releases/latest/download/iRingo.WeatherKit.snippet, tag=自定义「天气Kit」功能, update-interval=86400, opt-parser=false, enabled=true
https://github.com/NSRingo/Weather/raw/main/modules/Weather.snippet, tag=自定义「天气」功能, update-interval=86400, opt-parser=false, enabled=true
https://github.com/NSRingo/Siri/releases/latest/download/iRingo.Siri.snippet, tag=自定义「Siri与搜索」功能, update-interval=86400, opt-parser=false, enabled=true
https://github.com/NSRingo/GeoServices/releases/latest/download/iRingo.Location.snippet, tag=自定义「定位服务」功能, update-interval=86400, opt-parser=false, enabled=false
https://github.com/NSRingo/GeoServices/releases/latest/download/iRingo.Maps.snippet, tag=自定义「地图」功能, update-interval=86400, opt-parser=false, enabled=false
https://github.com/BiliUniverse/Enhanced/releases/latest/download/BiliBili.Enhanced.snippet, tag=自定义「哔哩哔哩粉白」主界面, update-interval=172800, opt-parser=false, enabled=true
https://gist.githubusercontent.com/RavelloH/68ed0626dae69a1ce7c8ad6887087ea1/raw/main.snippet, tag=「reddit」翻译增强, update-interval=172800, opt-parser=false, enabled=true

# VIP解锁
https://raw.githubusercontent.com/Guding88/Script/main/APPheji_Guding.sgmodule, tag=「合集2」VIP解锁, update-interval=86400, opt-parser=true, enabled=true
https://raw.githubusercontent.com/Suyu6/sub/master/rules/Unlock.qxrewrite, tag=「合集1」VIP解锁, update-interval=86400, opt-parser=false, enabled=true
https://raw.githubusercontent.com/yqc007/QuantumultX/master/LightBeautyCamCrack.js, tag=「轻颜相机5.2.1」VIP解锁, update-interval=86400, opt-parser=true, enabled=true

# 基本
https://raw.githubusercontent.com/VirgilClyne/GetSomeFries/main/snippet/HTTPDNS.Block.snippet, tag=「HTTPDNS」禁止, update-interval=172800, opt-parser=false, enabled=false
https://raw.githubusercontent.com/chavyleung/scripts/master/box/rewrite/boxjs.rewrite.quanx.conf, tag = BoxJS, update-interval=172800, opt-parser=false, enabled=true
https://raw.githubusercontent.com/sub-store-org/Sub-Store/master/config/QX.snippet, tag = SubStore, update-interval=172800, opt-parser=false, enabled=true
https://raw.githubusercontent.com/Script-Hub-Org/Script-Hub/main/modules/script-hub.beta.qx.conf, tag = ScriptHub, update-interval=172800, opt-parser=false, enabled=true

[server_local]

[task_local]
# UI 交互检测
event-interaction https://raw.githubusercontent.com/KOP-XIAO/QuantumultX/master/Scripts/streaming-ui-check.js, tag=流媒体 - 解锁查询, img-url=checkmark.seal.system, enabled=true
event-interaction https://raw.githubusercontent.com/I-am-R-E/Functional-Store-Hub/Master/NodeLinkCheck/Script/NodeLinkCheck.js, tag=Env代理链路检测, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Stack.png, enabled=true

# 10000  (By @chavyleung)
42 9 * * * https://raw.githubusercontent.com/chavyleung/scripts/master/10000/10000.js, tag=10000, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Color/10000.png,enabled=true

# 10010  (By @chavyleung)
43 9 * * * https://raw.githubusercontent.com/chavyleung/scripts/master/10010/10010.js, tag=10010, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Color/10010.png,enabled=true

# 12123  (By @dompling)


# 爱思助手  (By @Crazy-Z7)
45 9 * * * https://raw.githubusercontent.com/Crazy-Z7/Task/main/Aisisign.js, tag=爱思助手全能版,img-url=https://raw.githubusercontent.com/Crazy-Z7/Task/main/Image/IMG_0917.jpeg,enabled=true

# 百度贴吧  (By @chavyleung)
# 浏览器访问一下: https://tieba.baidu.com 或者 https://tieba.baidu.com/index/
20 9 * * * https://raw.githubusercontent.com/chavyleung/scripts/master/tieba/tieba.js, tag=百度贴吧, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Color/tieba.png, enabled=true

# B站每日等级任务  (By @ClydeTime)
# 方法A：后台退出手机B站客户端的情况下, 重新打开APP进入主页
# 方法B：通过网址「https://www.bilibili.com」登录（`暂不支持Loon`）
46 9 * * * https://raw.githubusercontent.com/ClydeTime/BiliBili/main/js/BiliBiliDailyBonus.js, tag=B站每日等级任务, img-url=https://raw.githubusercontent.com/HuiDoY/Icon/main/mini/Color/bilibili.png, enabled=true

# 霸王茶姬  (By @Guding88)
# 进入微信霸王茶姬小程序 --> 积分商城 --> 积分签到 --> 签到
47 9 * * * https://gist.githubusercontent.com/Sliverkiss/4984f7f34d6df8bcdd1e13ecac4bba51/raw/bwcj.js, tag=霸王茶姬小程序签到, img-url=https://raw.githubusercontent.com/Guding88/Script/main/bawangchaji/bwcj.png, enabled=true

# 机场签到  (By @evilbutcher)
# 教程：https://github.com/evilbutcher/QuantumultX/blob/main/check_in/glados/checkin.jpeg
46 9 * * * https://raw.githubusercontent.com/evilbutcher/Quantumult_X/master/check_in/glados/checkincookie_env.js, tag=机场签到, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/CNIX.png, enabled=true

# 多看阅读  (By @chavyleung)
# `我的` > `签到任务` 等到提示获取 Cookie 成功即可
25 9 * * * https://raw.githubusercontent.com/chavyleung/scripts/master/duokan/duokan.js, tag=多看, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Color/duokan.png,enabled=true

# 飞客茶馆  (By @chavyleung)
# 打开 APP, 访问下`个人中心`
45 9 * * * https://raw.githubusercontent.com/chavyleung/scripts/master/flyertea/flyertea.js, tag=飞客茶馆, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Color/flyertea.png,enabled=true

# 途虎养车  (By @Crazy-Z7)
# 公众号：搜索途虎小程序登录
40 9 * * * https://raw.githubusercontent.com/Crazy-Z7/Task/main/Tuhyche.js, tag=途虎养车积分签到, img-url=https://raw.githubusercontent.com/Crazy-Z7/Task/main/Image/IMG_0905.jpeg, enabled=true

# 什么值得买  (By @blackmatrix7)
# 打开什么值得买APP，点击“我的”，进入右上角的签到页面，等待脚本弹出获取Cookie成功的通知即可。
41 9 * * * https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/script/smzdm/smzdm_daily.js, tag=什么值得买每日签到, img-url=https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/icon/task/smzdm.png, enabled=true

# 青龙 docker 每日自动同步 boxjs cookie  (By @dompling)
4 0 * * * https://raw.githubusercontent.com/dompling/Script/master/jd/ql_cookie_sync.js, tag=青龙同步, img-url=https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/script/magicjs/images/qinglong.png, enabled=true

# 起点  (By @MCdasheng)
20 21 * * * https://raw.githubusercontent.com/MCdasheng/QuantumultX/main/Scripts/myScripts/qidian/qidian.js, img-url=https://raw.githubusercontent.com/chxm1023/Script_X/main/icon/qidian.png, tag=起点读书, enabled=true

# i茅台自动预约  (By @FoKit)
17 9 * * * https://gist.githubusercontent.com/Fvr9W/cf76045e60e70b08912f0484f33e4717/raw/i-maotai.js, tag=i 茅台, enabled=true

# 假知轩藏书  (By @GoodNight)
# hostname = zxcstxt.com
# 将获取ck脚本保存到本地
# 登录网站，打开个人中心，若提示获取ck成功则可以使用该脚本
# 关闭获取ck脚本，防止产生不必要的mitm
0 8 * * * https://raw.githubusercontent.com/Sliverkiss/GoodNight/master/Script/zhixuan.js, tag=知轩藏书签到,img-url=https://raw.githubusercontent.com/Sliverkiss/QuantumultX/main/icon/Zxcs.png, enabled=true

# 高德地图  (By @wf021325)
# hostname = *.amap.com
# 获取Cookie方法 ，QX开重写，进入【高德地图/微信/支付宝 小程序[高德打车]，打车，福利中心】，任意一端获取成功即可3端签到
01 8 * * * https://raw.githubusercontent.com/wf021325/qx/master/task/ampDache.js, tag=高德地图打车签到, img-url=https://raw.githubusercontent.com/Sliverkiss/QuantumultX/main/icon/Gddt.png, enabled=true

# 美的 (By @wf021325)
# hostname = mvip.midea.cn
# 打开小程序->我的
02 8 * * * https://gist.githubusercontent.com/Sliverkiss/3c0239a09cbe381c572a826a5caf5621/raw/midea.js, tag=美的签到, enabled=true

# 爱奇艺  (By @Nobyda)
# Safari浏览器打开 https://m.iqiyi.com/user.html 使用密码登录, 如通知成功获取cookie则可使用该脚本.
03 8 * * * https://raw.githubusercontent.com/NobyDa/Script/master/iQIYI-DailyBonus/iQIYI.js, tag=爱奇艺签到, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Color/iQIYI.png, enabled=true

# 微博  (By @GoodHolidays)
04 8 * * * https://raw.githubusercontent.com/GoodHolidays/Scripts/master/Task/weibo.js, tag=微博签到, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Color/weibo.png, enabled=true

# 哈啰出行  (By @chavyleung)
# 打开 APP 进入签到页面: 我的 > 有哈有车 系统提示: 首次写入 哈啰出行 Token 成功
05 8 * * * https://raw.githubusercontent.com/chavyleung/scripts/master/hellobike/hellobike.js, tag=哈啰出行签到, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Color/hellbike.png, enabled=true
# 哈啰出行 奖励金签到  (By @Sliverkiss)
# 打开 APP : 我的 > 福利中心 系统提示: 获取Cookie成功
05 8 * * * https://gist.githubusercontent.com/Sliverkiss/4e0081f7b18a2cea9dbdf13545e60885/raw/hldc.js, tag=哈啰出行奖励金签到, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Color/hellbike.png, enabled=true

# 美团  (By @chavyleung)
# 打开 APP , 然后手动签到 1 次, 系统提示: 获取Cookie: 成功 (首页 > 红包签到)
06 8 * * * https://raw.githubusercontent.com/chavyleung/scripts/master/meituan/meituan.js, tag=美团签到, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Color/meituan.png, enabled=true
# 美团 买菜任务  (By @JoJoJotarou)
# 使用说明：方式1：美团APP -> 美团买菜 -> 我的 -> 买菜币 -> QX提示成功即可 （若此方式不行尝试下面2种方法）
# 使用说明：方式2：美团APP -> 美团买菜 -> 我的 -> 买菜币 -> 去使用 -> 在退回上一级，QX提示成功即可
# 使用说明：方式3：美团APP -> 美团买菜 -> 我的 -> 买菜币 -> 左滑一半做退出手势再松手（不要真的退出了）-> QX提示成功即可
07 6,8 * * * https://raw.githubusercontent.com/JoJoJotarou/myScript/master/script/meituan/mall.meituan.mallcoin.task.js, tag=美团买菜任务, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Color/meituan.png, enabled=true

# 网易云音乐  (By @chavyleung)
# 先登录: https://music.163.com/m/login 再访问: https://music.163.com/#/user/level 提示: 获取会话: 成功!
08 8 * * * https://raw.githubusercontent.com/chavyleung/scripts/master/neteasemusic/neteasemusic.cookie.js, tag=网易云音乐签到, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Color/neteasemusic.png, enabled=true

# 去哪儿  (By @chavyleung)
# 打开 APP 然后手动签到 1 次 系统提示: 获取Cookie: 成功
09 8 * * * https://raw.githubusercontent.com/chavyleung/scripts/master/qunar/qunar.js, tag=去哪儿签到, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Color/qunar.png, enabled=true

# 顺丰速运  (By @chavyleung)
# APP 我的顺丰 > 任务中心 > 去签到 提示 获取会话: 成功
10 8 * * * https://raw.githubusercontent.com/chavyleung/scripts/master/sfexpress/sfexpress.js, tag=顺丰速运签到, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Color/sfexpress.png, enabled=true

# 斗鱼鱼吧  (By @lowking)
# 打开https://yuba.douyu.com/homepage/hotwbs并登陆，打开获取cookie，刷新页面，提示获取鱼吧关注列表成功
11 8 * * * https://raw.githubusercontent.com/lowking/Scripts/master/douyu/yubaSign.js, tag=斗鱼鱼吧签到, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Color/douyu.png, enabled=true

# 阿里云任务  (By @Sliverkiss)
# 单账号&&多账号：1.将获取ck脚本拉取到本地 2.打开阿里云盘，若提示获取ck成功，则可以使用该脚本 3.获取成功后，关闭获取ck脚本，避免产生不必要的mitm
0 7,11,17 * * * https://gist.githubusercontent.com/Sliverkiss/33800a98dcd029ba09f8b6fc6f0f5162/raw/aliyun.js, tag=阿里云签到, img-url=https://raw.githubusercontent.com/fmz200/wool_scripts/main/icons/apps/AliYunDrive.png, enabled=true

# 天翼云盘签到  (By @MCdasheng)
# 我的 --> 手动签到一次
13 8 * * * https://raw.githubusercontent.com/MCdasheng/QuantumultX/main/Scripts/myScripts/ty.js, tag=天翼云盘, enabled=true

# 捷停车  (By @FoKit)
# 打开捷停车APP即可获取userId
14 8 * * * https://raw.githubusercontent.com/FoKit/Scripts/main/scripts/jparking_sign.js, tag=捷停车签到, enabled=true

# 建行生活  (By @FoKit)
# 建行生活APP -> 首页 -> 会员有礼 -> 签到
15 8 * * * https://raw.githubusercontent.com/FoKit/Scripts/main/scripts/jhsh_checkIn.js, tag=建行生活, enabled=true

# 龙湖天街  (By @leiyiyan)
# 获取 Cookie：打开龙湖天街小程序，进入 我的 - 签到赚珑珠 - 任务赚奖励 - 马上签到。
# gw2c-hw-open.longfor.com
16 8 * * * https://raw.githubusercontent.com/leiyiyan/resource/main/script/lhtj/lhtj.js, tag=龙湖天街, img-url=https://raw.githubusercontent.com/leiyiyan/resource/main/icons/lhtj.png, enabled=true

#奈雪点单签到 (By @Sliverkiss)
17 8 * * * https://gist.githubusercontent.com/Sliverkiss/4d0e9572b99530b7cb0e7298622aa2a9/raw/naixue.js, tag=奈雪点单签到, enabled=true

#蜜雪冰城签到 (By @Sliverkiss)
18 8 * * * https://gist.githubusercontent.com/Sliverkiss/865c82e42a5730bb696f6700ebb94cee/raw/mxbc.js, tag=蜜雪冰城签到, enabled=true

#夸克网盘 (By @Sliverkiss)
19 8 * * * https://gist.githubusercontent.com/Sliverkiss/1589f69e675019b0b685a57a89de9ea5/raw/quarkV2.js, tag=夸克网盘签到, enabled=true

[http_backend]

[filter_local]
Final, Other Game

[rewrite_local]

[mitm]
{% if exists("request.who") %}
{% if request.who == "Suyu" %}
passphrase = 3DM67UCM
p12 = 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
{% endif %}
passphrase = DlerCloud
p12 = MIIJKQIBAzCCCO8GCSqGSIb3DQEHAaCCCOAEggjcMIII2DCCA48GCSqGSIb3DQEHBqCCA4AwggN8AgEAMIIDdQYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQYwDgQI3fJWfZaNaxgCAggAgIIDSCr2zGhO28dMTINwrCLFUrAePu+yc98x5cpqeACRV6fgBYfamVTP705koLsh0Ex98azK5w5yTm5kVeW2kBsTN23j6sYYy8mvYzsECYzjPy6EUnTjcvAazejxofO/p5mB/ErHDGNXhS++2Q/bvMHTIDpmuvCPnjVePpiBz3E8kAV0CqW+XNWMjMVyITWEJF729LC9IxttznCISZzENzoYHMLBXJExEOnia68Mv4PezOah+Op1ZcJfXZb/f5gSmdCJKmVTDl2fKS7BCPltDgttgBFCHRbgEP2DVsWHuZnnvDoW0GgR+WAdFQnv+Rf6tZ2Y4TIg4T/ko+yLLSbUludm6Ymueb06OXWrM7bqmBR5RqrQRQkIbzDJZ7mnyzYJySp7Jt9IhTmavl3O+vH7bfWD0VmNVOI54yVFETfGq+L+crDdL2MosKMxlKnQa2DrOHVFahwocQd0S5y5I25hieODjoogGOndS08tax7BDNC6YE/H/rQ+F3Eb9kK8ec1mj/HSwvKSX6/360ftR9/f96mAQ+SFi+TF7Y6S8RBtUhy9ioJGV5adQqnHcDkYxRM/ajhPF4KCLSpSqNclZ7jRBmNi48GeDV6CmqaR9CFERzEY/5jn5cDJjskHvmB3O0v2CPZq6EiAQP8r29GBq3RoSjIQCRM0lozGedaXlfWJZq9XAoGGyICeLfLdnbOemRBEreAzhQBdhz1NUygpUU1tI9UaqYy2a8M8hUKsl/AkaMs816iIV6IXfAl5jTbj68S1zgn0pPqDYEPLpjniMAqr6iCmUv07oJJrb3Ybe3oQ+Bb3XKgTQo98s50sBYNw9mOHSTfYxGMCCQXzXUH6lGviy7AW18T0b85RUtWrRCTnH2xKqE/0m70KCkLzNjLJCPuQIkzZ5VraPGKqsWtOt+4aOfwqyY5n7bxl41C7FFlW1Xyl4QGuKOD/BCB3R0gekgXfD9fIKZdany0YhI9DWyWLvzqar0i0e/6t0DborLfLSuDZfbXI7rkcdM76ApC12Io0yo12XxZkgejYeTri3vjMbtKVYZ0R99OikMimPs+GIg5KAB79u0Mj9c3D4/eYw8NpGrlwrpko0sjlC99WZIpJe0tQlNaWKh0lGH29VDCCBUEGCSqGSIb3DQEHAaCCBTIEggUuMIIFKjCCBSYGCyqGSIb3DQEMCgECoIIE7jCCBOowHAYKKoZIhvcNAQwBAzAOBAhaEE/1daqfgQICCAAEggTIceK6BIQs8ZhGQ04mZ3BOqELL08KS3sYlGskG4EhCUawbsUI3TXFoXuJV1A9je0uWw2drTdicIK9unJJkxsvNLkJsQnORQBFyNS3XIiRbUrJka7SvF0p7fqB+eVM1jiG1CEP2sQ4uQ0BrtZZ0Aaqv7Pi33OrR/9w79K1iGWYGOD/eqp4UmIPCuFWPJ3zta9iD1lTXhl7FlDBlW6JY1/b5lRqsh2CP4W5rvXvyFoL5XjDHshFVtVC/Z/wKdI5m8zCOh6a/D94gk5qiRYGPqlAra56Sebe7b2a/iDKe2rNqL76DQj2PgeqnrVL95L8lgkDoWD0FUpTt4TwyWiK8DIEwux/MqtYJYuqxHzg1NSalNLBcDN/GDaGB3HkQ7L9Fm6eQnqQUXqJ9UrBy+UqhlnAGagoYrkUkrlzFSGE8CIvBi/L1gSND9dVzi8at5FglA2fV57Xg3McN2h/ox5C/uafFYuoBDrDtNE8J7s6zGGlWwqysuvMnmic5wiu4hHYn6Ydiw/BMfNjlnNSQjis7KDoon9yght7Gaot3Of5fgmJ+sAZSqHsZ3EcgIiEBPLjtMWY+gyOJ3HDhcc3Xobi/aIBfoYKTJR/Uox3oH4wL5iLHbF33aJBDC53Zb6/jxZow1esx+qdf+aXWhto9BPWpl/ZupOLuC5w0QPVmbIniCW3OzywxD1jK2HbNfQvDR+vTVaXCakp8B9dnHnj9I9DQYRdpQ39WmU+vt/x8tNJj31aivIg097YcgKfvfRm1bZ3xk9tKGQvxtftvmZAPN/MCRugptz7UH2QS2hjiOIpAbQHoyLpcLMEeOXokD2ITaYeZRjHe2v/BsWg5nbIb/eknFA5TJb51VJwjJJayrlT+jSvpF4RhNe6xm9I45fUPxfByDibzvAZByfXXLZRccNr0VQxBUIyaIVnqJZjcE+6e5PSc1jmK4qft6U1cwJKJTbcQUOsfW9HYP3705tm1+YN1DcdTrCzBIY6P/YeqYvtWaVoQPKHkWTmitOyvmK7+ebtB+0BU4/kgKzgkg5/Be/6ylGfkGYeKMUwe3Ir/edze55sbDaNHpj/mm2FOimNTS6BPBjjjmSwZYNEInOoVIVBVJ3Gyk9gspoZhOBfZN94+eqaCGjlmN354Sowxn4qYkpG1iU/Ta+1rNQoiGPKpKQw/P10rwss6FqC92OsPVGx0m9ba1lWW4UZKuhSkaYFfQwREt5R4ULdbToUOGVug5dq27rquGaP75E+gRAqVqmNb+oUPUW4qc8+jg3qr9AEulf0iCgTrMKirVAuqVDYTaxDgiDZNSAVZVzM43QRa7eXoX8Q16BU3T2h4Ug2H52vFC8xHARnpKgHO+5IY+Jmcu1CyDZD6sjwrSBSSWSvek+L4/8Wx8/IqyADnifA0VL5BcBIZ0TBn1+J8n72zqyf//Jo8ArsAdXZQjsMlncIj0ExJLz81s2eRurz6zSSCyryZDVp63i4odCrcQEbwtU0AvGToh+juch4JS7lQUuzFdrlmCNVTBLTMVEMUeNDd35a0Jp/n1fDnu5gYfX1JLlcDCEvVgGGXcPk5Naz2KzKCP3L8ghjTUxCNuo9qCIX+NZ0aNkRmDOzdqYbO4XIwpIjxZlVGW79CP4hiK2qjYUWEMSUwIwYJKoZIhvcNAQkVMRYEFE3xOZ+wrYQDW41V+Cj2OUJ6emEQMDEwITAJBgUrDgMCGgUABBTROXmDbpHtaAz/G0iTdJ3JDfw2DAQI59HRQ27QxqYCAggA
{% endif %}
{% endif %}
{% if request.target == "mellow" %}

[Endpoint]
DIRECT, builtin, freedom, domainStrategy=UseIP
REJECT, builtin, blackhole
Dns-Out, builtin, dns

[Routing]
domainStrategy = IPIfNonMatch

[Dns]
hijack = Dns-Out
clientIp = 114.114.114.114

[DnsServer]
localhost
223.5.5.5
8.8.8.8, 53, Remote
8.8.4.4

[DnsRule]
DOMAIN-KEYWORD, geosite:geolocation-!cn, Remote
DOMAIN-SUFFIX, google.com, Remote

[DnsHost]
doubleclick.net = 127.0.0.1

[Log]
loglevel = warning

{% endif %}
{% if request.target == "surfboard" %}

[General]
loglevel = notify
interface = 127.0.0.1
skip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 100.64.0.0/10, localhost, *.local
ipv6 = false
dns-server = system, 223.5.5.5
exclude-simple-hostnames = true
enhanced-mode-by-rule = true
{% endif %}
{% if request.target == "sssub" %}
{
  "route": "bypass-lan-china",
  "remote_dns": "dns.google",
  "ipv6": false,
  "metered": false,
  "proxy_apps": {
    "enabled": false,
    "bypass": true,
    "android_list": [
      "com.eg.android.AlipayGphone",
      "com.wudaokou.hippo",
      "com.zhihu.android"
    ]
  },
  "udpdns": false
}

{% endif %}
