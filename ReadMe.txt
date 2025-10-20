1、启动方式
./coredns -conf Corefile.routeros
2、配置文件 文件中有说明看下即可
Corefile.routeros
3、编译
go generate
make
4、更新域名列表
python3 fetch_gfwlist.py
python3 fetch_china_domains.py
