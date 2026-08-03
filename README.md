# python-scan-burpsuite

# 基于指纹驱动的burpsuite前置代理漏洞扫描

0. 初次运行程序，会自动生成证书，证书安装方式同 burpsuite
1. poc目录下放置自己的poc
2. 浏览器代理设置程序启动后的代理 即浏览器设置代理 127.0.0.1:8889
3. python proxy_server.py --upstream 127.0.0.1:8080
4. python程序扫描到漏洞后会自动推送到bp，bp可直接看到漏洞数据包
5. 请手动维护 finger.json 和 yaml 模版里面的tags标签一致
