## 驱动开发环境测试

> 开发环境：win11 测试环境：vm win10 ltsc

1.编译：DriverTest.sys

- 项目属性，c/c++，常规，警告等级 = 3
- 项目属性，c/c++，常规，将警告视为错误 = 否
- 项目属性，链接器，常规，将链接器警告视为错误 = 否
- 排除自带 DriverTest.inf

2.创建测试证书：`makecert -r -pe -ss PrivateCertStore -n CN=Contoso.com(Test) -eku 1.3.6.1.5.5.7.3.3 ContosoTest.cer`

3.将该证书导入到 **受信任的根证书颁发机构**

4.签名：`SignTool sign /v /s PrivateCertStore /n Contoso.com(Test) /t http://timestamp.digicert.com 64\Debug\DriverTest.sys`

5.开启测试签名：`bcdedit  /set  testsigning  on`

6.管理员运行 Monitor | InstDrv 加载运行驱动

7.管理员运行 DbgView  ，Capture 勾选 **Capture Kernel** ，**Enable Verbose Kernel Output** 查看内核Dbg信息

8.成功打印：[DriverTest] DriverEntry 与 [DriverTest] DriverUnload