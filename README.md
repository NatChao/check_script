# Linux服务器等保加固脚本/检测脚本


#这脚本程序是我在一位的开源xiaoyunjie老哥写的脚本加固基础上新增了两个加固脚本，设置密码长度和定期更换要求、建议操作系统对审计记录进行保护，通过日志服务器对审计记录进行定期存档备份

#他的加固脚本github项目地址https://github.com/xiaoyunjie/Shell_Script


## Check_Script
**操作说明**

```bash
#执行CentOS-Check_Script.sh脚本文件进行检查,命令格式如下
sudo sh CentOS_Check_Script.sh | tee check_`date +%Y%m%d_%H%M%S`.txt
```
#执行完CentOS_Check_Script.sh会在当前目录下生成以当前时间单位命名的txt检查结果文件(check_2023.xxxxx_xxxx.txt)
#这个检查脚本好像对Ubuntu系统没啥作用，因为Ubuntu系统有些配置文件和检测脚本的文件不一样或者不存在。


**检查说明**
此脚本是按三级等保要求，编写的一键检查脚本，此脚本只适合linux分支中的redhat、centos，运行脚本将结果输出到自定义的文件中，脚本结果需要人为检查。

此检查脚本包含以下几块内容：
- 系统基本信息
- 资源使用情况
- 系统用户情况
- 身份鉴别安全
- 访问控制安全
- 安全审计
- 剩余信息保护
- 入侵防范安全
- 恶意代码防范
- 资源控制安全


----



## Protective_Script

```bash
CentOS_Protective_Script.sh
执行完脚本任意编号功能，该脚本在执行加固前会自动备份服务器需要修改安全加固的相关配置文件，并且在当前脚本目录下生成backup文件夹
(备份的文件都存储在backup文件夹下,如需恢复原本服务器相关配置文件请执行8号程序 还原配置文件)
```

**操作说明**
```bash
#执行CentOS_Protective_Script.sh脚本文件进行加固,命令格式如下
sudo sh CentOS_Protective_Script.sh
#执行完成后,请按脚本提示重启相应服务

#如果是Ubuntu系统，可能会出现类似Syntax error: "(" unexpected的错误，一般这种是因为sh与bash有些地方不兼容，解决方式：使用bash命令来启动脚本
sudo bash CentOS_Protective_Script.sh

```

**功能说明**
-  1.一键进行全部加固
-  2.设置密码复杂度
-  3.添加openroot账号(一键加固未调用该函数, 如有需求自行在main函数中调用)
-  4.禁止root远程登入(一键加固未调用该函数, 如有需求自行在main函数中调用)
-  5.设置history保存行数以及命令时间，设置窗口超时时间
-  6.更改SSH端口(一键加固未调用该函数, 如有需求自行在main函数中调用)
-  7.登入失败处理
-  8.还原配置文件(一键加固未调用该函数, 如有需求自行在main函数中调用)
-  9.设置密码长度和定期更换要求
-  10.建议操作系统对审计记录进行保护，通过日志服务器对审计记录进行定期存档备份
-  11.退出程序
