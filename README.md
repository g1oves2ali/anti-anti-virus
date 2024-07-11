# 开始

# 免杀木马生成器

## 🟢 **测试github上的免杀项目**

*   ×代表无法免杀

*   √代表可以免杀

| 序号 | 项目地址                                                                                                 | 项目简介                                  | Microsoft Defender      | 火绒 | 360安全卫士 | 卡巴斯基 | 备注     |
| :- | :--------------------------------------------------------------------------------------------------- | :------------------------------------ | :---------------------- | :- | :------ | :--- | :----- |
| 1  | <https://github.com/Pizz33/JoJoLoader>                                                               | 助力红队成员一键生成免杀木马，使用rust实现 (by\_hyyrent) | ×                       | √  | ×       | √    | 0708测试 |
| 2  | <https://github.com/Joe1sn/S-inject>                                                                 | DLL+Shellcode的Windows注入免杀工具           | 罗列各种方法，免杀推荐搭配其他技巧，要灵活使用 |    |         |      |        |
| 3  | [https://github.com/T4y1oR/RingQ](https://github.com/T4y1oR/RingQ "https://github.com/T4y1oR/RingQ") | 一键免杀上线CS、fscan、mimikatz ...           | ×                       | √  | √       | ×    | 0709测试 |

# 免杀中用到的工具

## 🟢 **绝大部分无法直接生成免杀木马，开发、测试免杀时会用到。**

| 工具简称                                                                                           | 概述                                                      | 工具来源                                | 下载路径                                                                                                                                                                   |
| :--------------------------------------------------------------------------------------------- | :------------------------------------------------------ | :---------------------------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| x64dbg 中文版安装程序(Jan 6 2024).exe                                                                 |                                                         | 52pojie                             |                                                                                                                                                                        |
| hellshell                                                                                      | 官方的加密或混淆shellcode                                       | github                              | <https://gitlab.com/ORCA000/hellshell/-/releases>                                                                                                                      |
| hellshell-网络版本                                                                                 |                                                         | github                              | <https://github.com/SenSecurity/Hellshell-with-more-fuctionality>                                                                                                      |
| Dependencies.AheadLib.Plugin                                                                   | 在dependencies上额外加了导出函数                                  | 看雪                                  | <https://bbs.kanxue.com/thread-260874.htm>                                                                                                                             |
| Dependencies                                                                                   |                                                         | github                              | <https://github.com/lucasg/Dependencies>                                                                                                                               |
| ChangeTimestamp.exe                                                                            | 更改时间戳                                                   |                                     |                                                                                                                                                                        |
| sgn\_windows\_amd64\_2.0.1                                                                     | 对二进制文件编码免杀shellcode                                     | github                              | <https://github.com/EgeBalci/sgn>                                                                                                                                      |
| Resource Hacker                                                                                |                                                         |                                     |                                                                                                                                                                        |
| BeaconEye\_x64                                                                                 | 通过扫描CobaltStrike中的内存特征，并进行Beacon Config扫描解析出对应的Beacon信息 | github                              | <https://github.com/CCob/BeaconEye/releases>                                                                                                                           |
| Hunt-Sleeping-Beacons                                                                          |                                                         | github                              | <https://github.com/thefLink/Hunt-Sleeping-Beacons>                                                                                                                    |
| yara-master-2298-win64                                                                         | 分类恶意软件样本的工具                                             | github                              | <https://github.com/VirusTotal/yara>                                                                                                                                   |
| Windows\_Trojan\_CobaltStrike.yar                                                              | Elastic安全公司开源检测CobaltStrike的yara规则                      | github                              | <https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_CobaltStrike.yar>                                                                |
| hollows\_hunter64                                                                              |                                                         | github                              | <https://github.com/hasherezade/hollows_hunter>                                                                                                                        |
| arsenal\_kit                                                                                   |                                                         | telegram                            |                                                                                                                                                                        |
| DLLSpy                                                                                         | 检测正在运行的进程、服务及其二进制文件中的 DLL 劫持                            | github                              |                                                                                                                                                                        |
| Process Hacker 2                                                                               | 查看进程                                                    |                                     |                                                                                                                                                                        |
| Alcatraz                                                                                       | 没下载， x64 二进制混淆器，能够混淆各种不同的 pe 文件                         | github                              | <https://github.com/weak1337/Alcatraz>                                                                                                                                 |
| pestudio-9.58                                                                                  | 查看文件熵值等信息，逆向等可用                                         | 官网下载                                | <https://www.winitor.com/download2>                                                                                                                                    |
| [https://junkcode.gehaxelt.in/](https://junkcode.gehaxelt.in/ "https://junkcode.gehaxelt.in/") | 垃圾代码生成器，降低熵值                                            | github                              | [https://github.com/gehaxelt/PHP-C---JunkCodeGenerator](https://github.com/gehaxelt/PHP-C---JunkCodeGenerator "https://github.com/gehaxelt/PHP-C---JunkCodeGenerator") |
| sgn\_windows\_amd64\_2.0.1                                                                     | 编码shellcode                                             | github                              |                                                                                                                                                                        |
| ChangeTimestamp.exe                                                                            | 改时间                                                     |                                     |                                                                                                                                                                        |
| SigThief                                                                                       | 把签名撕取下来                                                 | github                              | [https://github.com/secretsquirrel/SigThief](https://github.com/secretsquirrel/SigThief "https://github.com/secretsquirrel/SigThief")                                  |
| Restorator2018                                                                                 | 伪造图标                                                    | <https://www.sqlsec.com/tools.html> | [https://www.sqlsec.com/tools.html](https://www.sqlsec.com/tools.html "https://www.sqlsec.com/tools.html")                                                             |
| BeCyIconGrabber.exe                                                                            | 伪造图标                                                    | <https://www.sqlsec.com/tools.html> | <https://www.sqlsec.com/tools.html>                                                                                                                                    |
| SourcePoint                                                                                    | 自生成Malleable C2 profile                                 | github                              | <https://github.com/Tylous/SourcePoint>                                                                                                                                |
| S-inject                                                                                       | DLL+Shellcode的Windows注入免杀工具                             | github                              | [https://github.com/Joe1sn/S-inject](https://github.com/Joe1sn/S-inject "https://github.com/Joe1sn/S-inject")                                                          |
| RingQ                                                                                          | 免杀，exe2shellcode                                        | github                              | <https://github.com/T4y1oR/RingQ>                                                                                                                                      |
| pe2shc.exe                                                                                     | pe\_to\_shellcode                                       | github                              | <https://github.com/hasherezade/pe_to_shellcode/>                                                                                                                      |

# 免杀学习链接

## **🟢 比较近期的技术文章、或是一些免杀技术总结等**

## [【Web实战】先锋马免杀分享](https://forum.butian.net/share/2530)

## [AniYa-GUI免杀框架](https://github.com/piiperxyz/AniYa/blob/main/README.md)

## [释放看不见的威胁：利用钴攻击配置文件的力量来逃避 EDR](https://whiteknightlabs.com/2023/05/23/unleashing-the-unseen-harnessing-the-power-of-cobalt-strike-profiles-for-edr-evasion/)

## [go实现免杀(实用思路篇)](https://xz.aliyun.com/t/14692?time__1311=mqmx9QDtDQ0%3DeGKDsdoYIKKWTumQDuQnQYD\&alichlgref=https%3A%2F%2Fwww.google.com%2F#toc-20)

## [CobaltStrike的狩猎与反狩猎](https://xz.aliyun.com/t/14798?time__1311=mqmx9QwxBDcQD%2FD0Dx2DUxsoD88QGOfYeD\&alichlgref=https%3A%2F%2Fwww.google.com%2F)

## [【CS学习笔记】26、杀毒软件](https://teamssix.com/200419-150726)

## [进程启动&断链](https://blog.csdn.net/m0_62466350/article/details/135918002)

## [攻击性 Windows IPC 内部原理 2：RPC](https://csandker.io/2021/02/21/Offensive-Windows-IPC-2-RPC.html#finding-interesting-targets)

## [shellcode-loader汇总](https://github.com/xf555er/ShellcodeLoader)

## [CobaltStrike 4.9.10](https://wx.zsxq.com/dweb2/index/topic_detail/411555822551258)

## [COM调用 断链](https://wx.zsxq.com/dweb2/index/topic_detail/814851241282852)

## [杀软EDR都没检出？一文秒懂“银狐”四大绕过手法](https://zhuanlan.zhihu.com/p/618457433)

## [攻防演练 | 分享一次应急处置案例](https://cloud.tencent.com/developer/article/2326404)

## [学习免杀的笔记汇总](https://github.com/xf555er/AntiAntiVirusNotes)

## [免杀杂谈](https://www.cnblogs.com/xiaoxin07/p/18118006)

## [红队技术-钓鱼手法及木马免杀技巧](https://pizz33.github.io/posts/53de6033c423/)

## [助力每一位RT队员，快速生成免杀木马](https://github.com/wangfly-me/LoaderFly)

## [免杀手法大总结（入门)](https://xz.aliyun.com/t/14215?time__1311=mqmx9QiQi%3DgjD%2FD0DTGkbDCRKM4iTr9vD\&alichlgref=https%3A%2F%2Fwww.google.com%2F)

## [C++熵减法免杀-Mimikatz免杀](https://cloud.tencent.com/developer/article/2360969)

## [动态生成key免杀](https://mp.weixin.qq.com/s?__biz=Mzg5MDg0NzUzMw==\&mid=2247483697\&idx=1\&sn=40d0c408f382325eb3ece0ed7a303f14\&chksm=cfd72973f8a0a0654a47c250b2d0dc3fa3239ec9479544a848bc4ec854b106b624427b1d3e90\&scene=21#wechat_redirect)

## [免杀学习-从指令绕过开始(2)](https://xz.aliyun.com/t/12760?time__1311=mqmhDvOGkD7D8Dlc%2BG7FcbPQTZlfDfOTD\&alichlgref=https%3A%2F%2Fwww.google.com%2F)

## [obj2shellcode 前人不仅具有智慧,更具分享精神](https://mp.weixin.qq.com/s/sXX6hGeHVefESmmbw9IepQ)

## [自定义跳转函数的unhook方法](https://killer.wtf/2022/01/19/CustomJmpUnhook.html)

## [rust 免杀，方法记录](https://github.com/xiao-zhu-zhu/RustBypassMap)

## [混淆的文件或信息： 二进制填充](https://attack.mitre.org/techniques/T1027/001/)

## [Raising Beacons without UDRLs and Teaching them How to Sleep](https://www.naksyn.com/cobalt%20strike/2024/07/02/raising-beacons-without-UDRLs-teaching-how-to-sleep.html)

## [x86下借助回调函数以干净的栈执行内存权限修改](https://pastebin.com/XMfKJ9ZG)

## [EDRPrison：借用合法WFP驱动程序来静音 EDR 代理](https://www.3nailsinfosec.com/post/edrprison-borrow-a-legitimate-driver-to-mute-edr-agent)

## [规避ETW事件监控检测](https://s4dbrd.com/evading-etw-based-detections/)

## [Windows Rootkit与Bootkit技术列表与威胁](https://artemonsecurity.blogspot.com/2024/07/windows-rootkits-and-bootkits-guide-v2.html)

## [Windows 11 VBS enclave虚拟化保护技术](https://techcommunity.microsoft.com/t5/windows-os-platform-blog/securely-design-your-applications-and-protect-your-sensitive/ba-p/4179543)

## [利用偏移数组在运行时构造载荷](https://github.com/NUL0x4C/FetchPayloadFromDummyFile)

## [按需动态解密内存节区，闲置时重新加密](https://github.com/pygrum/gimmick)

## [修改Powershell配置文件永久关闭AMSI与ETW](https://github.com/EvilBytecode/Lifetime-Amsi-EtwPatch)

## [Bootkit内核修补检测绕过](https://tulach.cc/bootkits-and-kernel-patching/)

## [借助VEH和汇编指令加密规避内存扫描](https://github.com/vxCrypt0r/Voidgate)

## [睡眠状态Beacon识别工具](https://github.com/thefLink/Hunt-Sleeping-Beacons)

## [恶意Windows进程、线程异常状态识别](https://www.trustedsec.com/blog/windows-processes-nefarious-anomalies-and-you-threads)

## [绕过PowerShell ScriptBlock日志](<> "https://bc-security.org/scriptblock-smuggling/")

## [借助硬件断点提取明文RDP密码](https://github.com/0xEr3bus/RdpStrike)

## [渐进式 Web 应用程序 (PWA) 网络钓鱼](https://mrd0x.com/progressive-web-apps-pwa-phishing/)

# 结束

## 🟢 持续更新中
