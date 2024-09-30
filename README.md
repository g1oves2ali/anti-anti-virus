# 开始

# 免杀木马生成器

## 🟢 **github上的免杀项目**

*   ×代表无法免杀

*   √代表可以免杀


    | 序号 | 项目地址                                                                                                                                           | 项目简介                                  | Microsoft Defender       | 火绒 | 360安全卫士 | 卡巴斯基 | 时间        | 备注                         |
    | :- | :--------------------------------------------------------------------------------------------------------------------------------------------- | :------------------------------------ | :----------------------- | :- | :------ | :--- | :-------- | :------------------------- |
    | 1  | <https://github.com/Pizz33/JoJoLoader>                                                                                                         | 助力红队成员一键生成免杀木马，使用rust实现 (by\_hyyrent) | ×                        | √  | ×       | √    | 0708自测    |                            |
    | 2  | <https://github.com/Joe1sn/S-inject>                                                                                                           | DLL+Shellcode的Windows注入免杀工具           | 罗列各种方法，免杀推荐搭配其他技巧，要灵活使用  |    |         |      |           |                            |
    | 3  | [https://github.com/T4y1oR/RingQ](https://github.com/T4y1oR/RingQ "https://github.com/T4y1oR/RingQ")                                           | 一键免杀上线CS、fscan、mimikatz ...           | ×                        | √  | √       | ×    | 0709自测    | create.exe未开源              |
    | 4  | <https://github.com/HackerCalico/No_X_Memory_ShellCode_Loader>                                                                                 | 无可执行权限加载 ShellCode                    | 并非直接生成免杀马                |    |         |      |           |                            |
    | 5  | <https://github.com/Cherno-x/dataBrawl>                                                                                                        | 一键生成免杀木马的 shellcode 免杀框架              | 大型活动期间暂停维护，已删除核心template |    |         |      |           |                            |
    | 6  | [https://github.com/A-little-dragon/GoBypassAV](https://github.com/A-little-dragon/GoBypassAV "https://github.com/A-little-dragon/GoBypassAV") | Go语言编写的免杀工具，支持自动化随机加解密                | ×                        | ×  |         |      | 0416issue | 未开源;执行命令时出错： exit status 1 |
    | 7  | [https://github.com/Cipher7/ApexLdr](https://github.com/Cipher7/ApexLdr "https://github.com/Cipher7/ApexLdr")                                  | 纯C代码开发的DLL载荷加载器                       |                          |    |         |      |           | 开源、makefile                |
    | 8  | <https://github.com/yj94/BinarySpy>                                                                                                            | 一个手动或自动patch shellcode到二进制文件的免杀工具     | 免杀依赖于shellcode           |    |         |      | 0808      |                            |
    | 9  | <https://github.com/timwhitez/BinHol>                                                                                                          | 三种方式在你的pe二进制中插入恶意代码                   | 免杀依赖于shellcode           |    |         |      | 0808      |                            |
    | 10 | <https://github.com/yinsel/BypassA>                                                                                                            | 一款基于PE Patch技术的后渗透免杀工具，仅支持x64         | 无操作步骤说明                  |    |         |      | 0808      | 未开源                        |
    | 11 | <https://github.com/hhuang00/go-bypass-loader>                                                                                                 | go实现的shellcode免杀加载器                   |                          | √  | √       |      | 0806作者自述  |                            |
    | 12 | <https://github.com/berryalen02/PECracker>                                                                                                     | 针对PE文件的分离的免杀对抗工具。                     | √                        |    | √       |      | 0813作者自述  | 未开源                        |

# 免杀中用到的工具

## 🟢 **绝大部分无法直接生成免杀木马，开发、测试免杀时会用到。**

| 工具简称                                                                                           | 概述                                                                                                                  | 工具来源                                | 下载路径                                                                                                                                                                                                 |
| :--------------------------------------------------------------------------------------------- | :------------------------------------------------------------------------------------------------------------------ | :---------------------------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| x64dbg 中文版安装程序(Jan 6 2024).exe                                                                 |                                                                                                                     | 52pojie                             |                                                                                                                                                                                                      |
| hellshell                                                                                      | 官方的加密或混淆shellcode                                                                                                   | github                              | <https://gitlab.com/ORCA000/hellshell/-/releases>                                                                                                                                                    |
| hellshell-网络版本                                                                                 |                                                                                                                     | github                              | [https://github.com/SenSecurity/Hellshell-with-more-fuctionality](https://github.com/SenSecurity/Hellshell-with-more-fuctionality "https://github.com/SenSecurity/Hellshell-with-more-fuctionality") |
| Dependencies.AheadLib.Plugin                                                                   | 在dependencies上额外加了导出函数                                                                                              | 看雪                                  | [https://bbs.kanxue.com/thread-260874.htm](https://bbs.kanxue.com/thread-260874.htm "https://bbs.kanxue.com/thread-260874.htm")                                                                      |
| Dependencies                                                                                   |                                                                                                                     | github                              | <https://github.com/lucasg/Dependencies>                                                                                                                                                             |
| ChangeTimestamp.exe                                                                            | 更改时间戳                                                                                                               |                                     |                                                                                                                                                                                                      |
| sgn\_windows\_amd64\_2.0.1                                                                     | 对二进制文件编码免杀shellcode                                                                                                 | github                              | <https://github.com/EgeBalci/sgn>                                                                                                                                                                    |
| Resource Hacker                                                                                |                                                                                                                     |                                     |                                                                                                                                                                                                      |
| BeaconEye\_x64                                                                                 | 通过扫描CobaltStrike中的内存特征，并进行Beacon Config扫描解析出对应的Beacon信息                                                             | github                              | <https://github.com/CCob/BeaconEye/releases>                                                                                                                                                         |
| Hunt-Sleeping-Beacons                                                                          |                                                                                                                     | github                              | <https://github.com/thefLink/Hunt-Sleeping-Beacons>                                                                                                                                                  |
| yara-master-2298-win64                                                                         | 分类恶意软件样本的工具                                                                                                         | github                              | <https://github.com/VirusTotal/yara>                                                                                                                                                                 |
| Windows\_Trojan\_CobaltStrike.yar                                                              | Elastic安全公司开源检测CobaltStrike的yara规则                                                                                  | github                              | <https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_CobaltStrike.yar>                                                                                              |
| hollows\_hunter64                                                                              |                                                                                                                     | github                              | <https://github.com/hasherezade/hollows_hunter>                                                                                                                                                      |
| arsenal\_kit                                                                                   |                                                                                                                     | telegram                            |                                                                                                                                                                                                      |
| DLLSpy                                                                                         | 检测正在运行的进程、服务及其二进制文件中的 DLL 劫持                                                                                        | github                              |                                                                                                                                                                                                      |
| Process Hacker 2                                                                               | 查看进程                                                                                                                |                                     |                                                                                                                                                                                                      |
| Alcatraz                                                                                       | 没下载， x64 二进制混淆器，能够混淆各种不同的 pe 文件                                                                                     | github                              | <https://github.com/weak1337/Alcatraz>                                                                                                                                                               |
| pestudio-9.58                                                                                  | 查看文件熵值等信息，逆向等可用                                                                                                     | 官网下载                                | <https://www.winitor.com/download2>                                                                                                                                                                  |
| [https://junkcode.gehaxelt.in/](https://junkcode.gehaxelt.in/ "https://junkcode.gehaxelt.in/") | 垃圾代码生成器，降低熵值                                                                                                        | github                              | [https://github.com/gehaxelt/PHP-C---JunkCodeGenerator](https://github.com/gehaxelt/PHP-C---JunkCodeGenerator "https://github.com/gehaxelt/PHP-C---JunkCodeGenerator")                               |
| sgn\_windows\_amd64\_2.0.1                                                                     | 编码shellcode                                                                                                         | github                              |                                                                                                                                                                                                      |
| ChangeTimestamp.exe                                                                            | 改时间                                                                                                                 |                                     |                                                                                                                                                                                                      |
| SigThief                                                                                       | 把签名撕取下来                                                                                                             | github                              | [https://github.com/secretsquirrel/SigThief](https://github.com/secretsquirrel/SigThief "https://github.com/secretsquirrel/SigThief")                                                                |
| Restorator2018                                                                                 | 伪造图标                                                                                                                | <https://www.sqlsec.com/tools.html> | [https://www.sqlsec.com/tools.html](https://www.sqlsec.com/tools.html "https://www.sqlsec.com/tools.html")                                                                                           |
| BeCyIconGrabber.exe                                                                            | 伪造图标                                                                                                                | <https://www.sqlsec.com/tools.html> | <https://www.sqlsec.com/tools.html>                                                                                                                                                                  |
| SourcePoint                                                                                    | 自生成Malleable C2 profile                                                                                             | github                              | <https://github.com/Tylous/SourcePoint>                                                                                                                                                              |
| S-inject                                                                                       | DLL+Shellcode的Windows注入免杀工具                                                                                         | github                              | [https://github.com/Joe1sn/S-inject](https://github.com/Joe1sn/S-inject "https://github.com/Joe1sn/S-inject")                                                                                        |
| RingQ                                                                                          | 免杀，exe2shellcode                                                                                                    | github                              | <https://github.com/T4y1oR/RingQ>                                                                                                                                                                    |
| pe2shc.exe                                                                                     | pe\_to\_shellcode                                                                                                   | github                              | <https://github.com/hasherezade/pe_to_shellcode/>                                                                                                                                                    |
| pengcode                                                                                       | exe转换成shellcode                                                                                                     | github                              | <https://github.com/Mephostophiles/PengCode>                                                                                                                                                         |
| SharpIncrease                                                                                  | 一种利用二进制填充来逃避 AV 的工具                                                                                                 | github                              | <https://github.com/mertdas/SharpIncrease>                                                                                                                                                           |
| deoptimizer                                                                                    | 对shellcode进行反优化，rust                                                                                                | github                              | <https://github.com/EgeBalci/deoptimizer>                                                                                                                                                            |
| DojoLoader                                                                                     | 用于快速原型逃避技术的通用 PE 加载器                                                                                                | github                              | <https://github.com/naksyn/DojoLoader>                                                                                                                                                               |
| FetchPayloadFromDummyFile                                                                      | 使用偏移量数组构造有效载荷                                                                                                       | github                              | <https://github.com/NUL0x4C/FetchPayloadFromDummyFile>                                                                                                                                               |
| CFF\_Explorer                                                                                  |                                                                                                                     | 看雪                                  |                                                                                                                                                                                                      |
| CppDevShellcode-master                                                                         | 使用Visral Studio开发ShellCode                                                                                          | github                              |                                                                                                                                                                                                      |
| ShellcodeCompiler                                                                              |                                                                                                                     | github                              | <https://github.com/NytroRST/ShellcodeCompiler>                                                                                                                                                      |
| 20240125 CobaltStrike arsenal-kit更新                                                            | 主要相比上一次的kit增加了一个对sleepmask的编译混淆，主要解决sleepmask code本身在内存中的特征                                                         | 星球                                  | <https://wx.zsxq.com/dweb2/index/topic_detail/211418818824441>                                                                                                                                       |
| PushPlus2                                                                                      | 上线自动推送，截图等                                                                                                          | github                              | <https://github.com/S9MF/my_script_tools/tree/main/CS%E6%8F%92%E4%BB%B6>                                                                                                                             |
| BinHol                                                                                         | Patch白程序的工具                                                                                                         | github                              | [https://github.com/timwhitez/BinHol](https://github.com/timwhitez/BinHol "https://github.com/timwhitez/BinHol")                                                                                     |
| BinarySpy                                                                                      | Patch白程序的工具                                                                                                         | github                              | <https://github.com/yj94/BinarySpy>                                                                                                                                                                  |
| pconlife                                                                                       | 下载不同内核版本windows里的系统文件，之所以用到它还是因为之前星球里发的Patch手法，今天抓了个样本就是Patch的windows中的系统文件，但是windows不同版本里面的文件也不完全一样，把所有版本都装一遍肯定不现实 | github                              | <https://www.pconlife.com/>                                                                                                                                                                          |
| ShellcodeCompiler                                                                              | 将 C/C++ 样式代码编译为适用于 Windows（x86 和 x64）和 Linux（x86 和 x64）的小型、位置独立且无 NULL 的 shellcode 的程序                              | github                              | [https://github.com/NytroRST/ShellcodeCompiler](https://github.com/NytroRST/ShellcodeCompiler "https://github.com/NytroRST/ShellcodeCompiler")                                                       |
| shellen                                                                                        | 交互式的 shellcoding 环境                                                                                                 | github                              | <https://github.com/merrychap/shellen>                                                                                                                                                               |
| SigFlip                                                                                        | SigFlip 是一种用于修补 Authenticode 签名的 PE 文件（exe、dll、sys 等）的工具，而不会使现有签名无效或破坏。                                             | github                              | <https://github.com/med0x2e/SigFlip>                                                                                                                                                                 |
| microwaveo                                                                                     | 将dll exe 等转成shellcode 最后输出exe 可定制加载器模板 支持白文件的捆绑 shellcode 加密                                                        | github                              | <https://github.com/Ciyfly/microwaveo>                                                                                                                                                               |
| GoDhijacking                                                                                   | 快速识别可劫持程序、逃避防病毒软件和 EDR（端点检测和响应）系统                                                                                   | github                              | [https://github.com/m7rick/GoDhijacking](https://github.com/m7rick/GoDhijacking "https://github.com/m7rick/GoDhijacking")                                                                            |
| BinHol                                                                                         | 三种方式在你的pe二进制中插入恶意代码                                                                                                 | github                              | [https://github.com/timwhitez/BinHol](https://github.com/timwhitez/BinHol "https://github.com/timwhitez/BinHol")                                                                                     |
| 吾爱破解专用版Ollydbg                                                                                 |                                                                                                                     | 52pojie                             |                                                                                                                                                                                                      |
| StudyPE+ x64                                                                                   | PE查看/分析                                                                                                             | 看雪                                  | <https://bbs.kanxue.com/thread-246459-1.htm>                                                                                                                                                         |
| StudyPE+ x86                                                                                   | PE查看/分析                                                                                                             | 看雪                                  | <https://bbs.kanxue.com/thread-246459-1.htm>                                                                                                                                                         |

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

## [深入研究PE文件格式](https://0xrick.github.io/)

## [自定义反射DLL与注入器项目](https://oldboy21.github.io/posts/2023/12/all-i-want-for-christmas-is-reflective-dll-injection/)

## [Window Defender ASR规则提取工具](https://github.com/0xsp-SRD/MDE_Enum)

## [禁用Windows Defender防篡改功能](https://github.com/AlteredSecurity/Disable-TamperProtection)

## [File-Tunnel：借助文件隧道打通TCP连接](https://github.com/fiddyschmitt/File-Tunnel)

## [借助合法取证工具绕过EDR读取NTDS.dit](https://medium.com/@0xcc00/bypassing-edr-ntds-dit-protection-using-blueteam-tools-1d161a554f9f)

## [编写自己的C#混淆器](https://www.ribbiting-sec.info/posts/2024-06-05_csharp_obfuscator/)

## [深入剖析Window内核Secure Image对象](https://connormcgarr.github.io/secure-images/)

## [dirDevil：在文件夹结构中隐藏代码和内容](https://trustedsec.com/blog/dirdevil-hiding-code-and-content-within-folder-structures)

## [40+43+74 种权限提升方法集合（Linux/Windows/macOS）](https://github.com/HadessCS/Awesome-Privilege-Escalation)

## [Windows下Shellcode编写详解](https://xz.aliyun.com/t/2108?time__1311=n4%2Bxni0%3DoxBDgDfxDqGNL4YqoNvrDkR%2B8DLYeD)

## [Window向之x86 ShellCode入门](https://forum.butian.net/share/1244)

## [\[2024\]通杀检测基于白文件patch黑代码的免杀技术的后门](https://key08.com/index.php/2024/08/03/1949.html)

## [记一次Patch exe 文件实现的静态免杀](https://xz.aliyun.com/t/15081?time__1311=GqjxuiitiQGQDQD%2Fmd0%3D%3DudrK6eGIfXAPx)

## [一种基于patch免杀技术的自动化实现VT0](https://xz.aliyun.com/t/15096?time__1311=GqjxuiitGQi%3DdGNDQiiQGkFKO%2BQ9qqHF4D)

##

# 结束

## 🟢 持续更新中

# 更新日志

## 20240930 更新增加免杀相关工具

## 20240808 更新patch白文件添加shellcode的相关工具、github项目及文章
