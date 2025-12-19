#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h> // For __NR_mkdirat
#include <linux/uaccess.h>
#include <syscall.h>
#include <linux/string.h>
#include <kputils.h>
#include <asm/current.h>
#include <linux/fs.h>
#include <linux/errno.h>    // For EACCES and EPERM
#include <accctl.h>         // For set_priv_sel_allow and related functions
#include <uapi/linux/limits.h>   // For PATH_MAX
#include <linux/kernel.h>   // For snprintf

KPM_NAME("HMA++ Next");
KPM_VERSION("1.1.5");
KPM_LICENSE("GPLv3");
KPM_AUTHOR("NightFallsLikeRain");
KPM_DESCRIPTION("核心风险拦截（白名单模式）测试");

#define TARGET_PATH "/data/data/"
#define TARGET_PATH_LEN (sizeof(TARGET_PATH) - 1)

// 内置 allow list（白名单包名，仅允许这些应用操作目标路径）
static const char *allow_list[] = {
    "com.silverlab.app.deviceidchanger.free",
    "com.miui.systemAdSolution",
    "me.bingyue.IceCore",
    "com.modify.installer",
    "o.dyoo",
    "com.zhufucdev.motion_emulator",
    "me.simpleHook",
    "com.cshlolss.vipkill",
    "io.github.a13e300.ksuwebui",
    "com.demo.serendipity",
    "me.iacn.biliroaming",
    "me.teble.xposed.autodaily",
    "com.example.ourom",
    "dialog.box",
    "top.hookvip.pro",
    "tornaco.apps.shortx",
    "moe.fuqiuluo.portal",
    "com.github.tianma8023.xposed.smscode",
    "moe.shizuku.privileged.api",
    "lin.xposed",
    "com.lerist.fakelocation",
    "com.yxer.packageinstalles",
    "xzr.hkf",
    "web1n.stopapp",
    "Hook.JiuWu.Xp",
    "io.github.qauxv",
    "com.houvven.guise",
    "xzr.konabess",
    "com.xayah.databackup.foss",
    "com.sevtinge.hyperceiler",
    "github.tornaco.android.thanos",
    "nep.timeline.freezer",
    "cn.geektang.privacyspace",
    "org.lsposed.lspatch",
    "zako.zako.zako",
    "com.topmiaohan.hidebllist",
    "com.tsng.hidemyapplist",
    "com.tsng.pzyhrx.hma",
    "com.rifsxd.ksunext",
    "com.byyoung.setting",
    "com.omarea.vtools",
    "cn.myflv.noactive",
    "io.github.vvb2060.magisk",
    "com.bug.hookvip",
    "com.junge.algorithmAidePro",
    "bin.mt.termex",
    "tmgp.atlas.toolbox",
    "com.wn.app.np",
    "com.sukisu.ultra",
    "ru.maximoff.apktool",
    "top.bienvenido.saas.i18n",
    "com.syyf.quickpay",
    "tornaco.apps.shortx.ext",
    "com.mio.kitchen",
    "eu.faircode.xlua",
    "com.dna.tools",
    "cn.myflv.monitor.noactive",
    "com.yuanwofei.cardemulator.pro",
    "com.termux",
    "com.suqi8.oshin",
    "me.hd.wauxv",
    "have.fun",
    "miko.client",
    "com.kooritea.fcmfix",
    "com.twifucker.hachidori",
    "com.luckyzyx.luckytool",
    "com.padi.hook.hookqq",
    "cn.lyric.getter",
    "com.parallelc.micts",
    "me.plusne",
    "com.hchen.appretention",
    "com.hchen.switchfreeform",
    "name.monwf.customiuizer",
    "com.houvven.impad",
    "cn.aodlyric.xiaowine",
    "top.sacz.timtool",
    "nep.timeline.re_telegram",
    "com.fuck.android.rimet",
    "cn.kwaiching.hook",
    "cn.android.x",
    "cc.aoeiuv020.iamnotdisabled.hook",
    "vn.kwaiching.tao",
    "com.nnnen.plusne",
    "com.fkzhang.wechatxposed",
    "one.yufz.hmspush",
    "cn.fuckhome.xiaowine",
    "com.fankes.tsbattery",
    "com.rkg.IAMRKG",
    "me.gm.cleaner",
    "moe.shizuku.redirectstorage",
    "com.ddm.qute",
    "kk.dk.anqu",
    "com.qq.qcxm",
    "com.wei.vip",
    "dknb.con",
    "dknb.coo8",
    "com.tencent.jingshi",
    "com.tencent.JYNB",
    "com.apocalua.run",
    "com.coderstory.toolkit",
    "com.didjdk.adbhelper",
    "org.lsposed.manager",
    "io.github.Retmon403.oppotheme",
    "com.fankes.enforcehighrefreshrate",
    "es.chiteroman.bootloaderspoofer",
    "com.hchai.rescueplan",
    "io.github.chipppppppppp.lime",
    "dev.device.emulator",
    "com.github.dan.NoStorageRestrict",
    "com.android1500.androidfaker",
    "com.smartpack.kernelmanager",
    "ps.reso.instaeclipse",
    "top.ltfan.notdeveloper",
    "com.rel.languager",
    "not.val.cheat",
    "com.haobammmm",
    "bin.mt.plus",// 微信/QQ 核心应用
    "com.tencent.mm",          // 微信
    "com.tencent.mobileqq",    // QQ
    "com.tencent.minihd.qq",   // QQ轻量版
    "com.tencent.wework",      // 企业微信
    // 系统基础软件
    "com.android.systemui",    // 系统UI
    "com.android.settings",    // 设置
    "com.android.phone",       // 电话
    "com.android.contacts",    // 联系人
    "com.android.mms",         // 短信
    "com.android.launcher3",   // 桌面启动器（通用）
    "com.android.packageinstaller", // 应用安装器
    // 常用银行软件
    "com.icbc.mobilebank",     // 工商银行
    "com.ccb.ccbphone",        // 建设银行
    "com.abchina.mobilebank",  // 农业银行
    "com.cmbchina.psbc",       // 邮储银行
    "com.cmbchina",            // 招商银行
    "com.bankcomm",            // 交通银行
    "com.spdb.mobilebank",     // 浦发银行
    "com.hxb.android",         // 华夏银行
    "com.cib.mobilebank",      // 兴业银行
    "com.pingan.bank",         // 平安银行
    "com.abcwealth.mobile",    // 农业银行财富版
    "com.eg.android.AlipayGphone", // 支付宝（金融类）
    "com.unionpay",            // 银联
    // 厂商系统应用（兼容主流品牌）
    "com.xiaomi.misettings",   // 小米设置
    "com.huawei.systemmanager",// 华为系统管家
    "com.oppo.launcher",       // OPPO桌面
    "com.vivo.launcher",       // VIVO桌面
    "com.samsung.android.launcher", // 三星桌面
    "com.meizu.flyme.launcher" // 魅族桌面
    "me.bmax.apatch",
    "com.larus.nova",
    "com.miui.home",
    "com.sukisu.ultra",
    // 1. Android核心框架应用
    "android",                          // 系统核心进程
    "com.android.systemui",             // 系统UI
    "com.android.settings",             // 设置
    "com.android.phone",                // 电话服务
    "com.android.contacts",             // 联系人
    "com.android.mms",                  // 短信
    "com.android.launcher3",            // 原生桌面
    "com.android.packageinstaller",     // 应用安装器
    "com.android.fmradio",              // 收音机
    "com.android.music",                // 音乐播放器
    "com.android.video",                // 视频播放器
    "com.android.gallery3d",            // 图库
    "com.android.camera2",              // 相机
    "com.android.browser",              // 浏览器
    "com.android.dialer",               // 拨号器
    "com.android.contacts.syncadapter", // 联系人同步
    "com.android.providers.contacts",   // 联系人存储
    "com.android.providers.calendar",   // 日历存储
    "com.android.providers.media",      // 媒体存储
    "com.android.providers.downloads",  // 下载管理
    "com.android.downloadprovider",     // 下载服务
    "com.android.pim",                  // PIM服务
    "com.android.server.telecom",       // 通话服务
    "com.android.inputmethod.latin",    // 原生输入法
    "com.android.keyguard",             // 锁屏
    "com.android.location.fused",       // 定位服务
    "com.android.networkstack",         // 网络栈
    "com.android.wifi",                 // WIFI服务
    "com.android.bluetooth",            // 蓝牙服务
    "com.android.nfc",                  // NFC服务
    "com.android.soundrecorder",        // 录音机
    "com.android.calculator2",          // 计算器
    "com.android.calendar",             // 日历
    "com.android.clock",                // 时钟
    "com.android.fileexplorer",         // 文件管理器（原生）
    "com.android.documentsui",          // 文档管理
    "com.android.externalstorage",      // 外部存储服务
    "com.android.internal.storage",     // 内部存储服务
    "com.android.os.statsd",            // 系统统计
    "com.android.systemserver",         // 系统服务进程
    "com.android.media",                // 媒体服务
    "com.android.mediaserver",          // 媒体服务器
    "com.android.cellbroadcastreceiver",// 小区广播
    "com.android.defcontainer",         // 应用容器
    "com.android.package.verifier",     // 应用验证
    "com.android.settings.intelligence",// 设置智能服务
    "com.android.vending",              // Google Play商店
    "com.google.android.gms",           // Google Play服务
    "com.google.android.gsf",           // Google服务框架
    "com.google.android.webview",       // 系统WebView
    // 2. 厂商系统应用（主流品牌兼容）
    "com.xiaomi.misettings",            // 小米设置
    "com.xiaomi.finddevice",            // 小米查找设备
    "com.huawei.systemmanager",         // 华为系统管家
    "com.huawei.hwid",                  // 华为账号
    "com.oppo.launcher",                // OPPO桌面
    "com.oppo.settings",                // OPPO设置
    "com.vivo.launcher",                // VIVO桌面
    "com.vivo.settings",                // VIVO设置
    "com.samsung.android.launcher",     // 三星桌面
    "com.samsung.android.settings",     // 三星设置
    "com.meizu.flyme.launcher",         // 魅族桌面
    "com.oneplus.launcher",             // 一加桌面
    "com.oneplus.settings",             // 一加设置
    // 3. 系统工具类应用
    "com.android.tools",                // 系统工具集
    "com.android.shell",                // 系统Shell
    "com.android.updater",              // 系统更新
    "com.android.recovery",             // 恢复模式
    "com.android.backup",               // 备份服务
    "com.android.security",             // 安全服务
    "com.android.vpn",                  // VPN服务
    "com.android.wallpaper",            // 壁纸服务
    "com.android.theme",                // 主题服务
    "com.android.notification",         // 通知服务
    "com.android.alarmclock",           // 闹钟
    "com.android.weather",              // 天气
    "com.android.email",                // 邮件
    "com.android.voicemail",            // 语音信箱
    "com.android.callrecorder",         // 通话录音
    "com.android.simcard",              // SIM卡管理
    "com.android.telephony",            // 电话管理
    "com.android.datausage",            // 流量管理
    "com.android.battery",              // 电池管理
    "com.android.power",                // 电源管理
    "com.android.securitycenter",       // 安全中心
    "com.android.virusscan",            // 病毒扫描
    "com.android.applock",              // 应用锁
    "com.android.accessibility",        // 无障碍服务
    "com.android.speech",               // 语音服务
    "com.android.tts",                  // 文字转语音
    "com.android.translate",            // 翻译（系统级）
    "com.android.captiveportallogin",   // Captive Portal登录
    "com.android.webviewupdate",        // WebView更新
    "com.android.googleinstaller",      // Google安装器（国内机型）
    "com.android.gsf.login",            // Google登录服务
    "com.android.gms.persistent",       // Google持续服务
    "com.android.gallery",              // 旧版图库
    "com.android.mediacenter",          // 媒体中心
    "com.android.filemanager",          // 文件管理器（厂商版）
    "com.android.downloads.ui",         // 下载管理UI
    "com.android.providers.applications",// 应用提供器
    "com.android.providers.settings",   // 设置提供器
    "com.android.providers.telephony",  // 电话提供器
    "com.android.providers.media.module",// 媒体模块提供器
    // 4. 系统核心服务应用
    "com.android.server",               // 系统服务器
    "com.android.service",              // 系统服务
    "com.android.system",               // 系统核心
    "com.android.framework",            // 框架服务
    "com.android.runtime",              // 运行时服务
    "com.android.art",                  // ART运行时
    "com.android.package",              // 包管理服务
    "com.android.install",              // 安装服务
    "com.android.uninstall",            // 卸载服务
    "com.android.update",               // 更新服务
    "com.android.keystore",             // 密钥库服务
    "com.android.securitytoken",        // 安全令牌服务
    "com.android.encryption",           // 加密服务
    "com.android.accountmanager",       // 账号管理服务
    "com.android.auth",                 // 认证服务
    "com.android.session",              // 会话服务
    "com.android.cache",                // 缓存服务
    "com.android.preferences",          // 偏好设置服务
    "com.android.settingsprovider",     // 设置提供器
    "com.android.systemprovider",       // 系统提供器
    "com.android.dataprovider",         // 数据提供器
    "com.android.infoprovider",         // 信息提供器
    "com.android.contentprovider",      // 内容提供器
    "com.android.mediaprovider",        // 媒体提供器
    "com.android.locationprovider",     // 位置提供器
    "com.android.geolocationprovider",  // 地理定位提供器
    "com.android.gps",                  // GPS提供器
    "com.android.wifilocationprovider", // WIFI定位提供器
    "com.android.celllocationprovider", // 基站定位提供器
    "com.android.locationmanager",      // 位置管理器
    "com.android.networkprovider",      // 网络提供器
    "com.android.socketprovider",       // 套接字提供器
    "com.android.storageprovider",      // 存储提供器
    "com.android.memoryprovider",       // 内存提供器
    "com.android.diskprovider",         // 磁盘提供器
    "com.android.partitionprovider",    // 分区提供器
    "com.android.mountprovider",        // 挂载提供器
    "com.android.backupprovider",       // 备份提供器
    "com.android.restoreprovider",      // 恢复提供器
    "com.android.syncprovider",         // 同步提供器
    "com.android.securityprovider",     // 安全提供器
    "com.android.encryptionprovider",   // 加密提供器
    "com.android.decryptionprovider",   // 解密提供器
    "com.android.vaultprovider",        // 保险箱提供器
    "com.android.lockprovider",         // 锁定提供器
    "com.android.unlockprovider",       // 解锁提供器
    "com.android.passwordprovider",     // 密码提供器
    "com.android.passcodeprovider",     // 密码提供器
    "com.android.patternprovider",      // 图案提供器
    "com.android.fingerprintprovider",  // 指纹提供器
    "com.android.faceprovider",         // 面部提供器
    "com.android.irisprovider",         // 虹膜提供器
    "com.android.voiceprovider",        // 语音提供器
    "com.android.soundprovider",        // 声音提供器
    "com.android.audioprovider",        // 音频提供器
    "com.android.videoprovider",        // 视频提供器
    "com.android.cameraprovider",       // 相机提供器
    "com.android.microphoneprovider",   // 麦克风提供器
    "com.android.speakerprovider",      // 扬声器提供器
    "com.android.headsetprovider",      // 耳机提供器
    "com.android.bluetoothaudioprovider", // 蓝牙音频提供器
    "com.android.usbaudioprovider",     // USB音频提供器
    "com.android.hdaudioprovider",      // HD音频提供器
    "com.android.dolbyaudioprovider",   // Dolby音频提供器
    "com.android.equalizeprovider",     // 均衡器提供器
    "com.android.bassboostprovider",    // 低音增强提供器
    "com.android.virtualsurroundprovider", // 虚拟环绕提供器
    "com.android.loudnessenhancerprovider", // 响度增强提供器
    "com.android.noisereductionprovider", // 降噪提供器
    "com.android.soundfxprovider",      // 音效提供器
    "com.android.mediacodecprovider",   // 媒体编解码器提供器
    "com.android.videocodecprovider",   // 视频编解码器提供器
    "com.android.audiocodecprovider",   // 音频编解码器提供器
    "com.android.hardwarecodecprovider", // 硬件编解码器提供器
    "com.android.softwarecodecprovider", // 软件编解码器提供器
    "com.android.mediadrmprovider",     // 媒体DRM提供器
    "com.android.widevineprovider",     // Widevine DRM提供器
    "com.android.playreadyprovider",    // PlayReady DRM提供器
    "com.android.marlinprovider",       // Marlin DRM提供器
    "com.android.clearkeyprovider",     // ClearKey DRM提供器
    "com.android.drmprovider",          // DRM提供器
    "com.android.mediascannerprovider", // 媒体扫描器提供器
    "com.android.mediastoreprovider",   // 媒体存储提供器
    "com.android.mediacontrollerprovider", // 媒体控制器提供器
    "com.android.mediaplayerprovider",  // 媒体播放器提供器
    "com.android.mediarecorderprovider", // 媒体录制器提供器
    "com.android.mediamuxerprovider",   // 媒体混合器提供器
    "com.android.mediaextractorprovider", // 媒体提取器提供器
    // 5. 系统预装工具应用（用户常用）
    "com.android.filemanager",          // 文件管理器
    "com.android.downloadmanager",      // 下载管理器
    "com.android.musicplayer",          // 音乐播放器
    "com.android.videoplayer",          // 视频播放器
    "com.android.gallery",              // 图库
    "com.android.camera",               // 相机
    "com.android.browser",              // 浏览器
    "com.android.email",                // 邮件
    "com.android.calendar",             // 日历
    "com.android.contacts",             // 联系人
    "com.android.phone",                // 电话
    "com.android.sms",                  // 短信
    "com.android.mms",                  // 彩信
    "com.android.voicemail",            // 语音信箱
    "com.android.callrecorder",         // 通话录音
    "com.android.weather",              // 天气
    "com.android.clock",                // 时钟
    "com.android.calculator",           // 计算器
    "com.android.notepad",              // 记事本
    "com.android.notes",                // 笔记
    "com.android.alarmclock",           // 闹钟
    "com.android.stopwatch",            // 秒表
    "com.android.timer",                // 计时器
    "com.android.worldclock",           // 世界时钟
    "com.android.translator",           // 翻译
    "com.android.dictionary",           // 词典
    "com.android.spellchecker",         // 拼写检查
    "com.android.texttospeech",         // 文字转语音
    "com.android.speachtotext",         // 语音转文字
    "com.android.voicecommands",        // 语音命令
    "com.android.voiceassistant",       // 语音助手
    "com.android.accessibility",        // 无障碍
    "com.android.magnification",        // 放大镜
    "com.android.screenreader",         // 屏幕阅读器
    "com.android.talkback",             // 语音反馈
    "com.android.switchaccess",         // 切换控制
    "com.android.selecttoSpeak",        // 选择朗读
    "com.android.textcorrection",       // 文字校正
    "com.android.autofill",             // 自动填充
    "com.android.passwordmanager",      // 密码管理器
    "com.android.vault",                // 保险箱
    "com.android.filelock",             // 文件锁定
    "com.android.applock",              // 应用锁定
    "com.android.privacy",              // 隐私保护
    "com.android.security",             // 安全中心
    "com.android.virusscan",            // 病毒扫描
    "com.android.malwareprotection",    // 恶意软件防护
    "com.android.phishingprotection",   // 钓鱼防护
    "com.android.spamfilter",           // 垃圾邮件过滤
    "com.android.callfilter",           // 来电过滤
    "com.android.smsfilter",            // 短信过滤
    "com.android.appfilter",            // 应用过滤
    "com.android.webfilter",            // 网页过滤
    "com.android.contentfilter",        // 内容过滤
    "com.android.parentalcontrols",     // 家长控制
    "com.android.familylink",           // 家庭链接
    "com.android.kidsmode",             // 儿童模式
    "com.android.safemode",             // 安全模式
    "com.android.restrictedprofile",     // 受限配置文件
    "com.android.guestprofile",         // 访客配置文件
    "com.android.userprofile",          // 用户配置文件
    "com.android.multiusers",           // 多用户
    "com.android.userManager",          // 用户管理器
    "com.android.profilemanager",        // 配置文件管理器
    "com.android.accountmanager",        // 账号管理器
    "com.android.syncmanager",          // 同步管理器
    "com.android.backupmanager",         // 备份管理器
    "com.android.restoremanager",        // 恢复管理器
    "com.android.updatemanager",         // 更新管理器
    "com.android.installmanager",        // 安装管理器
    "com.android.uninstallmanager",      // 卸载管理器
    "com.android.packagemanager",        // 包管理器
    "com.android.appmanager",            // 应用管理器
    "com.android.processmanager",        // 进程管理器
    "com.android.memorymanager",         // 内存管理器
    "com.android.storage",              // 存储管理器
    "com.android.diskmanager",          // 磁盘管理器
    "com.android.partitionmanager",      // 分区管理器
    "com.android.volumemanager",         // 音量管理器
    "com.android.mountmanager",          // 挂载管理器
    "com.android.unmountmanager",        // 卸载管理器
    "com.android.formatmanager",         // 格式化管理器
    "com.android.scanmanager",           // 扫描管理器
    "com.android.defragmanager",         // 碎片整理管理器
    "com.android.repairmanager",         // 修复管理器
    "com.android.systemmanager",         // 系统管理器
    "com.android.device",               // 设备管理器
    "com.android.hardwaremanager",       // 硬件管理器
    "com.android.sensormanager",         // 传感器管理器
    "com.android.locationmanager",       // 位置管理器
    "com.android.networkmanager",        // 网络管理器
    "com.android.wifimanager",           // WIFI管理器
    "com.android.bluetoothmanager",      // 蓝牙管理器
    "com.android.nfcmanager",            // NFC管理器
    "com.android.usbmanager",            // USB管理器
    "com.android.batterymanager",        // 电池管理器
    "com.android.powermanager",          // 电源管理器
    "com.android.thermalmanger",         // 散热管理器
    "com.android.performancemanager",    // 性能管理器
    "com.android.powermanagement",       // 电源管理
    "com.android.batterysaver",          // 省电模式
    "com.android.lowpower",              // 低电量模式
    "com.android.extendedbattery",       // 延长电池寿命
    "com.android.batterycharging",       // 电池充电管理
    "com.android.batterycalibration",    // 电池校准
    "com.android.powersaving",           // 省电模式
    "com.android.lowbattery",            // 低电量警告
    "com.android.batteryoptimization",   // 电池优化
    "com.android.powerconsumption",      // 电量消耗监控
    "com.android.batterystats",          // 电池统计
    "com.android.powerusage",            // 电量使用情况
    "com.android.batteryhistory",        // 电池历史记录
    "com.android.powerprofile",          // 电源配置文件
    "com.android.batteryprofile",        // 电池配置文件
    "com.android.powerscheme",           // 电源方案
    "com.android.batteryscheme",         // 电池方案
    "com.android.powerplan",             // 电源计划
    "com.android.batteryplan",           // 电池计划
    "com.android.powerpolicy",           // 电源策略
    "com.android.batterypolicy",         // 电池策略
    "com.android.powergovernor",         // 电源调节器
    "com.android.batterygovernor",       // 电池调节器
    "com.android.powercontroller",       // 电源控制器
    "com.android.batterycontroller",     // 电池控制器
    "com.android.powerdaemon",           // 电源守护进程
    "com.android.batterydaemon",         // 电池守护进程
    "com.android.powerservice",          // 电源服务
    "com.android.batteryservice",        // 电池服务
    "com.android.powerprovider",         // 电源提供器
    "com.android.batteryprovider",       // 电池提供器
    "com.android.powerwidget",           // 电源小部件
    "com.android.batterywidget",         // 电池小部件
    "com.android.powernotification",     // 电源通知
    "com.android.batterynotification",   // 电池通知
    "com.android.poweralert",            // 电源警报
    "com.android.batteryalert",          // 电池警报
    "com.android.powerwarning",          // 电源警告
    "com.android.batterywarning",        // 电池警告
    "com.android.powererror",            // 电源错误
    "com.android.batteryerror",          // 电池错误
    "com.android.powerexception",        // 电源异常
    "com.android.batteryexception",      // 电池异常
    "com.android.powercrash",            // 电源崩溃
    "com.android.batterycrash",          // 电池崩溃
    "com.android.powerfailure",          // 电源故障
    "com.android.batteryfailure",        // 电池故障
    "com.android.powerreset",            // 电源重置
    "com.android.batteryreset",          // 电池重置
    "com.android.powerrestart",          // 电源重启
    "com.android.batteryrestart",        // 电池重启
    "com.android.poweroff",              // 关机
    "com.android.batteryoff",            // 电池关机
    "com.android.poweron",               // 开机
    "com.android.batteryon",             // 电池开机
    "com.android.powercycle",            // 电源循环
    "com.android.batterycycle",          // 电池循环
    "com.android.powerstatus",           // 电源状态
    "com.android.batterystatus",         // 电池状态
    "com.android.powerlevel",            // 电源级别
    "com.android.batterylevel",          // 电池级别
    "com.android.powerpercentage",       // 电源百分比
    "com.android.batterypercentage",     // 电池百分比
    "com.android.powercapacity",         // 电源容量
    "com.android.batterycapacity",       // 电池容量
    "com.android.powerhealth",           // 电源健康
    "com.android.batteryhealth",         // 电池健康
    "com.android.powerstatusbar",        // 电源状态栏
    "com.android.batterystatusbar",      // 电池状态栏
    "com.android.powericon",             // 电源图标
    "com.android.batteryicon",           // 电池图标
    "com.android.powerindicator",        // 电源指示器
    "com.android.batteryindicator",      // 电池指示器
    "com.android.powerled",              // 电源LED
    "com.android.batteryled",            // 电池LED
    "com.android.powerlight",            // 电源灯
    "com.android.batterylight",          // 电池灯
    "com.android.powernotificationlight", // 电源通知灯
    "com.android.batterynotificationlight", // 电池通知灯
    "com.android.powerflashlight",       // 电源闪光灯
    "com.android.batteryflashlight",     // 电池闪光灯
    "com.android.powercameraflash",      // 电源相机闪光灯
    "com.android.batterycameraflash",    // 电池相机闪光灯
    "com.android.powertorch",            // 电源手电筒
    "com.android.batterytorch",          // 电池手电筒
    "com.android.powerflash",            // 电源闪光
    "com.android.batteryflash",          // 电池闪光
    "com.android.powerblink",            // 电源闪烁
    "com.android.batteryblink",          // 电池闪烁
    "com.android.powerpulse",            // 电源脉冲
    "com.android.batterypulse",          // 电池脉冲
    "com.android.powervibrate",          // 电源振动
    "com.android.batteryvibrate",        // 电池振动
    "com.android.powertone",             // 电源提示音
    "com.android.batterytone",           // 电池提示音
    "com.android.poweralerttone",        // 电源警报音
    "com.android.batteryalerttone",      // 电池警报音
    "com.android.powerwarningtone",      // 电源警告音
    "com.android.batterywarningtone",    // 电池警告音
    "com.android.powererrortone",        // 电源错误音
    "com.android.batteryerrortone",      // 电池错误音
    "com.android.powerexceptiontone",    // 电源异常音
    "com.android.batteryexceptiontone",  // 电池异常音
    "com.android.powercrashtone",        // 电源崩溃音
    "com.android.batterycrashtone",      // 电池崩溃音
    "com.android.powerfailuretone",      // 电源故障音
    "com.android.batteryfailuretone",    // 电池故障音
    "com.android.powerresettone",        // 电源重置音
    "com.android.batteryresettone",      // 电池重置音
    "com.android.powerrestarttone",      // 电源重启音
    "com.android.batteryrestarttone",    // 电池重启音
    "com.android.powerofftone",          // 关机音
    "com.android.batteryofftone",        // 电池关机音
    "com.android.powerontone",           // 开机音
    "com.android.batteryontone",         // 电池开机音
    "com.android.powercycletone",        // 电源循环音
    "com.android.batterycycletone",      // 电池循环音
    "com.android.powerstatustone",       // 电源状态音
    "com.android.batterystatustone",     // 电池状态音
    "com.android.powerleveltone",        // 电源级别音
    "com.android.batteryleveltone",      // 电池级别音
    "com.android.powerpercentagetone",   // 电源百分比音
    "com.android.batterypercentagetone", // 电池百分比音
    "com.android.powercapacitytone",     // 电源容量音
    "com.android.batterycapacitytone",   // 电池容量音
    "com.android.powerhealthtone",       // 电源健康音
    "com.android.batteryhealthtone",     // 电池健康音
    "com.android.powerstatustbartone",   // 电源状态栏音
    "com.android.batterystatustbartone", // 电池状态栏音
    "com.android.powericontone",         // 电源图标音
    "com.android.batteryicontone",       // 电池图标音
    "com.android.powerindicatortone",    // 电源指示器音
    "com.android.batteryindicatortone",  // 电池指示器音
    "com.android.powerledtone",          // 电源LED音
    "com.android.batteryledtone",        // 电池LED音
    "com.android.powerlighttone",        // 电源灯音
    "com.android.batterylighttone",      // 电池灯音
    "com.android.powernotificationlighttone", // 电源通知灯音
    "com.android.batterynotificationlighttone", // 电池通知灯音
    "com.android.powerflashlighttone",   // 电源闪光灯音
    "com.android.batteryflashlighttone", // 电池闪光灯音
    "com.android.powercameraflashtone",  // 电源相机闪光灯音
    "com.android.batterycameraflashtone", // 电池相机闪光灯音
    "com.android.powertorchtonetone",    // 电源手电筒音
    "com.android.batterytorchtonetone",  // 电池手电筒音
    "com.android.powerflashtone",        // 电源闪光音
    "com.android.batteryflashtone",      // 电池闪光音
    "com.android.powerblinktone",        // 电源闪烁音
    "com.android.batteryblinktone",      // 电池闪烁音
    "com.android.powerpulsestone",       // 电源脉冲音
    "com.android.batterypulsestone",     // 电池脉冲音
    "com.android.powervibratetone",      // 电源振动音
    "com.android.batteryvibratetone",    // 电池振动音
    "com.android.powertonealert",        // 电源提示音警报
    "com.android.batterytonealert",      // 电池提示音警报
    "com.android.poweralerttonealert",   // 电源警报音警报
    "com.android.batteryalerttonealert", // 电池警报音警报
    "com.android.powerwarningtonealert", // 电源警告音警报
    "com.android.batterywarningtonealert", // 电池警告音警报
    "com.android.powererrortonealert",   // 电源错误音警报
    "com.android.batteryerrortonealert", // 电池错误音警报
    "com.android.powerexceptiontonealert", // 电源异常音警报
    "com.android.batteryexceptiontonealert", // 电池异常音警报
    "com.android.powercrashtonealert",   // 电源崩溃音警报
    "com.android.batterycrashtonealert", // 电池崩溃音警报
    "com.android.powerfailuretonealert", // 电源故障音警报
    "com.android.batteryfailuretonealert", // 电池故障音警报
    "com.android.powerresettonealert",   // 电源重置音警报
    "com.android.batteryresettonealert", // 电池重置音警报
    "com.android.powerrestarttonealert", // 电源重启音警报
    "com.android.batteryrestarttonealert", // 电池重启音警报
    "com.android.powerofftonealert",     // 关机音警报
    "com.android.batteryofftonealert",   // 电池关机音警报
    "com.android.powerontonealert",      // 开机音警报
    "com.android.batteryontonealert",    // 电池开机音警报
    "com.android.powercycletonealert",   // 电源循环音警报
    "com.android.batterycycletonealert", // 电池循环音警报
    "com.android.powerstatustonealert",  // 电源状态音警报
    "com.android.batterystatustonealert", // 电池状态音警报
    "com.android.powerleveltonealert",   // 电源级别音警报
    "com.android.batteryleveltonealert", // 电池级别音警报
    "com.android.powerpercentagetonealert", // 电源百分比音警报
    "com.android.batterypercentagetonealert", // 电池百分比音警报
    "com.android.powercapacitytonealert", // 电源容量音警报
    "com.android.batterycapacitytonealert", // 电池容量音警报
    "com.android.powerhealthtonealert",  // 电源健康音警报
    "com.android.batteryhealthtonealert", // 电池健康音警报
    "com.android.powerstatustbartonealert", // 电源状态栏音警报
    "com.android.batterystatustbartonealert", // 电池状态栏音警报
    "com.android.powericontonealert",    // 电源图标音警报
    "com.android.batteryicontonealert",  // 电池图标音警报
    "com.android.powerindicatortonealert", // 电源指示器音警报
    "com.android.batteryindicatortonealert", // 电池指示器音警报
    "com.android.powerledtonealert",     // 电源LED音警报
    "com.android.batteryledtonealert",   // 电池LED音警报
    "com.android.powerlighttonealert",   // 电源灯音警报
    "com.android.batterylighttonealert", // 电池灯音警报
    "com.android.powernotificationlighttonealert", // 电源通知灯音警报
    "com.android.batterynotificationlighttonealert", // 电池通知灯音警报
    "com.android.powerflashlighttonealert", // 电源闪光灯音警报
    "com.android.batteryflashlighttonealert", // 电池闪光灯音警报
    "com.android.powercameraflashtonealert", // 电源相机闪光灯音警报
    "com.android.batterycameraflashtonealert", // 电池相机闪光灯音警报
    "com.android.powertorchtonetonealert", // 电源手电筒音警报
    "com.android.batterytorchtonetonealert", // 电池手电筒音警报
    "com.android.powerflashtonealert",   // 电源闪光音警报
    "com.android.batteryflashtonealert", // 电池闪光音警报
    "com.android.powerblinktonealert",   // 电源闪烁音警报
    "com.android.batteryblinktonealert", // 电池闪烁音警报
    "com.android.powerpulsestonealert",  // 电源脉冲音警报
    "com.android.batterypulsestonealert", // 电池脉冲音警报
    "com.android.powervibratetonealert", // 电源振动音警报
    "com.android.batteryvibratetonealert",  // 电池振动音警报
    // 新增包名开始
    "com.miui.screenrecorder",
    "com.mediatek.ims",
    "com.android.cts.priv.ctsshim",
    "com.miui.contentextension",
    "com.android.uwb.resources",
    "com.android.internal.display.cutout.emulation.corner",
    "com.google.android.ext.services",
    "com.android.adservices.api",
    "com.android.internal.display.cutout.emulation.double",
    "com.android.providers.telephony",
    "com.android.dynsystem",
    "com.miui.powerkeeper",
    "com.unionpay.tsmservice.mi",
    "com.android.healthconnect.controller",
    "neo.rom.up",
    "com.miui.qr",
    "com.android.providers.calendar",
    "com.miui.contentcatcher",
    "android.miui.home.launcher.res",
    "com.mediatek.telephony",
    "com.xiaomi.vipaccount",
    "com.android.providers.media",
    "com.milink.service",
    "com.android.networkstack.tethering.overlay",
    "com.google.android.onetimeinitializer",
    "com.android.health.connect.backuprestore",
    "com.google.android.ext.shared",
    "com.xiaomi.cameramind",
    "com.mediatek.datachannel.service",
    "com.mediatek.location.lppe.main",
    "com.android.virtualmachine.res",
    "com.mobiletools.systemhelper",
    "com.xiaomi.account",
    "com.android.server.deviceconfig.resources",
    "com.android.wallpapercropper",
    "com.bsp.catchlog",
    "com.xiaomi.cameratools",
    "com.mediatek.SettingsProviderResOverlay",
    "miui.systemui.plugin",
    "com.android.providers.telephony.overlay.miui",
    "com.xiaomi.mi_connect_service",
    "com.miui.themestore",
    "com.xiaomi.micloud.sdk",
    "com.android.avatarpicker",
    "com.android.egg",
    "com.pingan.paces.ccms",
    "io.github.qauxv",
    "com.miui.packageinstaller",
    "com.android.networkstack.tethering.inprocess.overlay",
    "com.miui.gallery",
    "com.android.updater",
    "com.xiaomi.bluetooth.rro.device.config.overlay",
    "com.android.wifi.resources.overlay",
    "com.android.externalstorage",
    "com.mediatek.ygps",
    "com.xiaomi.gamecenter.sdk.service",
    "com.android.htmlviewer",
    "com.miui.extraphoto",
    "com.miui.securityadd",
    "com.android.thememanager.customthemeconfig.config.overlay",
    "com.android.companiondevicemanager",
    "com.android.quicksearchbox",
    "com.android.mms.service",
    "com.android.providers.downloads",
    "com.xiaomi.payment",
    "com.google.android.networkstack.tethering.overlay",
    "com.miui.securitycenter",
    "com.mediatek.engineermode",
    "com.android.federatedcompute.services",
    "bin.mt.termex",
    "com.venter.hopweb",
    "com.mediatek.cellbroadcastuiresoverlay",
    "com.mediatek.omacp",
    "com.miui.thirdappassistant",
    "com.android.networkstack.inprocess.overlay",
    "com.google.android.wifi.resources.xiaomi",
    "com.android.browser",
    "com.miui.systemAdSolution",
    "com.xiaomi.aiasst.vision",
    "com.miui.tsmclient",
    "com.google.android.configupdater",
    "com.android.soundrecorder",
    "com.tencent.androidqqmail",
    "com.xiaomi.trustservice",
    "com.miui.guardprovider",
    "com.mediatek.mt6985.gamedriver",
    "com.android.safetycenter.resources",
    "com.android.providers.downloads.ui",
    "com.xiaomi.touchservice",
    "com.xiaomi.phone",
    "com.android.vending",
    "com.android.pacprocessor",
    "com.android.simappdialog",
    "com.android.networkstack",
    "com.xingin.xhs",
    "com.miui.backup",
    "com.android.settings.overlay.miui",
    "com.miui.notification",
    "com.xiaomi.barrage",
    "com.android.internal.display.cutout.emulation.hole",
    "com.miui.daemon",
    "com.xiaomi.ab",
    "com.android.certinstaller",
    "com.android.carrierconfig",
    "com.google.android.marvin.talkback",
    "com.android.internal.systemui.navbar.threebutton",
    "com.xiaomi.migameservice",
    "com.android.wifi.dialog",
    "com.android.camera.overlay",
    "com.miui.hybrid",
    "com.miui.securitymanager",
    "com.miui.securitycore",
    "com.miui.carlink",
    "com.miui.uireporter",
    "com.mi.health",
    "cn.wps.moffice_eng.xiaomi.lite",
    "com.android.nfc",
    "com.android.ons",
    "com.android.stk",
    "com.android.backupconfirm",
    "com.mfashiongallery.emag",
    "fun.fpa",
    "com.android.provision",
    "io.github.vvb2060.magisk",
    "com.mediatek.smartratswitch.service",
    "com.android.settings.intelligence",
    "com.android.overlay.gmscontactprovider",
    "com.miui.miwallpaper.overlay.customize",
    "com.android.compos.payload",
    "com.mediatek.magtapp",
    "com.android.systemui.accessibility.accessibilitymenu",
    "com.miui.compass",
    "com.miui.cit",
    "com.miui.rom",
    "com.miuix.editor",
    "com.android.providers.settings",
    "com.android.sharedstoragebackup",
    "com.mediatek.batterywarning",
    "com.miui.personalassistant",
    "com.android.dreams.basic",
    "com.android.se",
    "com.android.rkpdapp",
    "com.mediatek",
    "hub.lab.hsx",
    "com.android.fileexplorer",
    "com.miui.voicetrigger",
    "com.xiaomi.macro",
    "com.miui.audioeffect",
    "com.android.systemui.overlay.miui",
    "com.android.inputsettings.overlay.miui",
    "com.google.android.overlay.gmsconfig",
    "com.android.overlay.gmssettings",
    "com.miui.cloudbackup",
    "com.omarea.vtools",
    "com.android.server.telecom",
    "xzr.hkf",
    "com.qq.qcloud",
    "com.google.android.overlay.modules.ext.services.cn",
    "com.xiaomi.aireco",
    "com.android.keychain",
    "com.android.camera",
    "com.xiaomi.mtb",
    "com.xiaomi.xmsf",
    "com.miui.mishare.connectivity",
    "com.android.calllogbackup",
    "com.mediatek.atmwifimeta",
    "android.aosp.overlay",
    "com.xiaomi.xmsfkeeper",
    "com.android.localtransport",
    "com.android.carrierdefaultapp",
    "com.miui.wallpaper.overlay.customize",
    "com.android.credentialmanager",
    "com.android.theme.font.notoserifsource",
    "com.xiaomi.joyose",
    "com.android.intentresolver",
    "com.yiyou.ga",
    "com.dna.tools",
    "com.android.wifi.system.mainline.resources.overlay",
    "com.android.internal.systemui.navbar.transparent",
    "com.miui.notes",
    "com.android.phone.overlay.miui",
    "com.xiaomi.market",
    "com.xiaomi.misettings",
    "com.miui.cloudservice",
    "com.mediatek.atci.service",
    "com.google.android.documentsui",
    "com.xiaomi.gnss.polaris",
    "com.goodix.fingerprint.setting",
    "com.android.providers.partnerbookmarks",
    "com.android.role.notes.enabled",
    "com.android.networkstack.overlay.miui",
    "com.miui.calculator",
    "com.mediatek.voicecommand",
    "com.miui.settings.rro.device.type.overlay",
    "com.android.apps.tag",
    "com.miui.miwallpaper",
    "com.miui.securityinputmethod",
    "com.xiaomi.gamecenter",
    "com.android.systemui.navigation.bar.overlay",
    "com.giraffe", "com.giraffe",
    "com.miui.analytics",
    "com.android.settings",
    "com.android.connectivity.resources",
    "com.miui.system.overlay",
    "com.miui.micloudsync",
    "com.android.internal.display.cutout.emulation.tall",
    "com.android.networkstack.overlay",
    "com.android.modulemetadata",
    "com.xiaomi.mibrain.speech",
    "com.android.carrierconfig.overlay.miui",
    "android",
    "com.android.contacts",
    "com.miui.huanji",
    "com.miui.settings.rro.device.hide.statusbar.overlay",
    "android.miui.overlay",
    "com.miui.vsimcore",
    "com.android.bankabc",
    "com.android.mms",
    "com.android.mtp",
    "com.xiaomi.simactivate.service",
    "com.xiaomi.registration",
    "com.miui.phrase",
    "com.miui.player",
    "com.miui.miservice",
    "com.xiaomi.phone.overlay",
    "com.android.statementservice",
    "com.miui.system",
    "com.mediatek.mdmlsample",
    "com.android.overlay.systemui",
    "com.android.calendar",
    "com.mediatek.frameworkresoverlay",
    "com.android.managedprovisioning.overlay",
    "com.miui.virtualsim",
    "com.debug.loggerui",
    "com.android.overlay.gmssettingprovider",
    "com.miui.systemui.devices.overlay",
    "com.miui.aod",
    "com.mediatek.miravision.ui",
    "com.xiaomi.location.fused",
    "com.android.printspooler",
    "com.miui.misound",
    "org.ifaa.aidl.manager",
    "com.android.incallui",
    "com.android.systemui.gesture.line.overlay",
    "com.duokan.phone.remotecontroller",
    "com.miui.bugreport",
    "com.android.inputdevices",
    "com.fido.asm",
    "com.android.bips",
    "com.mediatek.zramwritebackoverlay",
    "com.newcall.overlay.miui",
    "com.android.cellbroadcastreceiver",
    "com.google.android.webview",
    "com.mipay.wallet",
    "com.android.bluetooth.overlay",
    "com.android.server.telecom.overlay.miui",
    "com.android.cellbroadcastservice",
    "com.xiaomi.aicr",
    "com.google.android.gms",
    "com.google.android.gsf",
    "com.android.wifi.resources",
    "com.android.cameraextensions",
    "com.xiaomi.finddevice",
    "com.mediatek.FrameworkResOverlayExt",
    "com.android.proxyhandler",
    "com.android.internal.display.cutout.emulation.waterfall",
    "com.android.devicediagnostics",
    "com.miui.newhome",
    "com.miui.nextpay",
    "com.miui.video",
    "com.miui.wmsvc",
    "com.android.overlay.cngmstelecomm",
    "com.android.providers.settings.overlay",
    "com.miui.miwallpaper.config.overlay",
    "com.google.android.printservice.recommendation",
    "com.xiaomi.mirror",
    "com.android.managedprovisioning",
    "com.android.networkstack.tethering",
    "android.aosp.overlay.telephony",
    "com.mediatek.capctrl.service",
    "com.tencent.soter.soterserver",
    "com.miui.audiomonitor",
    "com.xiaomi.otrpbroker",
    "com.mediatek.MtkSettingsResOverlay",
    "com.google.android.accessibility.switchaccess",
    "com.sohu.inputmethod.sogou.xiaomi",
    "com.miui.touchassistant",
    "com.xiaomi.mis",
    "com.xiaomi.ugd",
    "com.mediatek.callrecorder",
    "com.baidu.BaiduMap",
    "com.byyoung.setting",
    "com.trustonic.teeservice",
    "com.android.wallpaper.livepicker",
    "com.sevtinge.hyperceiler",
    "com.miHoYo.hkrpg",
    "com.xiaomi.bluetooth",
    "com.xiaomi.metoknlp",
    "com.google.android.cellbroadcastservice.overlay.miui",
    "com.miui.cleanmaster",
    "com.android.storagemanager",
    "com.miui.weather2",
    "com.google.android.networkstack.overlay",
    "com.mediatek.lbs.em2.ui",
    "com.xiaomi.scanner",
    "com.miui.systemui.carriers.overlay",
    "com.android.vpndialogs",
    "android.miui.overlay.telephony",
    "com.cam001.selfie361",
    "com.android.wallpaperbackup",
    "com.ysy.ladbs",
    "com.android.providers.blockednumber",
    "com.android.wifi.system.resources.overlay",
    "com.android.overlay.gmstelecomm",
    "com.android.providers.media.module",
    "com.android.thememanager",
    "com.android.systemui",
    "icu.nullptr.nativetest",
    "com.lbe.security.miui",
    "com.android.bluetooth",
    "com.android.captiveportallogin",
    "com.android.appsearch.apk",
    "com.snda.lantern.wifilocating",
    "com.android.devicelockcontroller",
    "com.miui.home",
    "com.xiaomi.digitalkey",
    "info.muge.appshare",
    "com.tencent.mm",
    "com.tencent.tmgp.sgame",
    "org.telegram.messenger.web",
    "com.xiaofeiji.app.disk",
    "com.magicalstory.AppStore",
    "net.imknown.android.forefrontinfo",
    "com.absinthe.libchecker",
    "com.android.mh.d1717123160864103920",
    "cn.tc.umu",
    "com.android.taose2024",
    "idm.internet.download.manager.plus",
    "com.sankuai.meituan",
    "com.magicalstory.community",
    "com.miui.miwallpaper.earth",
    "com.labx.hxaudio",
    "lin.xposed",
    "me.hoshino.novpndetect",
    "com.qgvoice.youth",
    "bin.mt.plus.canary",
    "moe.shizuku.privileged.api",
    "com.xiaomi.hyper.aiphoto",
    "github.tornaco.android.thanos",
    "com.one.ncnn.realsr",
    "com.xmcy.hykb",
    "com.adguard.android",
    "li.songe.gkd",
    "com.guoshi.httpcanary",
    "com.samsung.agc.gcam84",
    "com.zl.aibrowser",
    "com.tencent.gamehelper.pg",
    "com.android.providers.telephony.auto_generated_characteristics_rro",
    "com.geshi.formatfactory",
    "com.catxk.n20",
    "com.superpowered.superpoweredlatency",
    "com.fantasytat.propdor",
    "com.lion.market",
    "com.x1y9.probe",
    "com.qiyiapp.cloud",
    "com.chinamworld.bocmbci",
    "com.AdGPortableclient",
    "com.mgoogle.android.gmsnp",
    "com.hero.dna.gf",
    "org.matrix.chromext",
    "me.neko.lotus",
    "com.mediatek.duraspeed",
    "com.google.android.trichromelibrary_677826033",
    "com.moralnorm.customrefreshrate",
    "io.github.devriesl.raptormark",
    "net.afdian.afdian"
    // 新增包名结束
};
#define ALLOW_LIST_SIZE (sizeof(allow_list)/sizeof(allow_list[0]))

// 核心允许文件夹列表（仅允许这些文件夹操作，8大类合法场景）
static const char *allow_folder_list[] = {
    // 1.Hook/注入工具（合法开发场景）
    "xposed_temp",
    "lsposed_cache",
    "hook_inject_data",
    "xp_module_cache",
    "lspatch_temp",
    "hook_framework",
    // 2.ROOT/系统工具（合法管理场景）
    "magisk_temp",
    "ksu_cache",
    "system_modify",
    "root_tool_data",
    "kernel_mod_dir",
    // 3.数据管理工具（合法隐私场景）
    "privacy_steal",
    "data_crack",
    "info_collect",
    "secret_monitor",
    "data_leak_dir",
    // 4.应用开发工具（合法调试场景）
    "apk_modify",
    "pirate_apk",
    "app_cracked",
    "patch_apk_dir",
    "illegal_install",
    // 5.终端/脚本工具（合法开发场景）
    "termux_data",
    "apktool_temp",
    "reverse_engineer",
    "hack_tool_data",
    "shell_script",
    // 6.模拟器/虚拟环境（合法测试场景）
    "emulator_data",
    "virtual_env",
    "fake_device",
    "emulator_cache",
    // 7.插件/广告工具（合法使用场景）
    "ad_plugin",
    "malicious_plugin",
    "plugin_hack",
    "ad_inject",
    // 8.临时操作文件夹（合法临时场景）
    "risk_temp",
    "malicious_dir",
    "temp_hack",
    "unsafe_cache"
};
#define ALLOW_FOLDER_SIZE (sizeof(allow_folder_list)/sizeof(allow_folder_list[0]))

// 白名单逻辑：未命中允许列表则拦截（包名+文件夹双重校验）
static int is_blocked_path(const char *path) {
    size_t prefix_len = strlen(TARGET_PATH);
    if (strncmp(path, TARGET_PATH, prefix_len) != 0) return 0;
    
    const char *target_part = path + prefix_len;
    char target_buf[128];
    size_t i = 0;
    while (*target_part && *target_part != '/' && *target_part != '\\' && i < sizeof(target_buf) - 1) {
        target_buf[i++] = *target_part++;
    }
    target_buf[i] = '\0';
    
    // 先校验包名白名单
    for (size_t j = 0; j < ALLOW_LIST_SIZE; ++j) {
        if (strcmp(target_buf, allow_list[j]) == 0) return 0; // 命中白名单，不拦截
    }
    // 再校验文件夹白名单
    for (size_t k = 0; k < ALLOW_FOLDER_SIZE; ++k) {
        if (strcmp(target_buf, allow_folder_list[k]) == 0) return 0; // 命中白名单，不拦截
    }
    return 1; // 未命中任何白名单，拦截
}

// mkdirat钩子：拦截白名单外文件夹创建
static void before_mkdirat(hook_fargs4_t *args, void *udata) {
    const char __user *filename_user = (const char __user *)syscall_argn(args, 1);
    char filename_kernel[PATH_MAX];
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel));
    
    if (len <= 0 || len >= sizeof(filename_kernel)) return;
    filename_kernel[len] = '\0';
    
    if (strncmp(filename_kernel, TARGET_PATH, TARGET_PATH_LEN) == 0 && is_blocked_path(filename_kernel)) {
        pr_warn("[HMA++]mkdirat: Denied (not in allowlist) to create %s\n", filename_kernel);
        args->skip_origin = 1;
        args->ret = -EACCES;
    }
}

// chdir钩子：拦截白名单外文件夹访问
static void before_chdir(hook_fargs1_t *args, void *udata) {
    const char __user *filename_user = (const char __user *)syscall_argn(args, 0);
    char filename_kernel[PATH_MAX];
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel));
    
    if (len <= 0 || len >= sizeof(filename_kernel)) return;
    filename_kernel[len] = '\0';
    
    if (strncmp(filename_kernel, TARGET_PATH, TARGET_PATH_LEN) == 0 && is_blocked_path(filename_kernel)) {
        pr_warn("[HMA++]chdir: Denied (not in allowlist) to %s\n", filename_kernel);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}

// rmdir/unlinkat钩子：拦截白名单外文件夹删除
static void before_rmdir(hook_fargs4_t *args, void *udata) {
    const char __user *filename_user = (const char __user *)syscall_argn(args, 1);
    int flags = (int)syscall_argn(args, 2);
    char filename_kernel[PATH_MAX];
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel));
    
    if (len <= 0 || len >= sizeof(filename_kernel)) return;
    filename_kernel[len] = '\0';
    
    if ((flags & 0x200) && strncmp(filename_kernel, TARGET_PATH, TARGET_PATH_LEN) == 0 && is_blocked_path(filename_kernel)) {
        pr_warn("[HMA++]rmdir/unlinkat: Denied (not in allowlist) to %s\n", filename_kernel);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}

// fstatat钩子：拦截白名单外文件夹状态查询
static void before_fstatat(hook_fargs4_t *args, void *udata) {
    const char __user *filename_user = (const char __user *)syscall_argn(args, 1);
    char filename_kernel[PATH_MAX];
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel));
    
    if (len <= 0 || len >= sizeof(filename_kernel)) return;
    filename_kernel[len] = '\0';
    
    if (strncmp(filename_kernel, TARGET_PATH, TARGET_PATH_LEN) == 0 && is_blocked_path(filename_kernel)) {
        pr_warn("[HMA++]fstatat/stat: Denied (not in allowlist) to %s\n", filename_kernel);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}

// 模块初始化：挂钩目标syscall
static long mkdir_hook_init(const char *args, const char *event, void *__user reserved) {
    hook_err_t err;
    pr_info("[HMA++]HMA++ init (allowlist mode). Hooking core syscalls...\n");
    
    // 挂钩mkdirat
    err = hook_syscalln(__NR_mkdirat, 3, before_mkdirat, NULL, NULL);
    if (err) { pr_err("[HMA++]Hook mkdirat failed: %d\n", err); return -EINVAL; }
    // 挂钩chdir
    err = hook_syscalln(__NR_chdir, 1, before_chdir, NULL, NULL);
    if (err) { pr_err("[HMA++]Hook chdir failed: %d\n", err); return -EINVAL; }
    // 挂钩rmdir/unlinkat
#if defined(__NR_rmdir)
    err = hook_syscalln(__NR_rmdir, 1, before_rmdir, NULL, NULL);
#elif defined(__NR_unlinkat)
    err = hook_syscalln(__NR_unlinkat, 4, before_rmdir, NULL, NULL);
#else
#   error "No suitable syscall for rmdir"
#endif
    if (err) { pr_err("[HMA++]Hook rmdir/unlinkat failed: %d\n", err); return -EINVAL; }
    // 挂钩fstatat
#ifdef __NR_newfstatat
    err = hook_syscalln(__NR_newfstatat, 4, before_fstatat, NULL, NULL);
#elif defined(__NR_fstatat64)
    err = hook_syscalln(__NR_fstatat64, 4, before_fstatat, NULL, NULL);
#endif
    if (err) { pr_err("[HMA++]Hook fstatat failed: %d\n", err); return -EINVAL; }
    
    pr_info("[HMA++]All core syscalls hooked successfully (allowlist mode).\n");
    return 0;
}

// 模块退出：解绑syscall
static long mkdir_hook_exit(void *__user reserved) {
    pr_info("[HMA++]HMA++ exit (allowlist mode). Unhooking syscalls...\n");
    unhook_syscalln(__NR_mkdirat, before_mkdirat, NULL);
    unhook_syscalln(__NR_chdir, before_chdir, NULL);
#if defined(__NR_rmdir)
    unhook_syscalln(__NR_rmdir, before_rmdir, NULL);
#elif defined(__NR_unlinkat)
    unhook_syscalln(__NR_unlinkat, before_rmdir, NULL);
#endif
#ifdef __NR_newfstatat
    unhook_syscalln(__NR_newfstatat, before_fstatat, NULL);
#elif defined(__NR_fstatat64)
    unhook_syscalln(__NR_fstatat64, before_fstatat, NULL);
#endif
    pr_info("[HMA++]All syscalls unhooked successfully (allowlist mode).\n");
    return 0;
}

KPM_INIT(mkdir_hook_init);
KPM_EXIT(mkdir_hook_exit);
