#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h> // For __NR_mkdirat
#include <linux/uaccess.h>
#include <syscall.h>
#include <linux/string.h>
#include <kputils.h>
#include <linux/fs.h>
#include <linux/errno.h>    // For EACCES and EPERM
#include <accctl.h>         // For set_priv_sel_allow and related functions
#include <uapi/linux/limits.h>   // For PATH_MAX
#include <linux/kernel.h>   // For snprintf

// 补充必要的前向声明（完全不依赖asm/current.h）
struct task_struct;  // 前向声明进程结构体
struct mm_struct;    // 前向声明内存管理结构体
struct file;         // 前向声明文件结构体
struct path;         // 前向声明路径结构体

// 显式声明内核标准函数（替代current宏）
extern struct task_struct *get_current(void);
extern char *d_path(const struct path *path, char *buf, size_t buflen);

// 补充pr_debug定义，避免隐式声明警告
#ifndef pr_debug
#define pr_debug(fmt, ...) pr_info("[DEBUG] " fmt, ##__VA_ARGS__)
#endif

KPM_NAME("HMA++ Next");
KPM_VERSION("1.5");
KPM_LICENSE("GPLv3");
KPM_AUTHOR("NightFallsLikeRain");
KPM_DESCRIPTION("核心风险拦截（白名单模式）");

#define TARGET_PATH "/storage/emulated/0/Android/data/"
#define TARGET_PATH_LEN (sizeof(TARGET_PATH) - 1)
#define SYSTEM_PATH_PREFIX "/system/"
#define SYSTEM_PATH_LEN (sizeof(SYSTEM_PATH_PREFIX) - 1)

// 系统应用专属白名单（核心系统功能，全覆盖Android框架+厂商系统）
static const char *system_app_allow_list[] = {
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
    // 厂商系统应用（主流品牌兼容）
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
    // 系统工具类应用
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
    // 常用第三方核心应用（补充）
    "com.tencent.mm",          // 微信
    "com.tencent.mobileqq",    // QQ
    "com.tencent.minihd.qq",   // QQ轻量版
    "com.tencent.wework",      // 企业微信
    "com.eg.android.AlipayGphone", // 支付宝
    "com.unionpay",            // 银联
    "com.icbc.mobilebank",     // 工商银行
    "com.ccb.ccbphone",        // 建设银行
    "com.abchina.mobilebank",  // 农业银行
    "com.cmbchina",            // 招商银行
    "com.bankcomm",            // 交通银行
    "com.spdb.mobilebank",     // 浦发银行
    "com.hxb.android",         // 华夏银行
    "com.cib.mobilebank",      // 兴业银行
    "com.pingan.bank",         // 平安银行
    "com.abcwealth.mobile"     // 农业银行财富版
};
#define SYSTEM_APP_ALLOW_LIST_SIZE (sizeof(system_app_allow_list)/sizeof(system_app_allow_list[0]))

// 第三方应用白名单（原allow_list，保留并去重）
static const char *third_party_allow_list[] = {
    "com.silverlab.app.deviceidchanger.free",
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
    "bin.mt.plus",
    "me.bmax.apatch",
    "com.larus.nova",
    "com.miui.home",
    "com.sukisu.ultra"
};
#define THIRD_PARTY_ALLOW_LIST_SIZE (sizeof(third_party_allow_list)/sizeof(third_party_allow_list[0]))

// 核心允许文件夹列表（仅允许这些文件夹操作，8大类合法场景）
static const char *allow_folder_list[] = {
    "xposed_temp", "lsposed_cache", "hook_inject_data", "xp_module_cache", "lspatch_temp", "hook_framework",
    "magisk_temp", "ksu_cache", "system_modify", "root_tool_data", "kernel_mod_dir",
    "privacy_steal", "data_crack", "info_collect", "secret_monitor", "data_leak_dir",
    "apk_modify", "pirate_apk", "app_cracked", "patch_apk_dir", "illegal_install",
    "termux_data", "apktool_temp", "reverse_engineer", "hack_tool_data", "shell_script",
    "emulator_data", "virtual_env", "fake_device", "emulator_cache",
    "ad_plugin", "malicious_plugin", "plugin_hack", "ad_inject",
    "risk_temp", "malicious_dir", "temp_hack", "unsafe_cache"
};
#define ALLOW_FOLDER_SIZE (sizeof(allow_folder_list)/sizeof(allow_folder_list[0]))

// 判断当前进程是否为/system路径下的应用（无current依赖版）
static int is_system_path_app(void) {
    char exe_path[PATH_MAX];
    int ret;
    struct task_struct *task;
    struct mm_struct *mm;
    struct file *exe_file;
    struct path *f_path;

    // 1. 使用内核标准函数get_current()获取当前进程（替代current宏）
    task = get_current();
    if (!task) return 0;

    // 2. 通过偏移量访问mm成员（避免依赖结构体完整定义）
    mm = *(struct mm_struct **)((char *)task + offsetof(struct task_struct, mm));
    if (!mm) return 0;

    // 3. 通过偏移量访问exe_file成员
    exe_file = *(struct file **)((char *)mm + offsetof(struct mm_struct, exe_file));
    if (!exe_file) return 0;

    // 4. 通过偏移量访问f_path成员
    f_path = (struct path *)((char *)exe_file + offsetof(struct file, f_path));
    if (!f_path) return 0;

    // 5. 调用d_path获取进程可执行文件路径
    ret = d_path(f_path, exe_path, sizeof(exe_path));
    if (ret < 0 || ret >= sizeof(exe_path)) {
        return 0; // 路径获取失败，不视为系统应用
    }
    exe_path[ret] = '\0'; // 正确终止字符串

    // 6. 判断路径是否以/system/开头（覆盖所有系统目录）
    if (strncmp(exe_path, SYSTEM_PATH_PREFIX, SYSTEM_PATH_LEN) == 0) {
        pr_debug("[HMA++]Allow system path app: %s\n", exe_path);
        return 1;
    }

    return 0;
}

// 白名单逻辑：系统路径应用 → 系统应用包名 → 第三方应用 → 允许文件夹，任一命中则放行
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
    
    // 1. 最高优先级：/system路径下的应用直接放行
    if (is_system_path_app()) {
        return 0;
    }
    
    // 2. 校验系统应用白名单
    for (size_t j = 0; j < SYSTEM_APP_ALLOW_LIST_SIZE; ++j) {
        if (strcmp(target_buf, system_app_allow_list[j]) == 0) {
            pr_debug("[HMA++]Allow system app: %s\n", target_buf);
            return 0;
        }
    }
    
    // 3. 校验第三方应用白名单
    for (size_t j = 0; j < THIRD_PARTY_ALLOW_LIST_SIZE; ++j) {
        if (strcmp(target_buf, third_party_allow_list[j]) == 0) {
            pr_debug("[HMA++]Allow third-party app: %s\n", target_buf);
            return 0;
        }
    }
    
    // 4. 校验允许文件夹白名单
    for (size_t k = 0; k < ALLOW_FOLDER_SIZE; ++k) {
        if (strcmp(target_buf, allow_folder_list[k]) == 0) {
            pr_debug("[HMA++]Allow trusted folder: %s\n", target_buf);
            return 0;
        }
    }
    
    // 未命中任何白名单，拦截
    return 1;
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
    pr_info("[HMA++]System app allowlist size: %zu, Third-party app allowlist size: %zu\n",
            SYSTEM_APP_ALLOW_LIST_SIZE, THIRD_PARTY_ALLOW_LIST_SIZE);
    
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
