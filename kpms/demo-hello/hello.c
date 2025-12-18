#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h>
#include <linux/uaccess.h>
#include <syscall.h>
#include <linux/string.h>
#include <kputils.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <uapi/linux/limits.h>
#include <linux/kernel.h>

// 模块元信息（无控制参数，加载即生效）
KPM_NAME("HMA++ Next");
KPM_VERSION("1.0.10");
KPM_LICENSE("GPLv2");
KPM_AUTHOR("NightFallsLikeRain");
KPM_DESCRIPTION("全应用风险+广告拦截（风险白名单机制+广告黑名单，加载即开启，无控制参数）");

// 核心宏定义（移除路径限制，适配所有应用）
#define MAX_PACKAGE_LEN 576
#define ARG_SEPARATOR ','
#define PATH_SEPARATOR '/'

// 固定开启拦截（无外部控制，加载即生效）
#define HMA_RISK_ENABLED 1    // 风险拦截强制开启
#define HMA_AD_ENABLED 1      // 广告拦截强制开启

// 核心基础白名单（QQ/微信/系统软件/常用银行，无冗余，优先放行核心应用）
static const char *base_whitelist[] = {
    // 微信/QQ 核心应用
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
    "com.meizu.flyme.launcher", // 魅族桌面
    "me.bmax.apatch",
    "com.larus.nova",
    "com.miui.home",
    "com.sukisu.ultra"
};
#define BASE_WHITELIST_SIZE (sizeof(base_whitelist)/sizeof(base_whitelist[0]))

// 1.风险拦截白名单（独立名单！仅放行以下应用，不在此列表的风险应用均拦截）
static const char *risk_whitelist[] = {
    // 可信任的工具类应用（示例，可按需调整）
    "com.android.fileexplorer", // 系统文件管理器
    "com.google.android.files", // Google文件
    "com.microsoft.office.excel", // 微软Excel
    "com.microsoft.office.word",  // 微软Word
    "com.adobe.reader",         // Adobe阅读器
    "com.evernote",             // 印象笔记
    "com.dropbox.android",      // Dropbox
    "com.google.drive",         // Google云端硬盘
    "com.spotify.music",        // Spotify音乐
    "com.netflix.mediaclient",  // 网飞
    "com.amazon.primevideo",    // 亚马逊视频
    "com.twitter.android",      // 推特
    "com.instagram.android",    //  Instagram
    "com.facebook.katana",      // Facebook
    "com.reddit.frontpage",     // Reddit
    "com.quora.android",        // Quora
    "com.zhihu.android",        // 知乎
    "com.douban.frodo",         // 豆瓣
    "com.sina.weibo",           // 微博
    "com.taobao.taobao",        // 淘宝（解除原风险拦截，加入白名单）
    "com.jd.mobile",            // 京东
    "com.pinduoduo.app",        // 拼多多
    "com.ele.me",               // 饿了么
    "com.sankuai.meituan",      // 美团
    "com.autonavi.minimap",     // 高德地图
    "com.baidu.BaiduMap",       // 百度地图
    "com.tencent.map",          // 腾讯地图
    "com.xiaomi.shop",          // 小米商城（解除原风险拦截）
    "com.termux",               // Termux（解除原风险拦截）
    "bin.mt.plus",              // MT管理器（解除原风险拦截）
    "com.smartpack.kernelmanager", // 内核管理器（解除原风险拦截）
    "com.github.tianma8023.xposed.smscode", // 短信验证码插件（解除原风险拦截）
    "me.iacn.biliroaming",      // B站漫游（解除原风险拦截）
    "com.luckyzyx.luckytool",   // 幸运工具箱（解除原风险拦截）
    "com.fkzhang.wechatxposed", // 微信Xposed插件（解除原风险拦截）
    "com.lerist.fakelocation",  // 虚拟定位（解除原风险拦截）
    "com.modify.installer",     // 修改安装器（解除原风险拦截）
    "me.bingyue.IceCore",       // IceCore（解除原风险拦截）
    "com.silverlab.app.deviceidchanger.free" // 设备ID修改器（解除原风险拦截）
};
#define RISK_WHITELIST_SIZE (sizeof(risk_whitelist)/sizeof(risk_whitelist[0]))

// 风险文件夹白名单（独立名单！仅放行以下文件夹，不在此列表的风险文件夹均拦截）
static const char *risk_whitelist_folder[] = {
    "android_data", "app_cache", "normal_storage", "legitimate_tools", "trusted_plugin",
    "safe_backup", "official_data", "authorized_cache", "valid_module", "approved_dir",
    "system_cache", "vendor_cache", "oem_data", "user_data", "app_data",
    "media_files", "document_dir", "downloads", "pictures", "videos",
    "music", "ringtones", "alarms", "notifications", "fonts",
    "themes", "icons", "wallpapers", "launcher_data", "keyboard_data",
    "browser_cache", "map_data", "music_cache", "video_cache", "app_updates",
    "plugin_data", "extension_dir", "addon_data", "widget_data", "service_cache"
};
#define RISK_WHITELIST_FOLDER_SIZE (sizeof(risk_whitelist_folder)/sizeof(risk_whitelist_folder[0]))

// 2.广告拦截黑名单（独立名单，保持原有逻辑不变）
static const char *ad_file_keywords[] = {
    "ad_", "_ad.", "ads_", "_ads.", "advertise", "adcache", "adimg", "advideo",
    "adbanner", "adpopup", "adpush", "adconfig", "adlog", "adstat", "adtrack",
    "adservice", "adplugin", "admodule", "adlibrary", "adloader"
};
#define AD_FILE_KEYWORD_SIZE (sizeof(ad_file_keywords)/sizeof(ad_file_keywords[0]))

// 核心工具函数（极简无冗余）
// 1. 基础白名单校验（优先放行核心应用，与风险白名单独立）
static int is_base_whitelisted(const char *path) {
    if (!path || *path != PATH_SEPARATOR) return 0;

    // 提取包名（适配 /data/data/包名/... 或 /storage/emulated/0/Android/data/包名/... 路径）
    const char *data_prefix = "/data/data/";
    const char *android_data_prefix = "/storage/emulated/0/Android/data/";
    const char *pkg_start = NULL;

    if (strstr(path, data_prefix)) {
        pkg_start = path + strlen(data_prefix);
    } else if (strstr(path, android_data_prefix)) {
        pkg_start = path + strlen(android_data_prefix);
    } else {
        // 系统路径直接放行（系统软件基础白名单）
        return (strstr(path, "/system/") || strstr(path, "/vendor/") || strstr(path, "/oem/")) ? 1 : 0;
    }

    // 提取包名字符串
    char pkg_name[MAX_PACKAGE_LEN] = {0};
    size_t i = 0;
    while (pkg_start[i] && pkg_start[i] != PATH_SEPARATOR && i < MAX_PACKAGE_LEN - 1) {
        pkg_name[i] = pkg_start[i];
        i++;
    }
    if (i == 0) return 0;

    // 基础白名单匹配
    for (size_t j = 0; j < BASE_WHITELIST_SIZE; j++) {
        if (strcmp(pkg_name, base_whitelist[j]) == 0) {
            return 1;
        }
    }
    return 0;
}

// 2. 风险白名单校验（独立逻辑：仅放行风险白名单内的应用/文件夹）
static int is_risk_whitelisted(const char *path) {
    if (!path || *path != PATH_SEPARATOR) return 0;

    // 提取包名或文件夹名
    char target_buf[MAX_PACKAGE_LEN] = {0};
    const char *pkg_start = NULL;

    // 匹配 /data/data/包名/... 路径（应用包名）
    if (strstr(path, "/data/data/")) {
        pkg_start = path + strlen("/data/data/");
    }
    // 匹配 /storage/emulated/0/Android/data/包名/... 路径（应用包名）
    else if (strstr(path, "/storage/emulated/0/Android/data/")) {
        pkg_start = path + strlen("/storage/emulated/0/Android/data/");
    }
    // 匹配独立文件夹路径（直接提取文件夹名）
    else {
        const char *last_slash = strrchr(path, PATH_SEPARATOR);
        if (last_slash && *(last_slash + 1)) {
            pkg_start = last_slash + 1;
        } else {
            return 0;
        }
    }

    // 提取目标字符串（包名或文件夹名）
    size_t i = 0;
    while (pkg_start[i] && pkg_start[i] != PATH_SEPARATOR && i < MAX_PACKAGE_LEN - 1) {
        target_buf[i] = pkg_start[i];
        i++;
    }
    if (i == 0) return 0;

    // 风险应用白名单匹配（匹配则放行）
    for (size_t j = 0; j < RISK_WHITELIST_SIZE; j++) {
        if (strcmp(target_buf, risk_whitelist[j]) == 0) {
            return 1;
        }
    }
    // 风险文件夹白名单匹配（匹配则放行）
    for (size_t k = 0; k < RISK_WHITELIST_FOLDER_SIZE; k++) {
        if (strcmp(target_buf, risk_whitelist_folder[k]) == 0) {
            return 1;
        }
    }
    return 0; // 不在风险白名单内，需要拦截
}

// 3. 广告拦截判断（独立逻辑，保持原有黑名单机制）
static int is_ad_blocked(const char *path) {
    if (!path) return 0;

    char lower_path[PATH_MAX];
    strncpy(lower_path, path, PATH_MAX - 1);
    lower_path[PATH_MAX - 1] = '\0';

    // 转小写匹配
    for (char *s = lower_path; *s; s++) {
        if (*s >= 'A' && *s <= 'Z') {
            *s += 32;
        }
    }

    // 广告关键词匹配（匹配则拦截）
    for (size_t i = 0; i < AD_FILE_KEYWORD_SIZE; i++) {
        if (strstr(lower_path, ad_file_keywords[i]) != NULL) {
            return 1;
        }
    }
    return 0;
}

// 核心拦截钩子（全应用适配，风险+广告强制开启拦截）
static void before_mkdirat(hook_fargs4_t *args, void *udata) {
    char path[PATH_MAX];
    long len = compat_strncpy_from_user(path, (void *)syscall_argn(args, 1), PATH_MAX - 1);
    if (len <= 0 || is_base_whitelisted(path)) return; // 基础白名单直接放行
    path[len] = '\0';

    // 风险拦截（不在白名单即拦）+ 广告拦截（匹配黑名单即拦），均强制开启
    if ((HMA_RISK_ENABLED && !is_risk_whitelisted(path)) || (HMA_AD_ENABLED && is_ad_blocked(path))) {
        pr_warn("[HMA++] mkdirat deny: %s (risk_deny:%d, ad_deny:%d)\n", 
                path, 
                (HMA_RISK_ENABLED && !is_risk_whitelisted(path)) ? 1 : 0,
                (HMA_AD_ENABLED && is_ad_blocked(path)) ? 1 : 0);
        args->skip_origin = 1;
        args->ret = -EACCES;
    }
}

static void before_chdir(hook_fargs1_t *args, void *udata) {
    char path[PATH_MAX];
    long len = compat_strncpy_from_user(path, (void *)syscall_argn(args, 0), PATH_MAX - 1);
    if (len <= 0 || is_base_whitelisted(path)) return;
    path[len] = '\0';

    if ((HMA_RISK_ENABLED && !is_risk_whitelisted(path)) || (HMA_AD_ENABLED && is_ad_blocked(path))) {
        pr_warn("[HMA++] chdir deny: %s (risk_deny:%d, ad_deny:%d)\n", 
                path, 
                (HMA_RISK_ENABLED && !is_risk_whitelisted(path)) ? 1 : 0,
                (HMA_AD_ENABLED && is_ad_blocked(path)) ? 1 : 0);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}

#if defined(__NR_rmdir)
static void before_rmdir(hook_fargs1_t *args, void *udata) {
    char path[PATH_MAX];
    long len = compat_strncpy_from_user(path, (void *)syscall_argn(args, 0), PATH_MAX - 1);
    if (len <= 0 || is_base_whitelisted(path)) return;
    path[len] = '\0';

    if ((HMA_RISK_ENABLED && !is_risk_whitelisted(path)) || (HMA_AD_ENABLED && is_ad_blocked(path))) {
        pr_warn("[HMA++] rmdir deny: %s (risk_deny:%d, ad_deny:%d)\n", 
                path, 
                (HMA_RISK_ENABLED && !is_risk_whitelisted(path)) ? 1 : 0,
                (HMA_AD_ENABLED && is_ad_blocked(path)) ? 1 : 0);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}
#endif

#if defined(__NR_unlinkat)
static void before_unlinkat(hook_fargs4_t *args, void *udata) {
    char path[PATH_MAX];
    long len = compat_strncpy_from_user(path, (void *)syscall_argn(args, 1), PATH_MAX - 1);
    if (len <= 0 || is_base_whitelisted(path)) return;
    path[len] = '\0';

    if ((HMA_RISK_ENABLED && !is_risk_whitelisted(path)) || (HMA_AD_ENABLED && is_ad_blocked(path))) {
        pr_warn("[HMA++] unlinkat deny: %s (risk_deny:%d, ad_deny:%d)\n", 
                path, 
                (HMA_RISK_ENABLED && !is_risk_whitelisted(path)) ? 1 : 0,
                (HMA_AD_ENABLED && is_ad_blocked(path)) ? 1 : 0);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}
#endif

#ifdef __NR_openat
static void before_openat(hook_fargs5_t *args, void *udata) {
    char path[PATH_MAX];
    long len = compat_strncpy_from_user(path, (void *)syscall_argn(args, 1), PATH_MAX - 1);
    if (len <= 0 || is_base_whitelisted(path)) return;
    path[len] = '\0';

    if ((HMA_RISK_ENABLED && !is_risk_whitelisted(path)) || (HMA_AD_ENABLED && is_ad_blocked(path))) {
        pr_warn("[HMA++] openat deny: %s (risk_deny:%d, ad_deny:%d)\n", 
                path, 
                (HMA_RISK_ENABLED && !is_risk_whitelisted(path)) ? 1 : 0,
                (HMA_AD_ENABLED && is_ad_blocked(path)) ? 1 : 0);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}
#endif

#ifdef __NR_renameat
static void before_renameat(hook_fargs4_t *args, void *udata) {
    char old_path[PATH_MAX], new_path[PATH_MAX];
    long len_old = compat_strncpy_from_user(old_path, (void *)syscall_argn(args, 1), PATH_MAX - 1);
    long len_new = compat_strncpy_from_user(new_path, (void *)syscall_argn(args, 3), PATH_MAX - 1);
    if (len_old <= 0 || len_new <= 0) return;
    old_path[len_old] = '\0';
    new_path[len_new] = '\0';

    // 基础白名单校验（任一路径在基础白名单即放行）
    if (is_base_whitelisted(old_path) || is_base_whitelisted(new_path)) return;

    // 任一路径触发风险/广告拦截，均拒绝操作
    bool risk_deny = HMA_RISK_ENABLED && (!is_risk_whitelisted(old_path) || !is_risk_whitelisted(new_path));
    bool ad_deny = HMA_AD_ENABLED && (is_ad_blocked(old_path) || is_ad_blocked(new_path));
    if (risk_deny || ad_deny) {
        pr_warn("[HMA++] renameat deny: %s -> %s (risk_deny:%d, ad_deny:%d)\n", 
                old_path, new_path, risk_deny ? 1 : 0, ad_deny ? 1 : 0);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}
#endif

// 模块生命周期（极简无冗余）
static long mkdir_hook_init(const char *args, const char *event, void *__user reserved) {
    hook_err_t err;
    pr_info("[HMA++] init start（风险白名单+广告黑名单，加载即开启拦截）\n");
    pr_info("[HMA++] 风险白名单应用数：%zu，风险白名单文件夹数：%zu\n", 
            RISK_WHITELIST_SIZE, RISK_WHITELIST_FOLDER_SIZE);

    // 挂钩核心文件操作syscall
    err = hook_syscalln(__NR_mkdirat, 3, before_mkdirat, NULL, NULL);
    if (err) { pr_err("[HMA++] hook mkdirat err: %d\n", err); return -EINVAL; }
    err = hook_syscalln(__NR_chdir, 1, before_chdir, NULL, NULL);
    if (err) { pr_err("[HMA++] hook chdir err: %d\n", err); return -EINVAL; }
#if defined(__NR_rmdir)
    hook_syscalln(__NR_rmdir, 1, before_rmdir, NULL, NULL);
#endif
#if defined(__NR_unlinkat)
    hook_syscalln(__NR_unlinkat, 4, before_unlinkat, NULL, NULL);
#endif
#ifdef __NR_openat
    hook_syscalln(__NR_openat, 5, before_openat, NULL, NULL);
#endif
#ifdef __NR_renameat
    hook_syscalln(__NR_renameat, 4, before_renameat, NULL, NULL);
#endif

    pr_info("[HMA++] init success（风险拦截: 开启, 广告拦截: 开启）\n");
    return 0;
}

// 模块退出（极简解钩）
static long mkdir_hook_exit(void *__user reserved) {
    pr_info("[HMA++] exit start\n");
    unhook_syscalln(__NR_mkdirat, before_mkdirat, NULL);
    unhook_syscalln(__NR_chdir, before_chdir, NULL);
#if defined(__NR_rmdir)
    unhook_syscalln(__NR_rmdir, before_rmdir, NULL);
#endif
#if defined(__NR_unlinkat)
    unhook_syscalln(__NR_unlinkat, before_unlinkat, NULL);
#endif
#ifdef __NR_openat
    unhook_syscalln(__NR_openat, before_openat, NULL);
#endif
#ifdef __NR_renameat
    unhook_syscalln(__NR_renameat, before_renameat, NULL);
#endif
    pr_info("[HMA++] exit success\n");
    return 0;
}

// 模块注册（仅保留初始化和退出，无控制接口）
KPM_INIT(mkdir_hook_init);
KPM_EXIT(mkdir_hook_exit);
