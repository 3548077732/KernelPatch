#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <kputils.h>
#include <linux/sched.h>
#include <linux/uidgid.h>
#include <linux/fs.h>
#include <linux/delay.h>

KPM_NAME("Network Accelerator Lite");
KPM_VERSION("1.0");
KPM_LICENSE("GPLv3");
KPM_AUTHOR("NetworkOptimizer");
KPM_DESCRIPTION("轻量级网络优化模块");

// 网络优化配置
#define TCP_FAST_OPEN_ENABLED   1
#define TCP_WINDOW_SCALING      1
#define TCP_KEEPALIVE_TIME      300
#define TCP_KEEPALIVE_PROBES    3
#define TCP_KEEPALIVE_INTVL     10

// 游戏应用白名单
static const char *game_apps[] = {
    "com.tencent.tmgp.sgame",      // 王者荣耀
    "com.tencent.tmgp.pubgmhd",    // PUBG Mobile
    "com.miHoYo.GenshinImpact",    // 原神
    "com.riotgames.league.wildrift", // 英雄联盟手游
    "com.tencent.ig",              // 和平精英
    "com.tencent.lolm",            // 英雄联盟手游(国服)
    "com.tencent.tmgp.cod",        // CODM
    "com.mojang.minecraftpe",      // 我的世界
    "com.supercell.clashofclans",  // 部落冲突
    "com.supercell.brawlstars",    // 荒野乱斗
};

#define GAME_APPS_SIZE (sizeof(game_apps)/sizeof(game_apps[0]))

// DNS优化服务器
static const char *dns_servers[] = {
    "223.5.5.5",      // 阿里DNS
    "119.29.29.29",   // DNSPod
    "114.114.114.114", // 114DNS
    "8.8.8.8",        // Google DNS
};

#define DNS_SERVERS_SIZE (sizeof(dns_servers)/sizeof(dns_servers[0]))

// 获取当前进程名
static char *get_current_process_name(void) {
    struct task_struct *task = current;
    if (task && task->comm) {
        return task->comm;
    }
    return NULL;
}

// 检查进程名是否在游戏列表中
static int is_game_app(void) {
    char *comm = get_current_process_name();
    if (!comm) return 0;
    
    // 检查是否是游戏进程
    for (size_t i = 0; i < GAME_APPS_SIZE; ++i) {
        if (strstr(comm, game_apps[i]) != NULL) {
            return 1;
        }
    }
    return 0;
}

// 系统参数优化函数
static void optimize_system_params(void) {
    FILE *fp;
    
    // 优化TCP参数
    fp = fopen("/proc/sys/net/ipv4/tcp_fastopen", "w");
    if (fp) {
        fprintf(fp, "%d", TCP_FAST_OPEN_ENABLED ? 3 : 0);
        fclose(fp);
    }
    
    // 启用TCP窗口缩放
    fp = fopen("/proc/sys/net/ipv4/tcp_window_scaling", "w");
    if (fp) {
        fprintf(fp, "%d", TCP_WINDOW_SCALING);
        fclose(fp);
    }
    
    // 优化TCP KeepAlive
    fp = fopen("/proc/sys/net/ipv4/tcp_keepalive_time", "w");
    if (fp) {
        fprintf(fp, "%d", TCP_KEEPALIVE_TIME);
        fclose(fp);
    }
    
    fp = fopen("/proc/sys/net/ipv4/tcp_keepalive_probes", "w");
    if (fp) {
        fprintf(fp, "%d", TCP_KEEPALIVE_PROBES);
        fclose(fp);
    }
    
    fp = fopen("/proc/sys/net/ipv4/tcp_keepalive_intvl", "w");
    if (fp) {
        fprintf(fp, "%d", TCP_KEEPALIVE_INTVL);
        fclose(fp);
    }
    
    // 增大TCP缓冲区
    fp = fopen("/proc/sys/net/ipv4/tcp_rmem", "w");
    if (fp) {
        fprintf(fp, "4096 87380 6291456");
        fclose(fp);
    }
    
    fp = fopen("/proc/sys/net/ipv4/tcp_wmem", "w");
    if (fp) {
        fprintf(fp, "4096 16384 4194304");
        fclose(fp);
    }
    
    // 针对游戏应用的特殊优化
    if (is_game_app()) {
        // 减少延迟确认
        fp = fopen("/proc/sys/net/ipv4/tcp_delack_min", "w");
        if (fp) {
            fprintf(fp, "1");
            fclose(fp);
        }
        
        // 启用TCP低延迟
        fp = fopen("/proc/sys/net/ipv4/tcp_low_latency", "w");
        if (fp) {
            fprintf(fp, "1");
            fclose(fp);
        }
    }
    
    pr_info("[Network Lite] System parameters optimized\n");
}

// DNS优化
static void optimize_dns_settings(void) {
    FILE *fp;
    
    // 写入DNS服务器到临时文件
    fp = fopen("/tmp/network_optimizer_dns.txt", "w");
    if (fp) {
        for (size_t i = 0; i < DNS_SERVERS_SIZE; ++i) {
            fprintf(fp, "nameserver %s\n", dns_servers[i]);
        }
        fclose(fp);
    }
    
    pr_info("[Network Lite] DNS servers configured\n");
}

// 简单的性能监控
static void monitor_performance(void) {
    static unsigned long last_time = 0;
    unsigned long current_time = jiffies;
    
    // 每60秒输出一次状态
    if (current_time - last_time > 60 * HZ) {
        pr_info("[Network Lite] Network optimizer active\n");
        pr_info("[Network Lite] Game apps in list: %zu\n", GAME_APPS_SIZE);
        pr_info("[Network Lite] DNS servers: %zu\n", DNS_SERVERS_SIZE);
        last_time = current_time;
    }
}

// 模块初始化
static long network_lite_init(const char *args, const char *event, void *__user reserved) {
    pr_info("[Network Lite] Network Accelerator Lite init\n");
    
    // 优化系统参数
    optimize_system_params();
    
    // 优化DNS设置
    optimize_dns_settings();
    
    // 启动性能监控
    schedule_delayed_work(&monitor_performance, 60 * HZ);
    
    pr_info("[Network Lite] Network optimization applied\n");
    pr_info("[Network Lite] TCP Fast Open: %s\n", TCP_FAST_OPEN_ENABLED ? "Enabled" : "Disabled");
    pr_info("[Network Lite] TCP Window Scaling: %s\n", TCP_WINDOW_SCALING ? "Enabled" : "Disabled");
    
    return 0;
}

// 模块退出
static long network_lite_exit(void *__user reserved) {
    pr_info("[Network Lite] Network Accelerator Lite exit\n");
    
    // 恢复默认TCP参数（可选）
    FILE *fp = fopen("/proc/sys/net/ipv4/tcp_fastopen", "w");
    if (fp) {
        fprintf(fp, "1");
        fclose(fp);
    }
    
    pr_info("[Network Lite] Network optimization disabled\n");
    return 0;
}

KPM_INIT(network_lite_init);
KPM_EXIT(network_lite_exit);
