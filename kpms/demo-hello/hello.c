#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h>
#include <linux/uaccess.h>
#include <syscall.h>
#include <linux/string.h>
#include <kputils.h>
#include <asm/current.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <accctl.h>
#include <linux/net.h>
#include <net/sock.h>
#include <linux/tcp.h>
#include <net/inet_connection_sock.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <net/tcp.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/delay.h>

KPM_NAME("Network Turbo Boost");
KPM_VERSION("2.0");
KPM_LICENSE("GPLv3");
KPM_AUTHOR("NetworkOptimizer");
KPM_DESCRIPTION("网络加速与优化模块");

// 网络优化配置
#define TCP_OPTIMIZATION_ENABLED  1
#define UDP_OPTIMIZATION_ENABLED  1
#define DNS_OPTIMIZATION_ENABLED  1
#define LATENCY_OPTIMIZATION_ENABLED 1

// TCP优化参数
#define TCP_FAST_OPEN_ENABLED     1
#define TCP_WINDOW_SCALING        1
#define TCP_CONGESTION_CONTROL    "bbr"  // 使用BBR拥塞控制算法
#define TCP_INIT_CWND             10     // 初始拥塞窗口
#define TCP_SYN_RETRIES           3      // SYN重试次数
#define TCP_KEEPALIVE_TIME        300    // 保持连接时间(秒)
#define TCP_KEEPALIVE_PROBES      3      // 保持连接探测次数
#define TCP_KEEPALIVE_INTVL       10     // 保持连接间隔(秒)

// 网络缓冲区大小
#define TCP_RMEM_DEFAULT  8388608  // 8MB
#define TCP_RMEM_MAX      16777216 // 16MB
#define TCP_WMEM_DEFAULT  8388608  // 8MB
#define TCP_WMEM_MAX      16777216 // 16MB

// 游戏加速应用白名单
static const char *game_apps[] = {
    "com.tencent.tmgp.sgame",      // 王者荣耀
    "com.tencent.tmgp.pubgmhd",    // PUBG Mobile
    "com.miHoYo.GenshinImpact",    // 原神
    "com.riotgames.league.wildrift", // 英雄联盟手游
    "com.netease.hyperfront",      // 超凡先锋
    "com.ea.gp.fifamobile",        // FIFA足球
    "com.dts.freefireth",          // Free Fire
    "com.supercell.clashofclans",  // 部落冲突
    "com.supercell.brawlstars",    // 荒野乱斗
    "com.mojang.minecraftpe",      // 我的世界
    "com.activision.callofduty.shooter", // COD手游
    "com.tencent.ig",              // 和平精英
    "com.tencent.tmgp.cod",        // CODM
    "com.tencent.lolm",            // 英雄联盟手游(国服)
    "com.nintendo.zara",           // 塞尔达传说
    "com.blizzard.diablo.immortal", // 暗黑破坏神不朽
    "com.netease.onmyoji",         // 阴阳师
    "com.aniplex.fategrandorder",  // FGO
    "com.YoStarEN.Arknights",      // 明日方舟
    "com.HoYoverse.hkrpgoversea",  // 崩坏：星穹铁道
    "com.mihoyo.hyperion",         // 崩坏3
    "com.HoYoverse.hoyoverse",     // HoYoverse
};

#define GAME_APPS_SIZE (sizeof(game_apps)/sizeof(game_apps[0]))

// DNS优化服务器列表
static const char *dns_servers[] = {
    "223.5.5.5",      // 阿里DNS
    "223.6.6.6",      // 阿里DNS备用
    "119.29.29.29",   // DNSPod
    "180.76.76.76",   // 百度DNS
    "114.114.114.114", // 114DNS
    "8.8.8.8",        // Google DNS
    "1.1.1.1",        // CloudFlare DNS
};

#define DNS_SERVERS_SIZE (sizeof(dns_servers)/sizeof(dns_servers[0]))

// 获取当前进程的包名
static char *get_current_package_name(void) {
    struct task_struct *task = current;
    char *package_name = NULL;
    
    if (task && task->mm && task->mm->exe_file) {
        char *path = d_path(&task->mm->exe_file->f_path, (char *)__get_free_page(GFP_KERNEL), PAGE_SIZE);
        if (path) {
            // 从路径中提取包名
            char *p = strstr(path, "/data/app/");
            if (p) {
                p += 10; // 跳过"/data/app/"
                char *end = strchr(p, '/');
                if (end) {
                    *end = '\0';
                    // 提取包名（去掉版本号部分）
                    char *dash = strrchr(p, '-');
                    if (dash) *dash = '\0';
                    package_name = kstrdup(p, GFP_KERNEL);
                }
            }
            free_page((unsigned long)path);
        }
    }
    return package_name;
}

// 检查是否是游戏应用
static int is_game_app(void) {
    char *package_name = get_current_package_name();
    if (!package_name) return 0;
    
    for (size_t i = 0; i < GAME_APPS_SIZE; ++i) {
        if (strcmp(package_name, game_apps[i]) == 0) {
            kfree(package_name);
            return 1;
        }
    }
    kfree(package_name);
    return 0;
}

// TCP连接优化
static void optimize_tcp_connection(struct sock *sk) {
    struct tcp_sock *tp = tcp_sk(sk);
    struct inet_connection_sock *icsk = inet_csk(sk);
    
    if (!sk || !tp || !icsk) return;
    
    // 启用TCP Fast Open
    #if TCP_FAST_OPEN_ENABLED
    if (tcp_fastopen_enabled) {
        tp->fastopen_req = 1;
    }
    #endif
    
    // 设置拥塞控制算法
    #if TCP_CONGESTION_CONTROL
    if (icsk->icsk_ca_ops) {
        tcp_set_congestion_control(sk, TCP_CONGESTION_CONTROL, false);
    }
    #endif
    
    // 调整TCP窗口大小
    #if TCP_WINDOW_SCALING
    tp->rx_opt.rcv_wscale = 7; // 128倍窗口缩放
    tp->rx_opt.snd_wscale = 7;
    #endif
    
    // 设置初始拥塞窗口
    tp->snd_cwnd = TCP_INIT_CWND;
    tp->snd_cwnd_cnt = 0;
    
    // 减少延迟确认
    tp->ack.ato = 40; // 40ms
    tp->ack.pingpong = 0;
    
    // 针对游戏应用的特殊优化
    if (is_game_app()) {
        // 游戏需要更低延迟
        tp->delack_max = 1; // 立即ACK
        tp->urg_data = 1;   // 紧急数据模式
        
        // 更积极的拥塞控制
        tp->snd_cwnd_clamp = 20; // 限制拥塞窗口
        tp->snd_ssthresh = 10;   // 慢启动阈值
    }
}

// UDP连接优化
static void optimize_udp_connection(struct sock *sk) {
    if (!sk) return;
    
    // 增加UDP缓冲区大小
    sk->sk_rcvbuf = 1048576;  // 1MB接收缓冲区
    sk->sk_sndbuf = 1048576;  // 1MB发送缓冲区
    
    // 减少UDP超时时间
    sk->sk_rcvtimeo = 3000;   // 3秒接收超时
    sk->sk_sndtimeo = 3000;   // 3秒发送超时
}

// DNS解析优化
static void optimize_dns_query(struct msghdr *msg) {
    if (!msg || !msg->msg_name) return;
    
    struct sockaddr_in *sin = (struct sockaddr_in *)msg->msg_name;
    if (sin->sin_family == AF_INET) {
        // DNS端口是53
        if (ntohs(sin->sin_port) == 53) {
            // 这里可以添加DNS缓存或DNS服务器选择逻辑
            // 实际实现需要更复杂的DNS解析和重写
            pr_info("[Network Turbo] DNS query detected\n");
        }
    }
}

// connect系统调用钩子
static void before_connect(hook_fargs3_t *args, void *udata) {
    int fd = (int)syscall_argn(args, 0);
    struct sockaddr __user *addr = (struct sockaddr __user *)syscall_argn(args, 1);
    int addrlen = (int)syscall_argn(args, 2);
    
    // 获取socket文件描述符对应的socket结构
    struct socket *sock = sockfd_lookup(fd, NULL);
    if (!sock) return;
    
    // 优化TCP连接
    if (sock->sk && sock->sk->sk_protocol == IPPROTO_TCP) {
        optimize_tcp_connection(sock->sk);
    }
    // 优化UDP连接
    else if (sock->sk && sock->sk->sk_protocol == IPPROTO_UDP) {
        optimize_udp_connection(sock->sk);
    }
    
    sockfd_put(sock);
}

// sendto系统调用钩子
static void before_sendto(hook_fargs6_t *args, void *udata) {
    #if DNS_OPTIMIZATION_ENABLED
    struct msghdr msg;
    struct sockaddr __user *addr = (struct sockaddr __user *)syscall_argn(args, 4);
    int addrlen = (int)syscall_argn(args, 5);
    
    if (addr && addrlen > 0) {
        // 优化DNS查询
        msg.msg_name = addr;
        msg.msg_namelen = addrlen;
        optimize_dns_query(&msg);
    }
    #endif
}

// setsockopt系统调用钩子 - 优化socket选项
static void before_setsockopt(hook_fargs5_t *args, void *udata) {
    int fd = (int)syscall_argn(args, 0);
    int level = (int)syscall_argn(args, 1);
    int optname = (int)syscall_argn(args, 2);
    
    // 如果是TCP_NODELAY（禁用Nagle算法），直接允许
    if (level == SOL_TCP && optname == TCP_NODELAY) {
        pr_info("[Network Turbo] TCP_NODELAY enabled for fd %d\n", fd);
    }
    
    // 如果是SO_KEEPALIVE，优化参数
    if (level == SOL_SOCKET && optname == SO_KEEPALIVE) {
        struct socket *sock = sockfd_lookup(fd, NULL);
        if (sock && sock->sk) {
            sock->sk->sk_keepalive_time = TCP_KEEPALIVE_TIME;
            sock->sk->sk_keepalive_intvl = TCP_KEEPALIVE_INTVL;
            sock->sk->sk_keepalive_probes = TCP_KEEPALIVE_PROBES;
            sockfd_put(sock);
        }
    }
}

// 修改网络参数
static void tune_network_parameters(void) {
    // 调整TCP参数
    sysctl_tcp_fastopen = TCP_FAST_OPEN_ENABLED;
    sysctl_tcp_syn_retries = TCP_SYN_RETRIES;
    sysctl_tcp_keepalive_time = TCP_KEEPALIVE_TIME;
    sysctl_tcp_keepalive_probes = TCP_KEEPALIVE_PROBES;
    sysctl_tcp_keepalive_intvl = TCP_KEEPALIVE_INTVL;
    
    // 调整TCP缓冲区大小
    sysctl_tcp_rmem[0] = 4096;
    sysctl_tcp_rmem[1] = TCP_RMEM_DEFAULT;
    sysctl_tcp_rmem[2] = TCP_RMEM_MAX;
    
    sysctl_tcp_wmem[0] = 4096;
    sysctl_tcp_wmem[1] = TCP_WMEM_DEFAULT;
    sysctl_tcp_wmem[2] = TCP_WMEM_MAX;
    
    // 启用TCP窗口缩放
    sysctl_tcp_window_scaling = TCP_WINDOW_SCALING;
    
    pr_info("[Network Turbo] Network parameters tuned\n");
}

// 模块初始化
static long network_turbo_init(const char *args, const char *event, void *__user reserved) {
    hook_err_t err;
    pr_info("[Network Turbo] Network Turbo Boost init\n");
    
    // 优化系统网络参数
    tune_network_parameters();
    
    // 挂钩connect系统调用
    err = hook_syscalln(__NR_connect, 3, before_connect, NULL, NULL);
    if (err) { 
        pr_err("[Network Turbo] Hook connect failed: %d\n", err); 
        return -EINVAL; 
    }
    
    // 挂钩sendto系统调用
    err = hook_syscalln(__NR_sendto, 6, before_sendto, NULL, NULL);
    if (err) { 
        pr_err("[Network Turbo] Hook sendto failed: %d\n", err); 
        return -EINVAL; 
    }
    
    // 挂钩setsockopt系统调用
    err = hook_syscalln(__NR_setsockopt, 5, before_setsockopt, NULL, NULL);
    if (err) { 
        pr_err("[Network Turbo] Hook setsockopt failed: %d\n", err); 
        return -EINVAL; 
    }
    
    pr_info("[Network Turbo] All network syscalls hooked successfully\n");
    pr_info("[Network Turbo] Game apps in list: %zu\n", GAME_APPS_SIZE);
    pr_info("[Network Turbo] DNS servers: %zu\n", DNS_SERVERS_SIZE);
    
    return 0;
}

// 模块退出
static long network_turbo_exit(void *__user reserved) {
    pr_info("[Network Turbo] Network Turbo Boost exit\n");
    
    // 解绑所有系统调用
    unhook_syscalln(__NR_connect, before_connect, NULL);
    unhook_syscalln(__NR_sendto, before_sendto, NULL);
    unhook_syscalln(__NR_setsockopt, before_setsockopt, NULL);
    
    // 恢复原始网络参数
    sysctl_tcp_fastopen = 0;
    sysctl_tcp_window_scaling = 1;
    
    pr_info("[Network Turbo] All network syscalls unhooked\n");
    return 0;
}

KPM_INIT(network_turbo_init);
KPM_EXIT(network_turbo_exit);