#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/uaccess.h>
#include <syscall.h>
#include <linux/string.h>
#include <kputils.h>
#include <asm/current.h>
#include <linux/fs.h>
#include <linux/errno.h>
// 核心修复1：删除 linux/in.h（框架未提供）
#include <linux/inet.h>
#include <linux/tcp.h>
#include <linux/sysctl.h>
#include <linux/limits.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/jiffies.h>
#include <linux/time.h>
#include <netdb.h>

// ###########################################################################
// 手动补充所有缺失的核心定义（替代 linux/socket.h + linux/in.h + asm-generic/socket.h）
// ###########################################################################
// 1. 字节序转换宏（来自 linux/in.h，必须补充，代码中用到 htons/ntohs）
#ifndef __BIG_ENDIAN
#define htons(x) ((__be16)((((x) & 0xff) << 8) | (((x) & 0xff00) >> 8)))
#define ntohs(x) htons(x)
#define htonl(x) ((__be32)((((x) & 0xff) << 24) | (((x) & 0xff00) << 8) | (((x) & 0xff0000) >> 8) | (((x) & 0xff000000) >> 24)))
#define ntohl(x) htonl(x)
#else
#define htons(x) ((__be16)(x))
#define ntohs(x) ((__u16)(x))
#define htonl(x) ((__be32)(x))
#define ntohl(x) ((__u32)(x))
#endif

// 2. 地址族定义
#ifndef AF_INET
#define AF_INET 2       // IPv4
#endif
#ifndef AF_INET6
#define AF_INET6 10     // IPv6
#endif
#ifndef AF_UNSPEC
#define AF_UNSPEC 0     // 未指定地址族
#endif

// 3. 套接字类型定义
#ifndef SOCK_STREAM
#define SOCK_STREAM 1   // TCP
#endif
#ifndef SOCK_DGRAM
#define SOCK_DGRAM 2    // UDP
#endif

// 4. 协议类型定义
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

// 5. 辅助宏定义
#ifndef SOL_SOCKET
#define SOL_SOCKET 1
#endif
#ifndef NI_MAXHOST
#define NI_MAXHOST 1025 // 域名最大长度
#endif
#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46 // IPv6地址字符串最大长度
#endif
#ifndef __be16
#define __be16 unsigned short
#endif
#ifndef __be32
#define __be32 unsigned int
#endif
#ifndef __u8
#define __u8 unsigned char
#endif
#ifndef __u16
#define __u16 unsigned short
#endif
#ifndef __u32
#define __u32 unsigned int
#endif
#ifndef __kernel_sa_family_t
#define __kernel_sa_family_t unsigned short
#endif

// 6. IPv4地址结构体
struct in_addr {
    __be32 s_addr;
};

// 7. IPv6地址结构体
struct in6_addr {
    union {
        __u8 u6_addr8[16];
        __be16 u6_addr16[8];
        __be32 u6_addr32[4];
    } in6_u;
#define s6_addr in6_u.u6_addr8
#define s6_addr16 in6_u.u6_addr16
#define s6_addr32 in6_u.u6_addr32
};

// 8. 通用socket地址结构体
struct sockaddr {
    __kernel_sa_family_t sa_family; // 地址族
    char sa_data[14];               // 地址数据
};

// 9. IPv4 socket地址结构体
struct sockaddr_in {
    __kernel_sa_family_t sin_family; // AF_INET
    __be16 sin_port;                 // 端口号（网络字节序）
    struct in_addr sin_addr;         // IPv4地址
    unsigned char sin_zero[8];       // 填充字段
};

// 10. IPv6 socket地址结构体
struct sockaddr_in6 {
    __kernel_sa_family_t sin6_family; // AF_INET6
    __be16 sin6_port;                 // 端口号（网络字节序）
    __be32 sin6_flowinfo;             // 流信息
    struct in6_addr sin6_addr;        // IPv6地址
    __be32 sin6_scope_id;             // 作用域ID
};

// 11. getaddrinfo 相关结构体
struct addrinfo {
    int ai_flags;                     // 标志位
    int ai_family;                    // 地址族
    int ai_socktype;                  // 套接字类型
    int ai_protocol;                  // 协议类型
    socklen_t ai_addrlen;             // 地址长度
    char *ai_canonname;               // 规范域名
    struct sockaddr *ai_addr;         // 地址指针
    struct addrinfo *ai_next;         // 下一个节点（链表）
};

// ###########################################################################
// 模块元信息
// ###########################################################################
KPM_NAME("NetOpt++");
KPM_VERSION("1.1");
KPM_LICENSE("GPLv3");
KPM_AUTHOR("NightFallsLikeRain");
KPM_DESCRIPTION("Android 内核网络优化模块：TCP参数调优 + 恶意网络请求拦截 + DNS缓存优化");

// ###########################################################################
// 核心配置参数
// ###########################################################################
// 1. TCP 优化参数（可根据设备性能调整）
#define TCP_CONGESTION_ALG "bbr"          // 拥塞控制算法（bbr/cubic/htcp）
#define TCP_FASTOPEN_QSIZE 64             // TCP快速打开队列大小
#define TCP_MAX_SYN_BACKLOG 1024          // SYN队列最大长度
#define TCP_WINDOW_SCALE 7                // 窗口缩放因子（0-14）
#define TCP_KEEPALIVE_TIME 300            // TCP保活时间（秒）
#define TCP_KEEPALIVE_INTVL 60            // 保活探测间隔（秒）
#define TCP_KEEPALIVE_PROBES 3            // 保活探测次数

// 2. DNS 缓存优化参数
#define DNS_CACHE_TTL 300                 // 缓存过期时间（秒，默认5分钟）
#define DNS_MAX_CACHE_ENTRIES 128         // 最大缓存条目数（避免内存占用过高）
#define DNS_CACHE_LOCK_SPINLOCK           // 使用spinlock保证线程安全（内核态高性能）

// 3. 拦截黑名单（广告/追踪/恶意域名，支持通配符前缀匹配）
static const char *block_domain_list[] = {
    "ad.", "ads.", "advert.", "advertising.", "adserver.",
    "doubleclick.", "googleads.", "googlesyndication.",
    "facebookads.", "twitterads.", "bingads.", "yahooads.",
    "analytics.", "track.", "tracking.", "stats.", "metric.",
    "datacollect.", "userbehavior.", "crashlytics.", "firebaseanalytics.",
    "malware.", "phish.", "virus.", "spam.", "adware.",
    "trojan.", "spyware.", "botnet.", "miner.", "cryptojack."
};
#define BLOCK_DOMAIN_SIZE (sizeof(block_domain_list)/sizeof(block_domain_list[0]))

// 4. 允许的网络协议端口（白名单，仅放行常用合法端口）
static const __be16 allowed_ports[] = {
    htons(80),   // HTTP
    htons(443),  // HTTPS
    htons(21),   // FTP
    htons(22),   // SSH
    htons(53),   // DNS
    htons(110),  // POP3
    htons(143),  // IMAP
    htons(3389), // RDP
    htons(8080), // HTTP代理
    htons(8443)  // HTTPS代理
};
#define ALLOWED_PORT_SIZE (sizeof(allowed_ports)/sizeof(allowed_ports[0]))

// ###########################################################################
// DNS缓存数据结构
// ###########################################################################
struct dns_cache_entry {
    char domain[NI_MAXHOST];              // 域名
    union {
        struct in_addr ipv4;              // IPv4地址
        struct in6_addr ipv6;             // IPv6地址
    } addr;
    int family;                           // 地址族（AF_INET/AF_INET6）
    unsigned long expire_jiffies;         // 过期时间（内核节拍数）
    struct list_head list;                // LRU链表节点
    struct hlist_node hash_node;          // 哈希表节点
};

struct dns_cache {
    struct hlist_head *hash_table;        // 哈希表（快速查询）
    struct list_head lru_list;            // LRU链表（淘汰策略）
    unsigned int size;                    // 当前缓存条目数
    unsigned int max_size;                // 最大缓存条目数
    unsigned int ttl;                     // 缓存过期时间（秒）
#ifdef DNS_CACHE_LOCK_SPINLOCK
    spinlock_t lock;                      // 自旋锁（多核安全）
#else
    struct mutex lock;                    // 互斥锁
#endif
};

static struct dns_cache *dns_cache_global = NULL;

// ###########################################################################
// 工具函数
// ###########################################################################
// 检查端口是否在白名单中
static int is_port_allowed(__be16 port) {
    for (size_t i = 0; i < ALLOWED_PORT_SIZE; ++i) {
        if (port == allowed_ports[i]) return 1;
    }
    return 0;
}

// 域名前缀匹配（支持通配符前缀）
static int match_domain_prefix(const char *domain, const char *prefix) {
    size_t prefix_len = strlen(prefix);
    return strncmp(domain, prefix, prefix_len) == 0;
}

// 从socket地址中提取IP字符串（简化实现，适配手动定义的结构体）
static int get_target_addr(struct sockaddr *sa, char *buf, size_t buf_len) {
    if (!sa || !buf) return -EINVAL;

    switch (sa->sa_family) {
        case AF_INET: {
            struct sockaddr_in *sin = (struct sockaddr_in *)sa;
            inet_ntop(AF_INET, &sin->sin_addr, buf, buf_len);
            return 0;
        }
        case AF_INET6: {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;
            inet_ntop(AF_INET6, &sin6->sin6_addr, buf, buf_len);
            return 0;
        }
        default:
            return -EAFNOSUPPORT;
    }
}

// 域名哈希函数（用于缓存查询）
static unsigned int dns_domain_hash(const char *domain) {
    unsigned int hash = 5381;
    int c;
    while ((c = *domain++)) {
        hash = ((hash << 5) + hash) + c; // hash * 33 + c
    }
    return hash % DNS_MAX_CACHE_ENTRIES;
}

// ###########################################################################
// DNS缓存核心操作
// ###########################################################################
static int dns_cache_init(void) {
    dns_cache_global = kzalloc(sizeof(struct dns_cache), GFP_KERNEL);
    if (!dns_cache_global) return -ENOMEM;

    // 初始化哈希表
    dns_cache_global->hash_table = kzalloc(sizeof(struct hlist_head) * DNS_MAX_CACHE_ENTRIES, GFP_KERNEL);
    if (!dns_cache_global->hash_table) {
        kfree(dns_cache_global);
        return -ENOMEM;
    }
    for (int i = 0; i < DNS_MAX_CACHE_ENTRIES; ++i) {
        INIT_HLIST_HEAD(&dns_cache_global->hash_table[i]);
    }

    // 初始化LRU链表和锁
    INIT_LIST_HEAD(&dns_cache_global->lru_list);
    dns_cache_global->size = 0;
    dns_cache_global->max_size = DNS_MAX_CACHE_ENTRIES;
    dns_cache_global->ttl = DNS_CACHE_TTL;
#ifdef DNS_CACHE_LOCK_SPINLOCK
    spin_lock_init(&dns_cache_global->lock);
#else
    mutex_init(&dns_cache_global->lock);
#endif

    pr_info("[NetOpt++] DNS cache initialized: max entries=%d, TTL=%ds\n",
            DNS_MAX_CACHE_ENTRIES, DNS_CACHE_TTL);
    return 0;
}

static void dns_cache_destroy(void) {
    if (!dns_cache_global) return;

#ifdef DNS_CACHE_LOCK_SPINLOCK
    spin_lock(&dns_cache_global->lock);
#else
    mutex_lock(&dns_cache_global->lock);
#endif

    // 释放所有缓存条目
    struct list_head *pos, *n;
    list_for_each_safe(pos, n, &dns_cache_global->lru_list) {
        struct dns_cache_entry *entry = list_entry(pos, struct dns_cache_entry, list);
        hlist_del(&entry->hash_node);
        list_del(&entry->list);
        kfree(entry);
    }

#ifdef DNS_CACHE_LOCK_SPINLOCK
    spin_unlock(&dns_cache_global->lock);
#else
    mutex_unlock(&dns_cache_global->lock);
#endif

    kfree(dns_cache_global->hash_table);
    kfree(dns_cache_global);
    dns_cache_global = NULL;
    pr_info("[NetOpt++] DNS cache destroyed\n");
}

static struct dns_cache_entry *dns_cache_lookup(const char *domain, int family) {
    if (!dns_cache_global || !domain || (family != AF_INET && family != AF_INET6)) {
        return NULL;
    }

    unsigned long flags = 0;
#ifdef DNS_CACHE_LOCK_SPINLOCK
    spin_lock_irqsave(&dns_cache_global->lock, flags);
#else
    mutex_lock(&dns_cache_global->lock);
#endif

    unsigned int hash = dns_domain_hash(domain);
    struct hlist_node *hpos;
    struct dns_cache_entry *entry = NULL;
    hlist_for_each_entry(hpos, &dns_cache_global->hash_table[hash], hash_node) {
        entry = hlist_entry(hpos, struct dns_cache_entry, hash_node);
        if (strcmp(entry->domain, domain) == 0 && entry->family == family) {
            // 检查过期
            if (time_before(jiffies, entry->expire_jiffies)) {
                // 更新LRU位置
                list_del(&entry->list);
                list_add(&entry->list, &dns_cache_global->lru_list);
#ifdef DNS_CACHE_LOCK_SPINLOCK
                spin_unlock_irqrestore(&dns_cache_global->lock, flags);
#else
                mutex_unlock(&dns_cache_global->lock);
#endif
                return entry;
            } else {
                // 过期删除
                hlist_del(&entry->hash_node);
                list_del(&entry->list);
                kfree(entry);
                dns_cache_global->size--;
                entry = NULL;
                break;
            }
        }
    }

#ifdef DNS_CACHE_LOCK_SPINLOCK
    spin_unlock_irqrestore(&dns_cache_global->lock, flags);
#else
    mutex_unlock(&dns_cache_global->lock);
#endif

    return NULL;
}

static int dns_cache_add(const char *domain, const void *addr, int family) {
    if (!dns_cache_global || !domain || !addr || (family != AF_INET && family != AF_INET6)) {
        return -EINVAL;
    }

    if (strlen(domain) >= NI_MAXHOST) {
        pr_warn("[NetOpt++] DNS domain too long: %s\n", domain);
        return -EINVAL;
    }

    unsigned long flags = 0;
#ifdef DNS_CACHE_LOCK_SPINLOCK
    spin_lock_irqsave(&dns_cache_global->lock, flags);
#else
    mutex_lock(&dns_cache_global->lock);
#endif

    unsigned int hash = dns_domain_hash(domain);
    struct hlist_node *hpos;
    struct dns_cache_entry *entry = NULL;
    hlist_for_each_entry(hpos, &dns_cache_global->hash_table[hash], hash_node) {
        entry = hlist_entry(hpos, struct dns_cache_entry, hash_node);
        if (strcmp(entry->domain, domain) == 0 && entry->family == family) {
            // 更新已有条目
            if (family == AF_INET) {
                entry->addr.ipv4 = *(struct in_addr *)addr;
            } else {
                entry->addr.ipv6 = *(struct in6_addr *)addr;
            }
            entry->expire_jiffies = jiffies + (dns_cache_global->ttl * HZ);
            list_del(&entry->list);
            list_add(&entry->list, &dns_cache_global->lru_list);
#ifdef DNS_CACHE_LOCK_SPINLOCK
            spin_unlock_irqrestore(&dns_cache_global->lock, flags);
#else
            mutex_unlock(&dns_cache_global->lock);
#endif
            return 0;
        }
    }

    // 创建新条目
    entry = kzalloc(sizeof(struct dns_cache_entry), GFP_KERNEL);
    if (!entry) {
#ifdef DNS_CACHE_LOCK_SPINLOCK
        spin_unlock_irqrestore(&dns_cache_global->lock, flags);
#else
        mutex_unlock(&dns_cache_global->lock);
#endif
        return -ENOMEM;
    }

    strncpy(entry->domain, domain, NI_MAXHOST - 1);
    entry->family = family;
    if (family == AF_INET) {
        entry->addr.ipv4 = *(struct in_addr *)addr;
    } else {
        entry->addr.ipv6 = *(struct in6_addr *)addr;
    }
    entry->expire_jiffies = jiffies + (dns_cache_global->ttl * HZ);
    INIT_LIST_HEAD(&entry->list);
    INIT_HLIST_NODE(&entry->hash_node);

    // LRU淘汰
    if (dns_cache_global->size >= dns_cache_global->max_size) {
        struct dns_cache_entry *lru_entry = list_entry(dns_cache_global->lru_list.prev,
                                                      struct dns_cache_entry, list);
        hlist_del(&lru_entry->hash_node);
        list_del(&lru_entry->list);
        kfree(lru_entry);
        dns_cache_global->size--;
    }

    // 添加到哈希表和LRU链表
    hlist_add_head(&entry->hash_node, &dns_cache_global->hash_table[hash]);
    list_add(&entry->list, &dns_cache_global->lru_list);
    dns_cache_global->size++;

#ifdef DNS_CACHE_LOCK_SPINLOCK
    spin_unlock_irqrestore(&dns_cache_global->lock, flags);
#else
    mutex_unlock(&dns_cache_global->lock);
#endif

    return 0;
}

// ###########################################################################
// TCP参数优化
// ###########################################################################
static int tcp_optimize_init(void) {
    int ret = 0;

    // 设置TCP拥塞控制算法
#ifdef CONFIG_TCP_CONG_BBR
    ret = sysctl_set_str("net.ipv4.tcp_congestion_control", TCP_CONGESTION_ALG);
#else
    pr_warn("[NetOpt++] BBR not supported, use cubic\n");
    ret = sysctl_set_str("net.ipv4.tcp_congestion_control", "cubic");
#endif
    if (ret) {
        pr_err("[NetOpt++] Set congestion control failed: %d\n", ret);
        return ret;
    }

    // 启用TCP快速打开
    ret = sysctl_set_int("net.ipv4.tcp_fastopen", TCP_FASTOPEN_QSIZE);
    if (ret) {
        pr_err("[NetOpt++] Enable TCP fastopen failed: %d\n", ret);
        return ret;
    }

    // 调整TCP连接队列和保活参数
    sysctl_set_int("net.ipv4.tcp_max_syn_backlog", TCP_MAX_SYN_BACKLOG);
    sysctl_set_int("net.ipv4.tcp_window_scaling", 1);
    sysctl_set_int("net.ipv4.tcp_keepalive_time", TCP_KEEPALIVE_TIME);
    sysctl_set_int("net.ipv4.tcp_keepalive_intvl", TCP_KEEPALIVE_INTVL);
    sysctl_set_int("net.ipv4.tcp_keepalive_probes", TCP_KEEPALIVE_PROBES);

    pr_info("[NetOpt++] TCP optimized: alg=%s, fastopen=%d\n",
            TCP_CONGESTION_ALG, TCP_FASTOPEN_QSIZE);
    return 0;
}

static void tcp_optimize_restore(void) {
    sysctl_set_str("net.ipv4.tcp_congestion_control", "cubic");
    sysctl_set_int("net.ipv4.tcp_fastopen", 0);
    pr_info("[NetOpt++] TCP parameters restored\n");
}

// ###########################################################################
// 网络请求拦截钩子
// ###########################################################################
static void before_connect(hook_fargs3_t *args, void *udata) {
    int fd = (int)syscall_argn(args, 0);
    struct sockaddr __user *addr_user = (struct sockaddr __user *)syscall_argn(args, 1);
    socklen_t addr_len = (socklen_t)syscall_argn(args, 2);

    struct sockaddr_in addr_kernel;
    if (addr_len > sizeof(addr_kernel) || copy_from_user(&addr_kernel, addr_user, addr_len)) {
        return;
    }

    // 非法端口拦截
    if (!is_port_allowed(addr_kernel.sin_port)) {
        char port_str[8];
        snprintf(port_str, sizeof(port_str), "%d", ntohs(addr_kernel.sin_port));
        pr_warn("[NetOpt++] Block connect: illegal port %s (fd:%d)\n", port_str, fd);
        args->skip_origin = 1;
        args->ret = -EACCES;
        return;
    }

    // 黑名单拦截
    char target_addr[INET6_ADDRSTRLEN];
    if (get_target_addr((struct sockaddr *)&addr_kernel, target_addr, sizeof(target_addr)) == 0) {
        for (size_t i = 0; i < BLOCK_DOMAIN_SIZE; ++i) {
            if (match_domain_prefix(target_addr, block_domain_list[i])) {
                pr_warn("[NetOpt++] Block connect: blacklisted %s (fd:%d)\n", target_addr, fd);
                args->skip_origin = 1;
                args->ret = -EACCES;
                return;
            }
        }
    }
}

static void before_sendto(hook_fargs6_t *args, void *udata) {
    int fd = (int)syscall_argn(args, 0);
    struct sockaddr __user *addr_user = (struct sockaddr __user *)syscall_argn(args, 4);
    socklen_t addr_len = (socklen_t)syscall_argn(args, 5);

    if (!addr_user || addr_len == 0) return;

    struct sockaddr_in addr_kernel;
    if (addr_len > sizeof(addr_kernel) || copy_from_user(&addr_kernel, addr_user, addr_len)) {
        return;
    }

    // 非法端口拦截
    if (!is_port_allowed(addr_kernel.sin_port)) {
        char port_str[8];
        snprintf(port_str, sizeof(port_str), "%d", ntohs(addr_kernel.sin_port));
        pr_warn("[NetOpt++] Block sendto: illegal port %s (fd:%d)\n", port_str, fd);
        args->skip_origin = 1;
        args->ret = -EACCES;
        return;
    }

    // 黑名单拦截
    char target_addr[INET6_ADDRSTRLEN];
    if (get_target_addr((struct sockaddr *)&addr_kernel, target_addr, sizeof(target_addr)) == 0) {
        for (size_t i = 0; i < BLOCK_DOMAIN_SIZE; ++i) {
            if (match_domain_prefix(target_addr, block_domain_list[i])) {
                pr_warn("[NetOpt++] Block sendto: blacklisted %s (fd:%d)\n", target_addr, fd);
                args->skip_origin = 1;
                args->ret = -EACCES;
                return;
            }
        }
    }
}

static void after_getaddrinfo(hook_fargs6_t *args, void *udata) {
    if (args->ret != 0) return;

    const char __user *node = (const char __user *)syscall_argn(args, 0);
    const char __user *service = (const char __user *)syscall_argn(args, 1);
    const struct addrinfo __user *hints = (const struct addrinfo __user *)syscall_argn(args, 2);
    struct addrinfo __user **res = (struct addrinfo __user **)syscall_argn(args, 3);

    if (!node || service || !hints || !res) return;

    // 拷贝hints参数
    struct addrinfo hints_kernel;
    if (copy_from_user(&hints_kernel, hints, sizeof(struct addrinfo))) return;

    // 只处理IPv4/IPv6的TCP/UDP请求
    if ((hints_kernel.ai_family != AF_INET && hints_kernel.ai_family != AF_INET6) ||
        (hints_kernel.ai_socktype != SOCK_STREAM && hints_kernel.ai_socktype != SOCK_DGRAM)) {
        return;
    }

    // 拷贝域名
    char domain[NI_MAXHOST];
    if (strncpy_from_user(domain, node, NI_MAXHOST - 1) < 0) return;
    domain[NI_MAXHOST - 1] = '\0';

    // 缓存命中检查
    struct dns_cache_entry *cache_entry = dns_cache_lookup(domain, hints_kernel.ai_family);
    if (cache_entry) {
        struct addrinfo ai_kernel;
        struct sockaddr_in sin_kernel;
        size_t ai_total_size = sizeof(struct addrinfo) + sizeof(struct sockaddr_in);

        // 分配用户空间内存
        struct addrinfo __user *ai_user = (struct addrinfo __user *)kp_alloc_user(ai_total_size);
        if (!ai_user) return;

        // 构造addrinfo
        memset(&ai_kernel, 0, sizeof(ai_kernel));
        ai_kernel.ai_flags = hints_kernel.ai_flags;
        ai_kernel.ai_family = hints_kernel.ai_family;
        ai_kernel.ai_socktype = hints_kernel.ai_socktype;
        ai_kernel.ai_protocol = hints_kernel.ai_protocol;
        ai_kernel.ai_addrlen = sizeof(struct sockaddr_in);
        ai_kernel.ai_addr = (struct sockaddr *)(ai_user + 1);
        ai_kernel.ai_next = NULL;

        // 构造sockaddr_in
        memset(&sin_kernel, 0, sizeof(sin_kernel));
        sin_kernel.sin_family = hints_kernel.ai_family;
        if (hints_kernel.ai_family == AF_INET) {
            sin_kernel.sin_addr = cache_entry->addr.ipv4;
        } else {
            kp_free_user(ai_user);
            return;
        }
        sin_kernel.sin_port = 0;
        if (service) {
            unsigned short port;
            if (kstrtou16_from_user(service, strlen(service), 10, &port) == 0) {
                sin_kernel.sin_port = htons(port);
            }
        }

        // 拷贝到用户空间
        if (copy_to_user(ai_user, &ai_kernel, sizeof(struct addrinfo)) ||
            copy_to_user(ai_kernel.ai_addr, &sin_kernel, sizeof(struct sockaddr_in))) {
            kp_free_user(ai_user);
            return;
        }

        // 更新res指针
        if (put_user((unsigned long)ai_user, (unsigned long __user *)res)) {
            kp_free_user(ai_user);
            return;
        }

        pr_debug("[NetOpt++] DNS cache hit: %s -> %pI4\n", domain, &cache_entry->addr.ipv4);
        return;
    }

    // 缓存未命中，添加到缓存
    struct addrinfo ai_kernel;
    if (copy_from_user(&ai_kernel, *res, sizeof(struct addrinfo))) return;

    if (ai_kernel.ai_family == AF_INET && ai_kernel.ai_addr) {
        struct sockaddr_in sin_kernel;
        if (copy_from_user(&sin_kernel, ai_kernel.ai_addr, sizeof(struct sockaddr_in))) return;
        dns_cache_add(domain, &sin_kernel.sin_addr, AF_INET);
        pr_debug("[NetOpt++] DNS cache add: %s -> %pI4\n", domain, &sin_kernel.sin_addr);
    } else if (ai_kernel.ai_family == AF_INET6 && ai_kernel.ai_addr) {
        struct sockaddr_in6 sin6_kernel;
        if (copy_from_user(&sin6_kernel, ai_kernel.ai_addr, sizeof(struct sockaddr_in6))) return;
        dns_cache_add(domain, &sin6_kernel.sin6_addr, AF_INET6);
        pr_debug("[NetOpt++] DNS cache add: %s -> %pI6\n", domain, &sin6_kernel.sin6_addr);
    }
}

// ###########################################################################
// 模块生命周期
// ###########################################################################
static long netopt_init(const char *args, const char *event, void *__user reserved) {
    hook_err_t err;
    pr_info("[NetOpt++] Initializing...\n");

    // 初始化DNS缓存
    if (dns_cache_init() != 0) {
        pr_err("[NetOpt++] DNS cache init failed\n");
        return -EINVAL;
    }

    // TCP参数优化
    if (tcp_optimize_init() != 0) {
        pr_err("[NetOpt++] TCP optimize failed\n");
        dns_cache_destroy();
        return -EINVAL;
    }

    // 挂钩syscall
    err = hook_syscalln(__NR_connect, 3, before_connect, NULL, NULL);
    if (err) { pr_err("[NetOpt++] Hook connect failed: %d\n", err); goto init_fail; }
    err = hook_syscalln(__NR_sendto, 6, before_sendto, NULL, NULL);
    if (err) { pr_err("[NetOpt++] Hook sendto failed: %d\n", err); goto init_fail; }
#ifdef __NR_getaddrinfo
    err = hook_syscalln(__NR_getaddrinfo, 6, NULL, after_getaddrinfo, NULL);
    if (err) { pr_err("[NetOpt++] Hook getaddrinfo failed: %d\n", err); goto init_fail; }
#endif

    pr_info("[NetOpt++] Initialized successfully\n");
    return 0;

init_fail:
    dns_cache_destroy();
    tcp_optimize_restore();
    unhook_syscalln(__NR_connect, before_connect, NULL);
    unhook_syscalln(__NR_sendto, before_sendto, NULL);
#ifdef __NR_getaddrinfo
    unhook_syscalln(__NR_getaddrinfo, NULL, after_getaddrinfo);
#endif
    return -EINVAL;
}

static long netopt_exit(void *__user reserved) {
    pr_info("[NetOpt++] Exiting...\n");

    tcp_optimize_restore();
    dns_cache_destroy();

    unhook_syscalln(__NR_connect, before_connect, NULL);
    unhook_syscalln(__NR_sendto, before_sendto, NULL);
#ifdef __NR_getaddrinfo
    unhook_syscalln(__NR_getaddrinfo, NULL, after_getaddrinfo);
#endif

    pr_info("[NetOpt++] Exited successfully\n");
    return 0;
}

// 注册模块
KPM_INIT(netopt_init);
KPM_EXIT(netopt_exit);
