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
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/tcp.h>
#include <linux/sysctl.h>
#include <uapi/linux/limits.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/jiffies.h>
#include <linux/time.h>
#include <netdb.h>

// 模块元信息
KPM_NAME("NetOpt++");
KPM_VERSION("1.1");
KPM_LICENSE("GPLv3");
KPM_AUTHOR("NightFallsLikeRain");
KPM_DESCRIPTION("Android 内核网络优化模块：TCP参数调优 + 恶意网络请求拦截 + DNS缓存优化");

// -------------------------- 核心配置参数 --------------------------
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
    // 广告域名
    "ad.", "ads.", "advert.", "advertising.", "adserver.",
    "doubleclick.", "googleads.", "googlesyndication.",
    "facebookads.", "twitterads.", "bingads.", "yahooads.",
    // 追踪域名
    "analytics.", "track.", "tracking.", "stats.", "metric.",
    "datacollect.", "userbehavior.", "crashlytics.", "firebaseanalytics.",
    // 恶意/垃圾域名
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

// -------------------------- DNS缓存数据结构 --------------------------
// DNS缓存条目（支持IPv4/IPv6）
struct dns_cache_entry {
    char domain[NI_MAXHOST];              // 域名（最大长度符合POSIX标准）
    union {
        struct in_addr ipv4;              // IPv4地址
        struct in6_addr ipv6;             // IPv6地址
    } addr;
    int family;                           // 地址族（AF_INET/AF_INET6）
    unsigned long expire_jiffies;         // 过期时间（内核节拍数）
    struct list_head list;                // 链表节点（用于LRU淘汰）
    struct hlist_node hash_node;          // 哈希表节点（快速查询）
};

// DNS缓存全局结构
struct dns_cache {
    struct hlist_head *hash_table;        // 哈希表（提升查询效率）
    struct list_head lru_list;            // LRU链表（淘汰策略）
    unsigned int size;                    // 当前缓存条目数
    unsigned int max_size;                // 最大缓存条目数
    unsigned int ttl;                     // 缓存过期时间（秒）
#ifdef DNS_CACHE_LOCK_SPINLOCK
    spinlock_t lock;                      // 自旋锁（多核安全，低延迟）
#else
    struct mutex lock;                    // 互斥锁（适用于长操作）
#endif
};

static struct dns_cache *dns_cache_global = NULL;

// -------------------------- 工具函数 --------------------------
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

// 从socket地址中提取域名/IP（简化实现，优先解析IP）
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

// 哈希函数（域名哈希，用于缓存查询）
static unsigned int dns_domain_hash(const char *domain) {
    unsigned int hash = 5381;
    int c;
    while ((c = *domain++)) {
        hash = ((hash << 5) + hash) + c; // hash * 33 + c
    }
    return hash % DNS_MAX_CACHE_ENTRIES;
}

// -------------------------- DNS缓存核心操作 --------------------------
// 初始化DNS缓存
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

// 销毁DNS缓存（释放所有资源）
static void dns_cache_destroy(void) {
    if (!dns_cache_global) return;

#ifdef DNS_CACHE_LOCK_SPINLOCK
    spin_lock(&dns_cache_global->lock);
#else
    mutex_lock(&dns_cache_global->lock);
#endif

    // 遍历LRU链表，释放所有缓存条目
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

// 查找DNS缓存（命中返回条目，未命中返回NULL）
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

    // 计算哈希值，查找哈希表
    unsigned int hash = dns_domain_hash(domain);
    struct hlist_node *hpos;
    struct dns_cache_entry *entry = NULL;
    hlist_for_each_entry(hpos, &dns_cache_global->hash_table[hash], hash_node) {
        entry = hlist_entry(hpos, struct dns_cache_entry, hash_node);
        if (strcmp(entry->domain, domain) == 0 && entry->family == family) {
            // 检查是否过期
            if (time_before(jiffies, entry->expire_jiffies)) {
                // 命中，更新LRU（移到链表头部）
                list_del(&entry->list);
                list_add(&entry->list, &dns_cache_global->lru_list);
#ifdef DNS_CACHE_LOCK_SPINLOCK
                spin_unlock_irqrestore(&dns_cache_global->lock, flags);
#else
                mutex_unlock(&dns_cache_global->lock);
#endif
                return entry;
            } else {
                // 已过期，删除该条目
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

// 添加DNS缓存条目（超出最大容量时淘汰LRU尾部条目）
static int dns_cache_add(const char *domain, const void *addr, int family) {
    if (!dns_cache_global || !domain || !addr || (family != AF_INET && family != AF_INET6)) {
        return -EINVAL;
    }

    // 检查域名长度
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

    // 先检查是否已存在（避免重复添加）
    unsigned int hash = dns_domain_hash(domain);
    struct hlist_node *hpos;
    struct dns_cache_entry *entry = NULL;
    hlist_for_each_entry(hpos, &dns_cache_global->hash_table[hash], hash_node) {
        entry = hlist_entry(hpos, struct dns_cache_entry, hash_node);
        if (strcmp(entry->domain, domain) == 0 && entry->family == family) {
            // 更新已有条目（刷新过期时间+地址）
            if (family == AF_INET) {
                entry->addr.ipv4 = *(struct in_addr *)addr;
            } else {
                entry->addr.ipv6 = *(struct in6_addr *)addr;
            }
            entry->expire_jiffies = jiffies + (dns_cache_global->ttl * HZ);
            // 更新LRU位置
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

    // 填充条目信息
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

    // 超出最大容量，淘汰LRU尾部条目（最久未使用）
    if (dns_cache_global->size >= dns_cache_global->max_size) {
        struct dns_cache_entry *lru_entry = list_entry(dns_cache_global->lru_list.prev,
                                                      struct dns_cache_entry, list);
        hlist_del(&lru_entry->hash_node);
        list_del(&lru_entry->list);
        kfree(lru_entry);
        dns_cache_global->size--;
    }

    // 添加到哈希表和LRU链表头部
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

// -------------------------- TCP参数优化 --------------------------
static int tcp_optimize_init(void) {
    int ret = 0;

    // 1. 设置TCP拥塞控制算法
    ret = tcp_set_congestion_control(TCP_CONGESTION_ALG);
    if (ret) {
        pr_err("[NetOpt++] Failed to set congestion control to %s: %d\n", TCP_CONGESTION_ALG, ret);
        return ret;
    }

    // 2. 启用TCP快速打开（TFO）
    ret = sysctl_set_int("net.ipv4.tcp_fastopen", TCP_FASTOPEN_QSIZE);
    if (ret) {
        pr_err("[NetOpt++] Failed to enable TCP fastopen: %d\n", ret);
        return ret;
    }

    // 3. 调整TCP连接队列参数
    ret = sysctl_set_int("net.ipv4.tcp_max_syn_backlog", TCP_MAX_SYN_BACKLOG);
    if (ret) pr_warn("[NetOpt++] Failed to set tcp_max_syn_backlog: %d\n", ret);

    // 4. 启用窗口缩放
    ret = sysctl_set_int("net.ipv4.tcp_window_scaling", 1);
    if (ret) pr_warn("[NetOpt++] Failed to enable tcp_window_scaling: %d\n", ret);

    // 5. 调整TCP保活参数
    ret = sysctl_set_int("net.ipv4.tcp_keepalive_time", TCP_KEEPALIVE_TIME);
    if (ret) pr_warn("[NetOpt++] Failed to set tcp_keepalive_time: %d\n", ret);
    ret = sysctl_set_int("net.ipv4.tcp_keepalive_intvl", TCP_KEEPALIVE_INTVL);
    if (ret) pr_warn("[NetOpt++] Failed to set tcp_keepalive_intvl: %d\n", ret);
    ret = sysctl_set_int("net.ipv4.tcp_keepalive_probes", TCP_KEEPALIVE_PROBES);
    if (ret) pr_warn("[NetOpt++] Failed to set tcp_keepalive_probes: %d\n", ret);

    pr_info("[NetOpt++] TCP optimization applied successfully (alg: %s, fastopen: %d)\n",
            TCP_CONGESTION_ALG, TCP_FASTOPEN_QSIZE);
    return 0;
}

static void tcp_optimize_restore(void) {
    // 恢复默认拥塞控制算法（cubic为多数内核默认）
    tcp_set_congestion_control("cubic");
    // 恢复TCP快速打开默认值
    sysctl_set_int("net.ipv4.tcp_fastopen", 0);
    pr_info("[NetOpt++] TCP parameters restored to default\n");
}

// -------------------------- 网络请求拦截钩子 --------------------------
// connect 钩子：拦截TCP连接（黑名单域名+非法端口）
static void before_connect(hook_fargs3_t *args, void *udata) {
    int fd = (int)syscall_argn(args, 0);
    struct sockaddr __user *addr_user = (struct sockaddr __user *)syscall_argn(args, 1);
    socklen_t addr_len = (socklen_t)syscall_argn(args, 2);

    // 拷贝用户空间socket地址到内核空间
    struct sockaddr_in addr_kernel;
    if (addr_len > sizeof(addr_kernel)) return;
    if (copy_from_user(&addr_kernel, addr_user, addr_len)) return;

    // 检查端口是否合法
    if (!is_port_allowed(addr_kernel.sin_port)) {
        char port_str[8];
        snprintf(port_str, sizeof(port_str), "%d", ntohs(addr_kernel.sin_port));
        pr_warn("[NetOpt++] Blocked connect to illegal port %s (fd: %d)\n", port_str, fd);
        args->skip_origin = 1;
        args->ret = -EACCES;
        return;
    }

    // 检查域名/IP是否在黑名单
    char target_addr[INET6_ADDRSTRLEN];
    if (get_target_addr((struct sockaddr *)&addr_kernel, target_addr, sizeof(target_addr)) == 0) {
        for (size_t i = 0; i < BLOCK_DOMAIN_SIZE; ++i) {
            if (match_domain_prefix(target_addr, block_domain_list[i])) {
                pr_warn("[NetOpt++] Blocked connect to blacklisted domain/IP: %s (fd: %d)\n", target_addr, fd);
                args->skip_origin = 1;
                args->ret = -EACCES;
                return;
            }
        }
    }
}

// sendto 钩子：拦截UDP非法发送（非法端口+黑名单）
static void before_sendto(hook_fargs6_t *args, void *udata) {
    int fd = (int)syscall_argn(args, 0);
    struct sockaddr __user *addr_user = (struct sockaddr __user *)syscall_argn(args, 4);
    socklen_t addr_len = (socklen_t)syscall_argn(args, 5);

    if (!addr_user || addr_len == 0) return;

    struct sockaddr_in addr_kernel;
    if (addr_len > sizeof(addr_kernel)) return;
    if (copy_from_user(&addr_kernel, addr_user, addr_len)) return;

    // 非法端口拦截
    if (!is_port_allowed(addr_kernel.sin_port)) {
        char port_str[8];
        snprintf(port_str, sizeof(port_str), "%d", ntohs(addr_kernel.sin_port));
        pr_warn("[NetOpt++] Blocked sendto to illegal port %s (fd: %d)\n", port_str, fd);
        args->skip_origin = 1;
        args->ret = -EACCES;
        return;
    }

    // 黑名单域名拦截
    char target_addr[INET6_ADDRSTRLEN];
    if (get_target_addr((struct sockaddr *)&addr_kernel, target_addr, sizeof(target_addr)) == 0) {
        for (size_t i = 0; i < BLOCK_DOMAIN_SIZE; ++i) {
            if (match_domain_prefix(target_addr, block_domain_list[i])) {
                pr_warn("[NetOpt++] Blocked sendto to blacklisted domain/IP: %s (fd: %d)\n", target_addr, fd);
                args->skip_origin = 1;
                args->ret = -EACCES;
                return;
            }
        }
    }
}

// getaddrinfo 钩子：DNS缓存优化（优先从缓存查询，未命中则执行原调用并缓存结果）
static void after_getaddrinfo(hook_fargs6_t *args, void *udata) {
    // 原系统调用执行失败，直接返回
    if (args->ret != 0) return;

    const char __user *node = (const char __user *)syscall_argn(args, 0);
    const char __user *service = (const char __user *)syscall_argn(args, 1);
    const struct addrinfo __user *hints = (const struct addrinfo __user *)syscall_argn(args, 2);
    struct addrinfo __user **res = (struct addrinfo __user **)syscall_argn(args, 3);

    // 只处理域名解析（node不为空，service为空，且hints指定地址族）
    if (!node || service || !hints || !res) return;

    // 拷贝hints参数到内核空间
    struct addrinfo hints_kernel;
    if (copy_from_user(&hints_kernel, hints, sizeof(struct addrinfo))) return;

    // 只处理IPv4/IPv6的TCP/UDP解析请求
    if ((hints_kernel.ai_family != AF_INET && hints_kernel.ai_family != AF_INET6) ||
        (hints_kernel.ai_socktype != SOCK_STREAM && hints_kernel.ai_socktype != SOCK_DGRAM)) {
        return;
    }

    // 拷贝域名到内核空间
    char domain[NI_MAXHOST];
    if (strncpy_from_user(domain, node, NI_MAXHOST - 1) < 0) return;
    domain[NI_MAXHOST - 1] = '\0';

    // 检查是否命中缓存
    struct dns_cache_entry *cache_entry = dns_cache_lookup(domain, hints_kernel.ai_family);
    if (cache_entry) {
        // 缓存命中，直接构造addrinfo返回给用户空间，跳过原结果
        struct addrinfo ai_kernel, *ai_user;
        struct sockaddr_in sin_kernel;
        size_t ai_size = sizeof(struct addrinfo) + sizeof(struct sockaddr_in);

        // 分配用户空间内存（用于存储addrinfo和sockaddr）
        ai_user = (struct addrinfo __user *)__get_free_user_pages(GFP_KERNEL, 0, 0);
        if (!ai_user) return;

        // 构造addrinfo结构
        memset(&ai_kernel, 0, sizeof(ai_kernel));
        ai_kernel.ai_flags = hints_kernel.ai_flags;
        ai_kernel.ai_family = hints_kernel.ai_family;
        ai_kernel.ai_socktype = hints_kernel.ai_socktype;
        ai_kernel.ai_protocol = hints_kernel.ai_protocol;
        ai_kernel.ai_addrlen = sizeof(struct sockaddr_in);
        ai_kernel.ai_addr = (struct sockaddr *)(ai_user + 1); // 地址紧随addrinfo之后
        ai_kernel.ai_next = NULL;

        // 构造sockaddr_in结构
        memset(&sin_kernel, 0, sizeof(sin_kernel));
        sin_kernel.sin_family = hints_kernel.ai_family;
        if (hints_kernel.ai_family == AF_INET) {
            sin_kernel.sin_addr = cache_entry->addr.ipv4;
        } else {
            // IPv6需调整结构，此处简化处理（完整实现需用sockaddr_in6）
            return;
        }
        // 端口由service指定，若未指定则设为0
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
            free_user_pages((unsigned long)ai_user, 1);
            return;
        }

        // 更新用户空间的res指针
        if (put_user((unsigned long)ai_user, (unsigned long __user *)res)) {
            free_user_pages((unsigned long)ai_user, 1);
            return;
        }

        pr_debug("[NetOpt++] DNS cache hit: %s -> %pI4\n", domain, &cache_entry->addr.ipv4);
        return;
    }

    // 缓存未命中，提取原调用结果并添加到缓存
    struct addrinfo ai_kernel;
    if (copy_from_user(&ai_kernel, *res, sizeof(struct addrinfo))) return;

    if (ai_kernel.ai_family == AF_INET && ai_kernel.ai_addr) {
        struct sockaddr_in sin_kernel;
        if (copy_from_user(&sin_kernel, ai_kernel.ai_addr, sizeof(struct sockaddr_in))) return;
        // 添加到DNS缓存
        dns_cache_add(domain, &sin_kernel.sin_addr, AF_INET);
        pr_debug("[NetOpt++] DNS cache added: %s -> %pI4\n", domain, &sin_kernel.sin_addr);
    } else if (ai_kernel.ai_family == AF_INET6 && ai_kernel.ai_addr) {
        struct sockaddr_in6 sin6_kernel;
        if (copy_from_user(&sin6_kernel, ai_kernel.ai_addr, sizeof(struct sockaddr_in6))) return;
        // 添加到DNS缓存
        dns_cache_add(domain, &sin6_kernel.sin6_addr, AF_INET6);
        pr_debug("[NetOpt++] DNS cache added: %s -> %pI6\n", domain, &sin6_kernel.sin6_addr);
    }
}

// -------------------------- 模块生命周期 --------------------------
static long netopt_init(const char *args, const char *event, void *__user reserved) {
    hook_err_t err;
    pr_info("[NetOpt++] Initializing network optimization module...\n");

    // 1. 初始化DNS缓存
    if (dns_cache_init() != 0) {
        pr_err("[NetOpt++] DNS cache init failed, module init aborted\n");
        return -EINVAL;
    }

    // 2. 应用TCP参数优化
    if (tcp_optimize_init() != 0) {
        pr_err("[NetOpt++] TCP optimization failed, module init aborted\n");
        dns_cache_destroy();
        return -EINVAL;
    }

    // 3. 挂钩核心网络syscall
    // 挂钩connect（TCP连接）
    err = hook_syscalln(__NR_connect, 3, before_connect, NULL, NULL);
    if (err) { pr_err("[NetOpt++] Hook connect failed: %d\n", err); goto init_fail; }
    // 挂钩sendto（UDP发送）
    err = hook_syscalln(__NR_sendto, 6, before_sendto, NULL, NULL);
    if (err) { pr_err("[NetOpt++] Hook sendto failed: %d\n", err); goto init_fail; }
    // 挂钩getaddrinfo（DNS解析，使用after钩子缓存结果）
#ifdef __NR_getaddrinfo
    err = hook_syscalln(__NR_getaddrinfo, 6, NULL, after_getaddrinfo, NULL);
    if (err) { pr_err("[NetOpt++] Hook getaddrinfo failed: %d\n", err); goto init_fail; }
#endif

    pr_info("[NetOpt++] Module initialized successfully: TCP optimized + network hooks + DNS cache loaded\n");
    return 0;

init_fail:
    // 初始化失败，清理资源
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
    pr_info("[NetOpt++] Exiting network optimization module...\n");

    // 1. 恢复TCP默认参数
    tcp_optimize_restore();

    // 2. 销毁DNS缓存
    dns_cache_destroy();

    // 3. 解钩syscall
    unhook_syscalln(__NR_connect, before_connect, NULL);
    unhook_syscalln(__NR_sendto, before_sendto, NULL);
#ifdef __NR_getaddrinfo
    unhook_syscalln(__NR_getaddrinfo, NULL, after_getaddrinfo);
#endif

    pr_info("[NetOpt++] Module exited successfully: TCP parameters + DNS cache + hooks cleaned up\n");
    return 0;
}

// 注册模块初始化/退出函数
KPM_INIT(netopt_init);
KPM_EXIT(netopt_exit);
