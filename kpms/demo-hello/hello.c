#include <compiler.h>
#include <kpmodule.h>
#include <kputils.h>
#include <syscall.h>
// 仅保留框架公共头文件，不手动引入任何内部路径头文件
#include <linux/printk.h>
#include <linux/string.h>
#include <asm/current.h>
#include <linux/errno.h>
#include <linux/kernel.h>

// ###########################################################################
// 仅补充框架未提供的基础定义（用#ifndef包裹，避免重复）
// ###########################################################################
#ifndef GFP_KERNEL
#define GFP_KERNEL 0
#endif
#ifndef __be16
typedef unsigned short __be16;
#endif
#ifndef __be32
typedef unsigned int __be32;
#endif
#ifndef __u8
typedef unsigned char __u8;
#endif
#ifndef __u16
typedef unsigned short __u16;
#endif
#ifndef __u32
typedef unsigned int __u32;
#endif
#ifndef __u64
typedef unsigned long __u64;
#endif
#ifndef __kernel_sa_family_t
typedef unsigned short __kernel_sa_family_t;
#endif
#ifndef socklen_t
typedef unsigned int socklen_t;
#endif
#ifndef NI_MAXHOST
#define NI_MAXHOST 1025
#endif
#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif

// 2. 字节序宏（框架未提供时补充）
#ifndef htons
#define htons(x) ((__be16)((((x) & 0xff) << 8) | (((x) & 0xff00) >> 8)))
#endif
#ifndef ntohs
#define ntohs(x) htons(x)
#endif
#ifndef htonl
#define htonl(x) ((__be32)((((x) & 0xff) << 24) | (((x) & 0xff00) << 8) | (((x) & 0xff0000) >> 8) | (((x) & 0xff000000) >> 24)))
#endif
#ifndef ntohl
#define ntohl(x) htonl(x)
#endif

// 3. 网络相关宏（框架未提供时补充）
#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif
#ifndef SOCK_STREAM
#define SOCK_STREAM 1
#endif
#ifndef SOCK_DGRAM
#define SOCK_DGRAM 2
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif
#ifndef SOL_SOCKET
#define SOL_SOCKET 1
#endif
#ifndef EAFNOSUPPORT
#define EAFNOSUPPORT 97
#endif
#ifndef EACCES
#define EACCES 13
#endif

// 4. 时间相关定义（框架未提供时补充）
extern unsigned long jiffies;
#ifndef HZ
#define HZ 100
#endif
#ifndef time_before
#define time_before(a, b) ((long)(a) - (long)(b) < 0)
#endif

// 5. 内存/字符串函数声明（兼容框架环境）
extern void *kmalloc(size_t size, int flags);
extern void kfree(void *ptr);
static inline void *kzalloc(size_t size, int flags) {
    void *ptr = kmalloc(size, flags);
    if (ptr) memset(ptr, 0, size);
    return ptr;
}
extern int copy_from_user(void *to, const void __user *from, size_t n);
extern int copy_to_user(void __user *to, const void *from, size_t n);
extern long strncpy_from_user(char *to, const char __user *from, size_t count);
extern int put_user(unsigned long val, unsigned long __user *addr);
extern int kstrtou16_from_user(const char __user *s, size_t count, unsigned int base, unsigned short *res);
extern void *kp_alloc_user(size_t size);
extern void kp_free_user(void __user *ptr);
extern int sysctl_set_str(const char *path, const char *val);
extern int sysctl_set_int(const char *path, int val);

// 6. 调试打印宏（兼容框架）
#ifndef pr_debug
#define pr_debug(fmt, ...) pr_info(fmt, ##__VA_ARGS__)
#endif

// ###########################################################################
// 网络相关结构体（独立实现，无框架冲突）
// ###########################################################################
struct in_addr {
    __be32 s_addr;
};
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
struct sockaddr {
    __kernel_sa_family_t sa_family;
    char sa_data[14];
};
struct sockaddr_in {
    __kernel_sa_family_t sin_family;
    __be16 sin_port;
    struct in_addr sin_addr;
    unsigned char sin_zero[8];
};
struct sockaddr_in6 {
    __kernel_sa_family_t sin6_family;
    __be16 sin6_port;
    __be32 sin6_flowinfo;
    struct in6_addr sin6_addr;
    __be32 sin6_scope_id;
};
struct addrinfo {
    int ai_flags;
    int ai_family;
    int ai_socktype;
    int ai_protocol;
    socklen_t ai_addrlen;
    char *ai_canonname;
    struct sockaddr *ai_addr;
    struct addrinfo *ai_next;
};

// 7. IP地址转字符串（独立实现）
static const char *inet_ntop(int family, const void *addr, char *buf, size_t buf_len) {
    if (!addr || !buf || buf_len == 0) return NULL;
    switch (family) {
        case AF_INET: {
            const struct in_addr *ipv4 = (const struct in_addr *)addr;
            __u8 *bytes = (__u8 *)&ipv4->s_addr;
            int ret = snprintf(buf, buf_len, "%u.%u.%u.%u",
                              bytes[0], bytes[1], bytes[2], bytes[3]);
            return (ret >= 0 && (size_t)ret < buf_len) ? buf : NULL;
        }
        case AF_INET6: {
            const struct in6_addr *ipv6 = (const struct in6_addr *)addr;
            char temp[INET6_ADDRSTRLEN] = {0};
            size_t pos = 0;
            for (int i = 0; i < 8; ++i) {
                __u16 segment = ntohs(ipv6->s6_addr16[i]);
                int ret = snprintf(temp + pos, sizeof(temp) - pos,
                                  "%x%s", segment, (i < 7) ? ":" : "");
                if (ret < 0 || (pos += ret) >= sizeof(temp)) return NULL;
            }
            if (strlen(temp) >= buf_len) return NULL;
            strcpy(buf, temp);
            return buf;
        }
        default:
            return NULL;
    }
}

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
#define TCP_CONGESTION_ALG "bbr"
#define TCP_FASTOPEN_QSIZE 64
#define TCP_MAX_SYN_BACKLOG 1024
#define TCP_KEEPALIVE_TIME 300
#define TCP_KEEPALIVE_INTVL 60
#define TCP_KEEPALIVE_PROBES 3
#define DNS_CACHE_TTL 300
#define DNS_MAX_CACHE_ENTRIES 128
#define DNS_CACHE_LOCK_SPINLOCK

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

static const __be16 allowed_ports[] = {
    htons(80), htons(443), htons(21), htons(22), htons(53),
    htons(110), htons(143), htons(3389), htons(8080), htons(8443)
};
#define ALLOWED_PORT_SIZE (sizeof(allowed_ports)/sizeof(allowed_ports[0]))

// ###########################################################################
// DNS缓存数据结构（完全使用框架间接提供的类型）
// ###########################################################################
struct dns_cache_entry {
    char domain[NI_MAXHOST];
    union {
        struct in_addr ipv4;
        struct in6_addr ipv6;
    } addr;
    int family;
    unsigned long expire_jiffies;
    struct list_head list;       // 框架间接提供（通过kpmodule.h/kputils.h）
    struct hlist_node hash_node; // 框架间接提供
};
struct dns_cache {
    struct hlist_head *hash_table; // 框架间接提供
    struct list_head lru_list;     // 框架间接提供
    unsigned int size;
    unsigned int max_size;
    unsigned int ttl;
#ifdef DNS_CACHE_LOCK_SPINLOCK
    spinlock_t lock; // 框架间接提供
#else
    struct mutex lock; // 框架间接提供
#endif
};
static struct dns_cache *dns_cache_global = NULL;

// ###########################################################################
// 工具函数
// ###########################################################################
static int is_port_allowed(__be16 port) {
    for (size_t i = 0; i < ALLOWED_PORT_SIZE; ++i) {
        if (port == allowed_ports[i]) return 1;
    }
    return 0;
}
static int match_domain_prefix(const char *domain, const char *prefix) {
    size_t prefix_len = strlen(prefix);
    return strncmp(domain, prefix, prefix_len) == 0;
}
static int get_target_addr(struct sockaddr *sa, char *buf, size_t buf_len) {
    if (!sa || !buf) return -EINVAL;
    void *addr_ptr = NULL;
    if (sa->sa_family == AF_INET) {
        addr_ptr = (void *)&((struct sockaddr_in *)sa)->sin_addr;
    } else if (sa->sa_family == AF_INET6) {
        addr_ptr = (void *)&((struct sockaddr_in6 *)sa)->sin6_addr;
    } else {
        return -EAFNOSUPPORT;
    }
    return inet_ntop(sa->sa_family, addr_ptr, buf, buf_len) ? 0 : -EINVAL;
}
static unsigned int dns_domain_hash(const char *domain) {
    unsigned int hash = 5381;
    int c;
    while ((c = *domain++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash % DNS_MAX_CACHE_ENTRIES;
}

// ###########################################################################
// DNS缓存核心操作（完全使用框架间接提供的宏）
// ###########################################################################
static int dns_cache_init(void) {
    dns_cache_global = kzalloc(sizeof(struct dns_cache), GFP_KERNEL);
    if (!dns_cache_global) return -EINVAL;

    dns_cache_global->hash_table = kzalloc(sizeof(struct hlist_head) * DNS_MAX_CACHE_ENTRIES, GFP_KERNEL);
    if (!dns_cache_global->hash_table) {
        kfree(dns_cache_global);
        return -EINVAL;
    }
    for (int i = 0; i < DNS_MAX_CACHE_ENTRIES; ++i) {
        INIT_HLIST_HEAD(&dns_cache_global->hash_table[i]); // 框架间接提供的宏
    }

    INIT_LIST_HEAD(&dns_cache_global->lru_list); // 框架间接提供的宏
    dns_cache_global->size = 0;
    dns_cache_global->max_size = DNS_MAX_CACHE_ENTRIES;
    dns_cache_global->ttl = DNS_CACHE_TTL;
#ifdef DNS_CACHE_LOCK_SPINLOCK
    spin_lock_init(&dns_cache_global->lock); // 框架间接提供的宏
#else
    mutex_init(&dns_cache_global->lock); // 框架间接提供的宏
#endif

    pr_info("[NetOpt++] DNS cache initialized: max entries=%d, TTL=%ds\n",
            DNS_MAX_CACHE_ENTRIES, DNS_CACHE_TTL);
    return 0;
}
static void dns_cache_destroy(void) {
    if (!dns_cache_global) return;

#ifdef DNS_CACHE_LOCK_SPINLOCK
    spin_lock(&dns_cache_global->lock); // 框架间接提供的宏
#else
    mutex_lock(&dns_cache_global->lock); // 框架间接提供的宏
#endif

    struct list_head *pos, *n;
    list_for_each_safe(pos, n, &dns_cache_global->lru_list) { // 框架间接提供的宏
        struct dns_cache_entry *entry = list_entry(pos, struct dns_cache_entry, list); // 框架间接提供的宏
        hlist_del(&entry->hash_node); // 框架间接提供的宏
        list_del(&entry->list); // 框架间接提供的宏
        kfree(entry);
    }

#ifdef DNS_CACHE_LOCK_SPINLOCK
    spin_unlock(&dns_cache_global->lock); // 框架间接提供的宏
#else
    mutex_unlock(&dns_cache_global->lock); // 框架间接提供的宏
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
    spin_lock_irqsave(&dns_cache_global->lock, flags); // 框架间接提供的宏
#else
    mutex_lock(&dns_cache_global->lock);
#endif

    unsigned int hash = dns_domain_hash(domain);
    struct dns_cache_entry *entry = NULL;
    hlist_for_each_entry(entry, &dns_cache_global->hash_table[hash], hash_node) { // 框架间接提供的宏
        if (strcmp(entry->domain, domain) == 0 && entry->family == family) {
            if (time_before(jiffies, entry->expire_jiffies)) {
                list_del(&entry->list);
                list_add(&entry->list, &dns_cache_global->lru_list); // 框架间接提供的宏
#ifdef DNS_CACHE_LOCK_SPINLOCK
                spin_unlock_irqrestore(&dns_cache_global->lock, flags); // 框架间接提供的宏
#else
                mutex_unlock(&dns_cache_global->lock);
#endif
                return entry;
            } else {
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
    spin_lock_irqsave(&dns_cache_global->lock, flags); // 框架间接提供的宏
#else
    mutex_lock(&dns_cache_global->lock);
#endif

    unsigned int hash = dns_domain_hash(domain);
    struct dns_cache_entry *entry = NULL;
    hlist_for_each_entry(entry, &dns_cache_global->hash_table[hash], hash_node) { // 框架间接提供的宏
        if (strcmp(entry->domain, domain) == 0 && entry->family == family) {
            if (family == AF_INET) {
                entry->addr.ipv4 = *(struct in_addr *)addr;
            } else {
                entry->addr.ipv6 = *(struct in6_addr *)addr;
            }
            entry->expire_jiffies = jiffies + (dns_cache_global->ttl * HZ);
            list_del(&entry->list);
            list_add(&entry->list, &dns_cache_global->lru_list); // 框架间接提供的宏
#ifdef DNS_CACHE_LOCK_SPINLOCK
            spin_unlock_irqrestore(&dns_cache_global->lock, flags);
#else
            mutex_unlock(&dns_cache_global->lock);
#endif
            return 0;
        }
    }

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
    INIT_LIST_HEAD(&entry->list); // 框架间接提供的宏
    INIT_HLIST_NODE(&entry->hash_node); // 框架间接提供的宏

    if (dns_cache_global->size >= dns_cache_global->max_size) {
        struct dns_cache_entry *lru_entry = list_entry(dns_cache_global->lru_list.prev,
                                                      struct dns_cache_entry, list); // 框架间接提供的宏
        hlist_del(&lru_entry->hash_node);
        list_del(&lru_entry->list);
        kfree(lru_entry);
        dns_cache_global->size--;
    }

    hlist_add_head(&entry->hash_node, &dns_cache_global->hash_table[hash]); // 框架间接提供的宏
    list_add(&entry->list, &dns_cache_global->lru_list); // 框架间接提供的宏
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
    ret = sysctl_set_int("net.ipv4.tcp_fastopen", TCP_FASTOPEN_QSIZE);
    if (ret) {
        pr_err("[NetOpt++] Enable TCP fastopen failed: %d\n", ret);
        return ret;
    }
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

    if (!is_port_allowed(addr_kernel.sin_port)) {
        char port_str[8];
        snprintf(port_str, sizeof(port_str), "%d", ntohs(addr_kernel.sin_port));
        pr_warn("[NetOpt++] Block connect: illegal port %s (fd:%d)\n", port_str, fd);
        args->skip_origin = 1;
        args->ret = -EACCES;
        return;
    }

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

    if (!is_port_allowed(addr_kernel.sin_port)) {
        char port_str[8];
        snprintf(port_str, sizeof(port_str), "%d", ntohs(addr_kernel.sin_port));
        pr_warn("[NetOpt++] Block sendto: illegal port %s (fd:%d)\n", port_str, fd);
        args->skip_origin = 1;
        args->ret = -EACCES;
        return;
    }

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

    struct addrinfo hints_kernel;
    if (copy_from_user(&hints_kernel, hints, sizeof(struct addrinfo))) return;

    if ((hints_kernel.ai_family != AF_INET && hints_kernel.ai_family != AF_INET6) ||
        (hints_kernel.ai_socktype != SOCK_STREAM && hints_kernel.ai_socktype != SOCK_DGRAM)) {
        return;
    }

    char domain[NI_MAXHOST];
    if (strncpy_from_user(domain, node, NI_MAXHOST - 1) < 0) return;
    domain[NI_MAXHOST - 1] = '\0';

    struct dns_cache_entry *cache_entry = dns_cache_lookup(domain, hints_kernel.ai_family);
    if (cache_entry) {
        struct addrinfo ai_kernel;
        struct sockaddr_in sin_kernel;
        size_t ai_total_size = sizeof(struct addrinfo) + sizeof(struct sockaddr_in);

        struct addrinfo __user *ai_user = (struct addrinfo __user *)kp_alloc_user(ai_total_size);
        if (!ai_user) return;

        memset(&ai_kernel, 0, sizeof(ai_kernel));
        ai_kernel.ai_flags = hints_kernel.ai_flags;
        ai_kernel.ai_family = hints_kernel.ai_family;
        ai_kernel.ai_socktype = hints_kernel.ai_socktype;
        ai_kernel.ai_protocol = hints_kernel.ai_protocol;
        ai_kernel.ai_addrlen = sizeof(struct sockaddr_in);
        ai_kernel.ai_addr = (struct sockaddr *)(ai_user + 1);
        ai_kernel.ai_next = NULL;

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

        if (copy_to_user(ai_user, &ai_kernel, sizeof(struct addrinfo)) ||
            copy_to_user(ai_kernel.ai_addr, &sin_kernel, sizeof(struct sockaddr_in))) {
            kp_free_user(ai_user);
            return;
        }

        if (put_user((unsigned long)ai_user, (unsigned long __user *)res)) {
            kp_free_user(ai_user);
            return;
        }

        pr_debug("[NetOpt++] DNS cache hit: %s -> %s\n", domain,
                inet_ntop(AF_INET, &cache_entry->addr.ipv4, domain, NI_MAXHOST));
        return;
    }

    struct addrinfo ai_kernel;
    if (copy_from_user(&ai_kernel, *res, sizeof(struct addrinfo))) return;

    if (ai_kernel.ai_family == AF_INET && ai_kernel.ai_addr) {
        struct sockaddr_in sin_kernel;
        if (copy_from_user(&sin_kernel, ai_kernel.ai_addr, sizeof(struct sockaddr_in))) return;
        dns_cache_add(domain, &sin_kernel.sin_addr, AF_INET);
        pr_debug("[NetOpt++] DNS cache add: %s -> %s\n", domain,
                inet_ntop(AF_INET, &sin_kernel.sin_addr, domain, NI_MAXHOST));
    } else if (ai_kernel.ai_family == AF_INET6 && ai_kernel.ai_addr) {
        struct sockaddr_in6 sin6_kernel;
        if (copy_from_user(&sin6_kernel, ai_kernel.ai_addr, sizeof(struct sockaddr_in6))) return;
        dns_cache_add(domain, &sin6_kernel.sin6_addr, AF_INET6);
        pr_debug("[NetOpt++] DNS cache add: %s -> %s\n", domain,
                inet_ntop(AF_INET6, &sin6_kernel.sin6_addr, domain, NI_MAXHOST));
    }
}

// ###########################################################################
// 模块生命周期
// ###########################################################################
static long netopt_init(const char *args, const char *event, void *__user reserved) {
    hook_err_t err;
    pr_info("[NetOpt++] Initializing...\n");

    if (dns_cache_init() != 0) {
        pr_err("[NetOpt++] DNS cache init failed\n");
        return -EINVAL;
    }

    if (tcp_optimize_init() != 0) {
        pr_err("[NetOpt++] TCP optimize failed\n");
        dns_cache_destroy();
        return -EINVAL;
    }

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
