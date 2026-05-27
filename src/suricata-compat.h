/* Minimal Suricata 8.0 ABI declarations used by this plugin.
 *
 * This intentionally avoids including Suricata source or installed headers at
 * build time. Keep these declarations in sync with Suricata 8.0.x.
 */
#ifndef SURICATA_NDPI_SURICATA_8_0_COMPAT_H
#define SURICATA_NDPI_SURICATA_8_0_COMPAT_H

#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <netinet/in.h>

#ifndef __SCFILENAME__
#define __SCFILENAME__ "ndpi-plugin"
#endif

#ifndef BIT_U16
#define BIT_U16(n) ((uint16_t)(1U << (n)))
#endif

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#define SC_API_VERSION 0x0800
#define SC_PACKAGE_VERSION "8.0.x"

#define IPV6_HEADER_LEN 40
#define PLUGIN_VAR_SIZE 64
#define DETECT_SM_LIST_MATCH 0
#define DETECT_SM_LIST_MAX 7
#define SIGMATCH_QUOTES_OPTIONAL BIT_U16(5)
#define SIGMATCH_HANDLE_NEGATION BIT_U16(7)

#define PACKET_L3_IPV4 1
#define PACKET_L3_IPV6 2

#define SCCalloc(nm, sz) SCCallocFunc((nm), (sz))
#define SCMalloc(sz) SCMallocFunc((sz))
#define SCStrdup(s) SCStrdupFunc((s))
#define SCFree(p) free((p))

void *SCCallocFunc(size_t nm, size_t sz);
void *SCMallocFunc(size_t sz);
char *SCStrdupFunc(const char *s);

/* Logging ABI. */
typedef enum {
    SC_LOG_NOTSET = -1,
    SC_LOG_NONE = 0,
    SC_LOG_ERROR,
    SC_LOG_WARNING,
    SC_LOG_NOTICE,
    SC_LOG_INFO,
    SC_LOG_PERF,
    SC_LOG_CONFIG,
    SC_LOG_DEBUG,
    SC_LOG_LEVEL_MAX,
} SCLogLevel;

static const char *_sc_module __attribute__((unused)) = __SCFILENAME__;

void SCLog(int level, const char *file, const char *func, int line, const char *module,
        const char *fmt, ...) __attribute__((format(printf, 6, 7)));
void SCLogErr(int level, const char *file, const char *func, int line, const char *module,
        const char *fmt, ...) __attribute__((format(printf, 6, 7)));
int SCLogDebugEnabled(void);

#define SCLogNotice(...) SCLog(SC_LOG_NOTICE, __FILE__, __FUNCTION__, __LINE__, _sc_module, __VA_ARGS__)
#define SCLogError(...) SCLogErr(SC_LOG_ERROR, __FILE__, __FUNCTION__, __LINE__, _sc_module, __VA_ARGS__)
#ifndef DEBUG
#define SCLogDebug(...) do { } while (0)
#define SCEnter(...)
#define SCReturnInt(x) return (x)
#else
#define SCLogDebug(...) SCLog(SC_LOG_DEBUG, __FILE__, __FUNCTION__, __LINE__, _sc_module, __VA_ARGS__)
#define SCEnter(...)
#define SCReturnInt(x) return (x)
#endif
#define FatalError(...) do { SCLogError(__VA_ARGS__); exit(EXIT_FAILURE); } while (0)

/* Packet/IP ABI fragments. */
typedef struct IPV4Hdr_ {
    uint8_t ip_verhl;
    uint8_t ip_tos;
    uint16_t ip_len;
    uint16_t ip_id;
    uint16_t ip_off;
    uint8_t ip_ttl;
    uint8_t ip_proto;
    uint16_t ip_csum;
    union {
        struct {
            struct in_addr ip_src;
            struct in_addr ip_dst;
        } ip4_un1;
        uint16_t ip_addrs[4];
    } ip4_hdrun1;
} IPV4Hdr;

#define IPV4_GET_RAW_IPLEN(ip4h) ntohs((ip4h)->ip_len)

typedef struct IPV6Hdr_ {
    union {
        struct {
            uint32_t ip6_un1_flow;
            uint16_t ip6_un1_plen;
            uint8_t ip6_un1_nxt;
            uint8_t ip6_un1_hlim;
        } ip6_un1;
        uint8_t ip6_un2_vfc;
    } ip6_hdrun;
    union {
        struct {
            uint32_t ip6_src[4];
            uint32_t ip6_dst[4];
        } ip6_un2;
        uint16_t ip6_addrs[16];
    } ip6_hdrun2;
} IPV6Hdr;

#define s_ip6_plen ip6_hdrun.ip6_un1.ip6_un1_plen
#define IPV6_GET_RAW_PLEN(ip6h) ntohs((ip6h)->s_ip6_plen)

typedef struct SCTime_ {
    uint64_t secs : 44;
    uint64_t usecs : 20;
} SCTime_t;

struct PacketL3 {
    int type;
    bool csum_set;
    uint16_t csum;
    union {
        IPV4Hdr *ip4h;
        IPV6Hdr *ip6h;
        void *ptr;
    } hdrs;
    union {
        uint8_t bytes[24];
    } vars;
};

typedef struct Flow_ Flow;

typedef struct Packet_ {
    uint8_t _pad_proto[44];
    uint8_t proto;
    uint8_t _pad_flow[19];
    Flow *flow;
    uint8_t _pad_ts[8];
    SCTime_t ts;
    uint8_t _pad_l3[104];
    struct PacketL3 l3;
    uint8_t _pad_pcap_cnt[144];
    uint64_t pcap_cnt;
} Packet;

static inline bool PacketIsIPv4(const Packet *p)
{
    return p->l3.type == PACKET_L3_IPV4;
}

static inline bool PacketIsIPv6(const Packet *p)
{
    return p->l3.type == PACKET_L3_IPV6;
}

static inline const IPV4Hdr *PacketGetIPv4(const Packet *p)
{
    return p->l3.hdrs.ip4h;
}

static inline const IPV6Hdr *PacketGetIPv6(const Packet *p)
{
    return p->l3.hdrs.ip6h;
}

struct Flow_ {
    uint8_t _pad_proto[38];
    uint8_t proto;
    uint8_t _pad_counters[209];
    uint32_t todstpktcnt;
    uint32_t tosrcpktcnt;
};

/* Detect engine ABI fragments. */
typedef struct ThreadVars_ ThreadVars;
typedef struct DetectEngineCtx_ DetectEngineCtx;
typedef struct DetectEngineThreadCtx_ DetectEngineThreadCtx;
typedef struct SigMatchCtx_ { int foo; } SigMatchCtx;

typedef struct SigMatch_ {
    uint16_t type;
    uint16_t idx;
    SigMatchCtx *ctx;
    struct SigMatch_ *next;
    struct SigMatch_ *prev;
} SigMatch;

typedef struct SignatureInitData_ {
    uint8_t _pad_negated[18];
    bool negated;
    uint8_t _pad_smlists[365];
    SigMatch *smlists[DETECT_SM_LIST_MAX];
} SignatureInitData;

typedef struct Signature_ {
    uint8_t _pad_init_data[264];
    SignatureInitData *init_data;
} Signature;

typedef struct SigTableElmt_ {
    int (*Match)(DetectEngineThreadCtx *, Packet *, const Signature *, const SigMatchCtx *);
    int (*AppLayerTxMatch)(DetectEngineThreadCtx *, Flow *, uint8_t, void *, void *,
            const Signature *, const SigMatchCtx *);
    int (*FileMatch)(DetectEngineThreadCtx *, Flow *, uint8_t, void *, const Signature *,
            const SigMatchCtx *);
    void (*Transform)(DetectEngineThreadCtx *, void *, void *);
    bool (*TransformValidate)(const uint8_t *, uint16_t, void *);
    void (*TransformId)(const uint8_t **, uint32_t *, void *);
    int (*Setup)(DetectEngineCtx *, Signature *, const char *);
    bool (*SupportsPrefilter)(const Signature *s);
    int (*SetupPrefilter)(DetectEngineCtx *de_ctx, void *sgh);
    void (*Free)(DetectEngineCtx *, void *);
    uint16_t flags;
    uint8_t tables;
    uint16_t alternative;
    const char *name;
    const char *alias;
    const char *desc;
    const char *url;
    void (*Cleanup)(struct SigTableElmt_ *);
} SigTableElmt;

extern SigTableElmt *sigmatch_table;

SigMatch *SCSigMatchAppendSMToList(DetectEngineCtx *, Signature *, uint16_t, SigMatchCtx *, int);
int SCDetectHelperNewKeywordId(void);

/* Plugin and callback ABI. */
typedef struct SCPlugin_ {
    uint64_t version;
    const char *suricata_version;
    const char *name;
    const char *plugin_version;
    const char *license;
    const char *author;
    void (*Init)(void);
} SCPlugin;

typedef struct FlowStorageId { int id; } FlowStorageId;
typedef struct ThreadStorageId { int id; } ThreadStorageId;

FlowStorageId FlowStorageRegister(const char *name, unsigned int size,
        void *(*Alloc)(unsigned int), void (*Free)(void *));
void *FlowGetStorageById(const Flow *f, FlowStorageId id);
int FlowSetStorageById(Flow *f, FlowStorageId id, void *ptr);

ThreadStorageId ThreadStorageRegister(const char *name, unsigned int size,
        void *(*Alloc)(unsigned int), void (*Free)(void *));
void *ThreadGetStorageById(const ThreadVars *tv, ThreadStorageId id);
int ThreadSetStorageById(ThreadVars *tv, ThreadStorageId id, void *ptr);

typedef void (*SCFlowInitCallbackFn)(ThreadVars *, Flow *, const Packet *, void *);
typedef void (*SCFlowUpdateCallbackFn)(ThreadVars *, Flow *, Packet *, void *);
typedef void (*SCFlowFinishCallbackFn)(ThreadVars *, Flow *, void *);
typedef void (*SCThreadInitCallbackFn)(ThreadVars *, void *);

bool SCFlowRegisterInitCallback(SCFlowInitCallbackFn fn, void *user);
bool SCFlowRegisterUpdateCallback(SCFlowUpdateCallbackFn fn, void *user);
bool SCFlowRegisterFinishCallback(SCFlowFinishCallbackFn fn, void *user);
bool SCThreadRegisterInitCallback(SCThreadInitCallbackFn fn, void *user);

typedef struct SCJsonBuilder SCJsonBuilder;
typedef void (*SCEveUserCallbackFn)(ThreadVars *, const Packet *, Flow *, SCJsonBuilder *, void *);
bool SCEveRegisterCallback(SCEveUserCallbackFn fn, void *user);
bool SCJbSetFormatted(SCJsonBuilder *jb, const char *formatted);

#endif /* SURICATA_NDPI_SURICATA_8_0_COMPAT_H */
