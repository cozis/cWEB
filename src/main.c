#include <stdio.h>
#include <limits.h>
#include <stdlib.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <link.h>
#include <dlfcn.h>
#include <errno.h>
#include <signal.h>
#include <execinfo.h>
#include <sys/random.h>
#endif

#ifdef CWEB_ENABLE_DATABASE
#include "sqlite3.h"
#endif

#ifndef CWEB_AMALGAMATION
#ifdef CWEB_ENABLE_TEMPLATE
#include "wl.h"
#endif
#include "chttp.h"
#include "main.h"
#endif

#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))
#define MAX(X, Y) ((X) > (Y) ? (X) : (Y))
#define ASSERT(X) {if (!(X)) { __builtin_trap(); }}
#define TRACE(X, ...) ((void) 0)
#define SIZEOF(X) (int) (sizeof(X)/sizeof((X)[0]))

static int  crash_logger_init(char *file_name, int file_name_len);
static void crash_logger_free(void);

#ifdef CWEB_ENABLE_TEMPLATE

typedef struct {
    char           path[1<<8];
    int            pathlen;
    WL_Program     program;
} CachedProgram;

typedef struct {
    int count;
    int capacity_log2;
    CachedProgram pool[];
} TemplateCache;

static TemplateCache *template_cache_init(int capacity_log2);
static void           template_cache_free(TemplateCache *cache);

#endif

typedef struct SessionStorage SessionStorage;

#ifdef CWEB_ENABLE_DATABASE

typedef struct SQLiteCache SQLiteCache;

static SQLiteCache* sqlite_cache_init(sqlite3 *db, int capacity_log2);
static void         sqlite_cache_free(SQLiteCache *cache);

static int sqlite3utils_prepare(SQLiteCache *cache,
    sqlite3_stmt **pstmt, char *fmt, int fmtlen);

static int sqlite3utils_prepare_and_bind_impl(SQLiteCache *cache,
    sqlite3_stmt **pstmt, char *fmt, CWEB_VArgs args);

#define sqlite3utils_prepare_and_bind(cache, pstmt, fmt, ...) \
    sqlite3utils_prepare_and_bind_impl((cache), (pstmt), (fmt), VARGS(__VA_ARGS__))

#endif

struct CWEB_Request {

    CWEB *cweb;

    WL_Arena arena;

    HTTP_Request *req;
    HTTP_ResponseBuilder builder;

    // Session
    bool just_created_session;
    int  user_id;
    CWEB_String sess;
    CWEB_String csrf;
};

struct CWEB {

    HTTP_Server *server;
    int pool_cap;
    char *pool;

    uint16_t port;
    uint16_t secure_port;

    // Login
    SessionStorage *session_storage;

#ifdef CWEB_ENABLE_DATABASE
    sqlite3 *db;
    SQLiteCache *dbcache;
    bool trace_sql;
#endif

#ifdef CWEB_ENABLE_TEMPLATE
    TemplateCache *tpcache;
    bool enable_template_cache;
#endif

    bool allow_insecure_login;

    CWEB_Request req;
};

///////////////////////////

bool cweb_streq(CWEB_String a, CWEB_String b)
{
    return http_streq((HTTP_String) { a.ptr, a.len }, (HTTP_String) { b.ptr, b.len });
}

CWEB_String cweb_trim(CWEB_String s)
{
    HTTP_String s2 = http_trim((HTTP_String) { s.ptr, s.len });
    return (CWEB_String) { s2.ptr, s2.len };
}

static const char *type_names__[] = {
    [CWEB_VARG_TYPE_C] = "char",
    [CWEB_VARG_TYPE_S] = "short",
    [CWEB_VARG_TYPE_I] = "int",
    [CWEB_VARG_TYPE_L] = "long",
    [CWEB_VARG_TYPE_LL] = "long long",
    [CWEB_VARG_TYPE_SC] = "signed char",
    [CWEB_VARG_TYPE_SS] = "signed short",
    [CWEB_VARG_TYPE_SI] = "signed int",
    [CWEB_VARG_TYPE_SL] = "signed long",
    [CWEB_VARG_TYPE_SLL] = "signed long long",
    [CWEB_VARG_TYPE_UC] = "unsigned char",
    [CWEB_VARG_TYPE_US] = "unsigned short",
    [CWEB_VARG_TYPE_UI] = "unsigned int",
    [CWEB_VARG_TYPE_UL] = "unsigned long",
    [CWEB_VARG_TYPE_ULL] = "unsigned long long",
    [CWEB_VARG_TYPE_F] = "float",
    [CWEB_VARG_TYPE_D] = "double",
    [CWEB_VARG_TYPE_B] = "bool",
    [CWEB_VARG_TYPE_STR] = "string",
    [CWEB_VARG_TYPE_HASH] = "hash",
    [CWEB_VARG_TYPE_PC] = "char*",
    [CWEB_VARG_TYPE_PS] = "short*",
    [CWEB_VARG_TYPE_PI] = "int*",
    [CWEB_VARG_TYPE_PL] = "long*",
    [CWEB_VARG_TYPE_PLL] = "long long*",
    [CWEB_VARG_TYPE_PSC] = "signed char*",
    [CWEB_VARG_TYPE_PSS] = "signed short*",
    [CWEB_VARG_TYPE_PSI] = "signed int*",
    [CWEB_VARG_TYPE_PSL] = "signed long*",
    [CWEB_VARG_TYPE_PSLL] = "signed long long*",
    [CWEB_VARG_TYPE_PUC] = "unsigned char*",
    [CWEB_VARG_TYPE_PUS] = "unsigned short*",
    [CWEB_VARG_TYPE_PUI] = "unsigned int*",
    [CWEB_VARG_TYPE_PUL] = "unsigned long*",
    [CWEB_VARG_TYPE_PULL] = "unsigned long long*",
    [CWEB_VARG_TYPE_PF] = "float*",
    [CWEB_VARG_TYPE_PD] = "double*",
    [CWEB_VARG_TYPE_PB] = "bool*",
    [CWEB_VARG_TYPE_PSTR] = "string*",
    [CWEB_VARG_TYPE_PHASH] = "hash*",
};

CWEB_VArg cweb_varg_from_c    (char c)            { return (CWEB_VArg) { CWEB_VARG_TYPE_C,    .c=c       }; }
CWEB_VArg cweb_varg_from_s    (short s)           { return (CWEB_VArg) { CWEB_VARG_TYPE_S,    .s=s       }; }
CWEB_VArg cweb_varg_from_i    (int i)             { return (CWEB_VArg) { CWEB_VARG_TYPE_I,    .i=i       }; }
CWEB_VArg cweb_varg_from_l    (long l)            { return (CWEB_VArg) { CWEB_VARG_TYPE_L,    .l=l       }; }
CWEB_VArg cweb_varg_from_ll   (long long ll)      { return (CWEB_VArg) { CWEB_VARG_TYPE_LL,   .ll=ll     }; }
CWEB_VArg cweb_varg_from_sc   (char sc)           { return (CWEB_VArg) { CWEB_VARG_TYPE_SC,   .sc=sc     }; }
CWEB_VArg cweb_varg_from_ss   (short ss)          { return (CWEB_VArg) { CWEB_VARG_TYPE_SS,   .ss=ss     }; }
CWEB_VArg cweb_varg_from_si   (int si)            { return (CWEB_VArg) { CWEB_VARG_TYPE_SI,   .si=si     }; }
CWEB_VArg cweb_varg_from_sl   (long sl)           { return (CWEB_VArg) { CWEB_VARG_TYPE_SL,   .sl=sl     }; }
CWEB_VArg cweb_varg_from_sll  (long long sll)     { return (CWEB_VArg) { CWEB_VARG_TYPE_SLL,  .sll=sll   }; }
CWEB_VArg cweb_varg_from_uc   (char uc)           { return (CWEB_VArg) { CWEB_VARG_TYPE_UC,   .uc=uc     }; }
CWEB_VArg cweb_varg_from_us   (short us)          { return (CWEB_VArg) { CWEB_VARG_TYPE_US,   .us=us     }; }
CWEB_VArg cweb_varg_from_ui   (int ui)            { return (CWEB_VArg) { CWEB_VARG_TYPE_UI,   .ui=ui     }; }
CWEB_VArg cweb_varg_from_ul   (long ul)           { return (CWEB_VArg) { CWEB_VARG_TYPE_UL,   .ul=ul     }; }
CWEB_VArg cweb_varg_from_ull  (long long ull)     { return (CWEB_VArg) { CWEB_VARG_TYPE_ULL,  .ull=ull   }; }
CWEB_VArg cweb_varg_from_f    (float f)           { return (CWEB_VArg) { CWEB_VARG_TYPE_F,    .f=f       }; }
CWEB_VArg cweb_varg_from_d    (double d)          { return (CWEB_VArg) { CWEB_VARG_TYPE_D,    .d=d       }; }
CWEB_VArg cweb_varg_from_b    (bool b)            { return (CWEB_VArg) { CWEB_VARG_TYPE_B,    .b=b       }; }
CWEB_VArg cweb_varg_from_str  (CWEB_String str)   { return (CWEB_VArg) { CWEB_VARG_TYPE_STR,  .str=str   }; }
CWEB_VArg cweb_varg_from_hash (CWEB_PasswordHash hash) { return (CWEB_VArg) { CWEB_VARG_TYPE_HASH, .hash=hash }; }
CWEB_VArg cweb_varg_from_pc   (char *pc)          { return (CWEB_VArg) { CWEB_VARG_TYPE_PC,   .pc=pc     }; }
CWEB_VArg cweb_varg_from_ps   (short *ps)         { return (CWEB_VArg) { CWEB_VARG_TYPE_PS,   .ps=ps     }; }
CWEB_VArg cweb_varg_from_pi   (int *pi)           { return (CWEB_VArg) { CWEB_VARG_TYPE_PI,   .pi=pi     }; }
CWEB_VArg cweb_varg_from_pl   (long *pl)          { return (CWEB_VArg) { CWEB_VARG_TYPE_PL,   .pl=pl     }; }
CWEB_VArg cweb_varg_from_pll  (long long *pll)    { return (CWEB_VArg) { CWEB_VARG_TYPE_PLL,  .pll=pll   }; }
CWEB_VArg cweb_varg_from_psc  (signed char *psc)         { return (CWEB_VArg) { CWEB_VARG_TYPE_PSC,  .psc=psc   }; }
CWEB_VArg cweb_varg_from_pss  (signed short *pss)        { return (CWEB_VArg) { CWEB_VARG_TYPE_PSS,  .pss=pss   }; }
CWEB_VArg cweb_varg_from_psi  (signed int *psi)          { return (CWEB_VArg) { CWEB_VARG_TYPE_PSI,  .psi=psi   }; }
CWEB_VArg cweb_varg_from_psl  (signed long *psl)         { return (CWEB_VArg) { CWEB_VARG_TYPE_PSL,  .psl=psl   }; }
CWEB_VArg cweb_varg_from_psll (signed long long *psll)   { return (CWEB_VArg) { CWEB_VARG_TYPE_PSLL, .psll=psll }; }
CWEB_VArg cweb_varg_from_puc  (unsigned char *puc)         { return (CWEB_VArg) { CWEB_VARG_TYPE_PUC,  .puc=puc   }; }
CWEB_VArg cweb_varg_from_pus  (unsigned short *pus)        { return (CWEB_VArg) { CWEB_VARG_TYPE_PUS,  .pus=pus   }; }
CWEB_VArg cweb_varg_from_pui  (unsigned int *pui)          { return (CWEB_VArg) { CWEB_VARG_TYPE_PUI,  .pui=pui   }; }
CWEB_VArg cweb_varg_from_pul  (unsigned long *pul)         { return (CWEB_VArg) { CWEB_VARG_TYPE_PUL,  .pul=pul   }; }
CWEB_VArg cweb_varg_from_pull (unsigned long long *pull)   { return (CWEB_VArg) { CWEB_VARG_TYPE_PULL, .pull=pull }; }
CWEB_VArg cweb_varg_from_pf   (float *pf)         { return (CWEB_VArg) { CWEB_VARG_TYPE_PF,   .pf=pf     }; }
CWEB_VArg cweb_varg_from_pd   (double *pd)        { return (CWEB_VArg) { CWEB_VARG_TYPE_PD,   .pd=pd     }; }
CWEB_VArg cweb_varg_from_pb   (bool *pb)          { return (CWEB_VArg) { CWEB_VARG_TYPE_PB,   .pb=pb     }; }
CWEB_VArg cweb_varg_from_pstr (CWEB_String *pstr) { return (CWEB_VArg) { CWEB_VARG_TYPE_PSTR, .pstr=pstr }; }
CWEB_VArg cweb_varg_from_phash(CWEB_PasswordHash *phash) { return (CWEB_VArg) { CWEB_VARG_TYPE_PHASH, .phash=phash }; }

typedef struct {
    char *dst;
    int   cap;
    int   len;
} StaticOutputBuffer;

static void append_to_output(StaticOutputBuffer *out, char *src, int len)
{
    int unused = out->cap - out->len;
    if (unused > 0)
        memcpy(out->dst + out->len, src, MIN(len, unused));
    out->len += len;
}

static void append_to_output_u64(StaticOutputBuffer *out, uint64_t n)
{
    // TODO: test this function as it was vibecoded

    char buf[32]; // Enough for any 64-bit unsigned integer
    int len = 0;
    
    // Handle zero as special case
    if (n == 0) {
        buf[len++] = '0';
    } else {
        // Convert to decimal digits (in reverse order)
        char temp[32];
        int temp_len = 0;
        while (n > 0) {
            temp[temp_len++] = '0' + (n % 10);
            n /= 10;
        }
        // Reverse the digits
        for (int i = temp_len - 1; i >= 0; i--) {
            buf[len++] = temp[i];
        }
    }
    
    append_to_output(out, buf, len);
}

static void append_to_output_s64(StaticOutputBuffer *out, int64_t n)
{
    // TODO: test this function as it was vibecoded

    // Special case for INT64_MIN to avoid overflow when negating
    if (n == INT64_MIN) {
        append_to_output(out, "-9223372036854775808", 20);
        return;
    }
    
    char buf[32];
    int len = 0;
    
    // Handle negative sign
    if (n < 0) {
        buf[len++] = '-';
        n = -n;
    }
    
    // Convert absolute value
    if (n == 0) {
        buf[len++] = '0';
    } else {
        char temp[32];
        int temp_len = 0;
        while (n > 0) {
            temp[temp_len++] = '0' + (n % 10);
            n /= 10;
        }
        for (int i = temp_len - 1; i >= 0; i--) {
            buf[len++] = temp[i];
        }
    }
    
    append_to_output(out, buf, len);
}

static void append_to_output_f64(StaticOutputBuffer *out, double n)
{
    // TODO: test this function as it was vibecoded

    char buf[64];
    // Use %.17g for sufficient precision while avoiding trailing zeros
    int len = snprintf(buf, sizeof(buf), "%.17g", n);
    if (len > 0 && len < (int)sizeof(buf))
        append_to_output(out, buf, len);
}

static void append_to_output_ptr(StaticOutputBuffer *out, void *p)
{
    // TODO: test this function as it was vibecoded

    char buf[32];
    // Format pointer in hexadecimal (platform-dependent format)
    int len = snprintf(buf, sizeof(buf), "%p", p);
    if (len > 0 && len < (int)sizeof(buf))
        append_to_output(out, buf, len);
}

static void value_to_output(StaticOutputBuffer *out, CWEB_VArg arg)
{
    switch (arg.type) {
        case CWEB_VARG_TYPE_C    : append_to_output(out, &arg.c, 1);     break;
        case CWEB_VARG_TYPE_S    : append_to_output_s64(out, arg.s);     break;
        case CWEB_VARG_TYPE_I    : append_to_output_s64(out, arg.i);     break;
        case CWEB_VARG_TYPE_L    : append_to_output_s64(out, arg.l);     break;
        case CWEB_VARG_TYPE_LL   : append_to_output_s64(out, arg.ll);    break;
        case CWEB_VARG_TYPE_SC   : append_to_output_s64(out, arg.sc);    break;
        case CWEB_VARG_TYPE_SS   : append_to_output_s64(out, arg.ss);    break;
        case CWEB_VARG_TYPE_SI   : append_to_output_s64(out, arg.si);    break;
        case CWEB_VARG_TYPE_SL   : append_to_output_s64(out, arg.sl);    break;
        case CWEB_VARG_TYPE_SLL  : append_to_output_s64(out, arg.sll);   break;
        case CWEB_VARG_TYPE_UC   : append_to_output_u64(out, arg.uc);    break;
        case CWEB_VARG_TYPE_US   : append_to_output_u64(out, arg.us);    break;
        case CWEB_VARG_TYPE_UI   : append_to_output_u64(out, arg.ui);    break;
        case CWEB_VARG_TYPE_UL   : append_to_output_u64(out, arg.ul);    break;
        case CWEB_VARG_TYPE_ULL  : append_to_output_u64(out, arg.ull);   break;
        case CWEB_VARG_TYPE_F    : append_to_output_f64(out, arg.f);     break;
        case CWEB_VARG_TYPE_D    : append_to_output_f64(out, arg.d);     break;
        case CWEB_VARG_TYPE_B    : append_to_output(out, arg.b ? "true" : "false", arg.b ? 4: 5);break;
        case CWEB_VARG_TYPE_STR  : append_to_output(out, arg.str.ptr, arg.str.len); break;
        case CWEB_VARG_TYPE_HASH : append_to_output(out, arg.hash.data, strlen(arg.hash.data)); break;
        case CWEB_VARG_TYPE_PC   : append_to_output_ptr(out, arg.pc);    break;
        case CWEB_VARG_TYPE_PS   : append_to_output_ptr(out, arg.ps);    break;
        case CWEB_VARG_TYPE_PI   : append_to_output_ptr(out, arg.pi);    break;
        case CWEB_VARG_TYPE_PL   : append_to_output_ptr(out, arg.pl);    break;
        case CWEB_VARG_TYPE_PLL  : append_to_output_ptr(out, arg.pll);   break;
        case CWEB_VARG_TYPE_PSC  : append_to_output_ptr(out, arg.psc);   break;
        case CWEB_VARG_TYPE_PSS  : append_to_output_ptr(out, arg.pss);   break;
        case CWEB_VARG_TYPE_PSI  : append_to_output_ptr(out, arg.psi);   break;
        case CWEB_VARG_TYPE_PSL  : append_to_output_ptr(out, arg.psl);   break;
        case CWEB_VARG_TYPE_PSLL : append_to_output_ptr(out, arg.psll);  break;
        case CWEB_VARG_TYPE_PUC  : append_to_output_ptr(out, arg.puc);   break;
        case CWEB_VARG_TYPE_PUS  : append_to_output_ptr(out, arg.pus);   break;
        case CWEB_VARG_TYPE_PUI  : append_to_output_ptr(out, arg.pui);   break;
        case CWEB_VARG_TYPE_PUL  : append_to_output_ptr(out, arg.pul);   break;
        case CWEB_VARG_TYPE_PULL : append_to_output_ptr(out, arg.pull);  break;
        case CWEB_VARG_TYPE_PF   : append_to_output_ptr(out, arg.pf);    break;
        case CWEB_VARG_TYPE_PD   : append_to_output_ptr(out, arg.pd);    break;
        case CWEB_VARG_TYPE_PB   : append_to_output_ptr(out, arg.pb);    break;
        case CWEB_VARG_TYPE_PSTR : append_to_output_ptr(out, arg.pstr);  break;
        case CWEB_VARG_TYPE_PHASH: append_to_output_ptr(out, arg.phash); break;
    }
}

/////////////////////////////////////////////////////////////////
// FILE SYSTEM
////////////////////////////////////////////////////////////////

typedef struct LoadedFile LoadedFile;
struct LoadedFile {
    LoadedFile* next;
    int         len;
    char        data[];
};

static LoadedFile *load_file(CWEB_String path)
{
    char buf[1<<10];
    if (path.len >= (int) sizeof(buf))
        return NULL;
    memcpy(buf, path.ptr, path.len);
    buf[path.len] = '\0';

    FILE *stream = fopen(buf, "rb");
    if (stream == NULL)
        return NULL;

    int ret = fseek(stream, 0, SEEK_END);
    if (ret) {
        fclose(stream);
        return NULL;
    }

    long tmp = ftell(stream);
    if (tmp < 0 || tmp > INT_MAX) {
        fclose(stream);
        return NULL;
    }
    int len = (int) tmp;

    ret = fseek(stream, 0, SEEK_SET);
    if (ret) {
        fclose(stream);
        return NULL;
    }

    LoadedFile *result = malloc(sizeof(LoadedFile) + len + 1);
    if (result == NULL) {
        fclose(stream);
        return NULL;
    }
    result->next = NULL;
    result->len  = len;

    int read_len = fread(result->data, 1, len+1, stream);
    if (read_len != len || ferror(stream) || !feof(stream)) {
        fclose(stream);
        free(result);
        return NULL;
    }

    result->data[len] = '\0';

    fclose(stream);
    return result;
}

static void free_loaded_files(LoadedFile *loaded_file)
{
    while (loaded_file) {
        LoadedFile *next = loaded_file->next;
        free(loaded_file);
        loaded_file = next;
    }
}

////////////////////////////////////////////////////////////////
// RANDOM
////////////////////////////////////////////////////////////////

static int generate_random_bytes(char *dst, int cap)
{
#ifdef __linux__
    int copied = 0;
    while (copied < cap) {
        int ret = getrandom(dst, (size_t) cap, 0);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        copied += ret;
    }
    return 0;
#endif

#ifdef _WIN32
    NTSTATUS status = BCryptGenRandom(NULL, (unsigned char*) dst, (ULONG) cap, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return BCRYPT_SUCCESS(status) ? 0 : -1;
#endif
}

////////////////////////////////////////////////////////////////
// PASSWORD
////////////////////////////////////////////////////////////////

int cweb_hash_password(CWEB_String pass, int cost, CWEB_PasswordHash *hash)
{
    char passzt[128];
    if (pass.len >= (int) sizeof(passzt))
        return -1;
    memcpy(passzt, pass.ptr, pass.len);
    passzt[pass.len] = '\0';

    char random[16];
    int ret = generate_random_bytes(random, (int) sizeof(random));
    if (ret) return -1;

    char salt[30];
    if (_crypt_gensalt_blowfish_rn("$2b$", cost, random, sizeof(random), salt, sizeof(salt)) == NULL)
        return -1;

    if (_crypt_blowfish_rn(passzt, salt, hash->data, (int) sizeof(hash->data)) == NULL)
        return -1;

    return 0;
}

int cweb_check_password(CWEB_String pass, CWEB_PasswordHash hash)
{
    char passzt[128];
    if (pass.len >= (int) sizeof(passzt)) {
        CWEB_TRACE("%s: static buffer limit reached", __func__);
        return -1;
    }
    memcpy(passzt, pass.ptr, pass.len);
    passzt[pass.len] = '\0';

    CWEB_PasswordHash new_hash;
    if (_crypt_blowfish_rn(passzt, hash.data, new_hash.data, sizeof(new_hash.data)) == NULL) {
        CWEB_TRACE("%s: couldn't calculate hash (password=[%.*s], hash=[%.*s])", __func__, pass.len, pass.ptr, (int) strnlen(hash.data, sizeof(hash.data)), hash.data);
        return -1;
    }

    if (strcmp(hash.data, new_hash.data)) // TODO: should be constant-time
        return 1;

    return 0;
}

/////////////////////////////////////////////////////////////////
// SESSION
////////////////////////////////////////////////////////////////

#define CSRF_RAW_TOKEN_SIZE 32
#define SESS_RAW_TOKEN_SIZE 32

#define CSRF_TOKEN_SIZE (2 * CSRF_RAW_TOKEN_SIZE)
#define SESS_TOKEN_SIZE (2 * SESS_RAW_TOKEN_SIZE)

typedef struct {
    int  user;
    char csrf[CSRF_TOKEN_SIZE];
    char sess[SESS_TOKEN_SIZE];
} Session;

struct SessionStorage {
    int count;
    int capacity;
    Session items[];
};

#ifndef CWEB_AMALGAMATION

static bool is_hex_digit(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
}

static int hex_digit_to_int(char c)
{
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    return c - '0';
}

#endif

static void unpack_token(char *src, int srclen, char *dst, int dstlen)
{
    ASSERT(2 * srclen == dstlen);

    for (int i = 0; i < srclen; i++) {
        static const char table[] = "0123456789abcdef";
        int low  = (src[i] & 0x0F) >> 0;
        int high = (src[i] & 0xF0) >> 4;
        dst[(i << 1) | 0] = table[high];
        dst[(i << 1) | 1] = table[low];
    }
}

static int pack_token(char *src, int srclen, char *dst, int dstlen)
{
    if (srclen & 1)
        return -1;

    ASSERT(srclen == 2 * dstlen);

    for (int i = 0; i < srclen; i += 2) {
        int high = src[i+0];
        int low  = src[i+1];
        if (!is_hex_digit(high) || !is_hex_digit(low))
            return -1;
        dst[i >> 1] = (hex_digit_to_int(high) << 4) | (hex_digit_to_int(low) << 0);
    }

    return 0;
}

static SessionStorage *session_storage_init(int max_sessions)
{
    int capacity = 2 * max_sessions;
    SessionStorage *storage = malloc(sizeof(SessionStorage) + capacity * sizeof(Session));
    if (storage == NULL)
        return NULL;
    storage->count = 0;
    storage->capacity = capacity;
    for (int i = 0; i < capacity; i++)
        storage->items[i].user = -1;
    return storage;
}

static void session_storage_free(SessionStorage *storage)
{
    free(storage);
}

static Session *lookup_session_slot(SessionStorage *storage, CWEB_String sess, bool find_unused)
{
    if (find_unused && 2 * storage->count + 2 > storage->capacity)
        return NULL;

    if (sess.len != SESS_TOKEN_SIZE)
        return NULL;

    uint64_t key = 0;
    if (sess.len < (int) (2 * sizeof(key)))
        return NULL;
    for (int i = 0; i < (int) sizeof(key); i++) {

        int high = sess.ptr[(i << 1) | 0];
        int low  = sess.ptr[(i << 1) | 1];

        if (!is_hex_digit(high) ||
            !is_hex_digit(low))
            return NULL;

        key <<= 4;
        key |= hex_digit_to_int(high);

        key <<= 4;
        key |= hex_digit_to_int(low);
    }
    int i = key % storage->capacity;

    for (int j = 0; j < storage->capacity; j++) {

        if (find_unused) {

            if (storage->items[i].user < 0)
                return &storage->items[i]; // Unused slot

        } else {

            if (storage->items[i].user == -1)
                return NULL;

            if (storage->items[i].user != -2)
                if (!memcmp(storage->items[i].sess, sess.ptr, SESS_TOKEN_SIZE))
                    return &storage->items[i];
        }

        i++;
        if (i == storage->capacity)
            i = 0;
    }

    return NULL;
}

static int create_session(SessionStorage *storage, int user, CWEB_String *psess, CWEB_String *pcsrf)
{
    int ret;
    char raw_sess[SESS_RAW_TOKEN_SIZE];
    char raw_csrf[CSRF_RAW_TOKEN_SIZE];

    ret = generate_random_bytes(raw_sess, SESS_RAW_TOKEN_SIZE);
    if (ret) return -1;

    ret = generate_random_bytes(raw_csrf, CSRF_RAW_TOKEN_SIZE);
    if (ret) return -1;

    char sess[SESS_TOKEN_SIZE];
    char csrf[CSRF_TOKEN_SIZE];
    unpack_token(raw_sess, SESS_RAW_TOKEN_SIZE, sess, SESS_TOKEN_SIZE);
    unpack_token(raw_csrf, CSRF_RAW_TOKEN_SIZE, csrf, CSRF_TOKEN_SIZE);

    Session *found = lookup_session_slot(storage, (CWEB_String) { sess, SESS_TOKEN_SIZE }, true);
    if (found == NULL) return -1;

    found->user = user;
    memcpy(found->sess, sess, SESS_TOKEN_SIZE);
    memcpy(found->csrf, csrf, CSRF_TOKEN_SIZE);

    *psess = (CWEB_String) { found->sess, SESS_TOKEN_SIZE };
    *pcsrf = (CWEB_String) { found->csrf, CSRF_TOKEN_SIZE };

    storage->count++;
    return 0;
}

static int delete_session(SessionStorage *storage, CWEB_String sess)
{
    char raw_sess[SESS_RAW_TOKEN_SIZE];
    if (sess.len != SESS_TOKEN_SIZE || pack_token(sess.ptr, sess.len, raw_sess, (int) sizeof(raw_sess)) < 0)
        return -1;
    Session *found = lookup_session_slot(storage, sess, false);
    if (found == NULL)
        return -1;
    ASSERT(found->user >= 0);
    found->user = -2;
    storage->count--;
    return 0;
}

static int find_session(SessionStorage *storage, CWEB_String sess, CWEB_String *pcsrf, int *puser)
{
    Session *found = lookup_session_slot(storage, sess, false);
    if (found == NULL)
        return -1;
    ASSERT(found->user >= 0);
    *pcsrf = (CWEB_String) { found->csrf, CSRF_TOKEN_SIZE };
    *puser = found->user;
    return 0;
}

/////////////////////////////////////////////////////////////////
// DATABASE
////////////////////////////////////////////////////////////////

#ifdef CWEB_ENABLE_DATABASE

typedef struct {
    char *str;
    int   len;
    sqlite3_stmt *stmt;
} Prepped;

struct SQLiteCache {
    sqlite3 *db;
    int count;
    int capacity_log2;
    Prepped items[];
};

static SQLiteCache *sqlite_cache_init(sqlite3 *db, int capacity_log2)
{
    SQLiteCache *cache = malloc(sizeof(SQLiteCache) + (1 << capacity_log2) * sizeof(Prepped));
    if (cache == NULL)
        return NULL;

    cache->db = db;
    cache->count = 0;
    cache->capacity_log2 = capacity_log2;

    for (int i = 0; i < (1 << capacity_log2); i++)
        cache->items[i].stmt = NULL;

    return cache;
}

static void sqlite_cache_free(SQLiteCache *cache)
{
    for (int i = 0; i < (1 << cache->capacity_log2); i++) {
        sqlite3_stmt *stmt = cache->items[i].stmt;
        if (stmt) {
            free(cache->items[i].str);
            sqlite3_finalize(stmt);
        }
    }
    free(cache);
}

static unsigned long djb2(char *src, int len)
{
    char *ptr = src;
    char *end = src + len;

    unsigned long hash = 5381;
    int c;
    while (ptr < end && (c = *ptr++))
        hash = ((hash << 5) + hash) + c; // hash * 33 + c
    return hash;
}

static int sqlite_cache_lookup(SQLiteCache *cache, char *fmt, int fmtlen)
{
    int mask = (1 << cache->capacity_log2) - 1;
    int hash = djb2(fmt, fmtlen);
    int i = hash & mask;
    int perturb = hash;
    for (;;) {

        if (cache->items[i].stmt == NULL)
            return i;

        if (cache->items[i].len == fmtlen && !memcmp(cache->items[i].str, fmt, fmtlen))
            return i;

        perturb >>= 5;
        i = (i * 5 + 1 + perturb) & mask;
    }

    return -1;
}

static int sqlite3utils_prepare(SQLiteCache *cache, sqlite3_stmt **pstmt, char *fmt, int fmtlen)
{
    if (fmtlen < 0)
        fmtlen = strlen(fmt);

    int i = sqlite_cache_lookup(cache, fmt, fmtlen);
    if (cache->items[i].stmt == NULL) {

        sqlite3_stmt *stmt;
        int ret = sqlite3_prepare_v2(cache->db, fmt, fmtlen, &stmt, NULL);
        if (ret != SQLITE_OK) {
            fprintf(stderr, "Failed to prepare statement: %s (%s:%d)\n", sqlite3_errmsg(cache->db), __FILE__, __LINE__); // TODO
            return ret;
        }

        char *cpy = malloc(fmtlen);
        if (cpy == NULL) {
            sqlite3_finalize(stmt);
            return SQLITE_NOMEM;
        }
        memcpy(cpy, fmt, fmtlen);

        cache->items[i].str = cpy;
        cache->items[i].len = fmtlen;
        cache->items[i].stmt = stmt;
    }

    sqlite3_stmt *stmt = cache->items[i].stmt;

    *pstmt = stmt;
    return SQLITE_OK;
}

static int sqlite3utils_prepare_and_bind_impl(SQLiteCache *cache,
    sqlite3_stmt **pstmt, char *fmt, CWEB_VArgs args)
{
    sqlite3_stmt *stmt;
    int ret = sqlite3utils_prepare(cache, &stmt, fmt, strlen(fmt));
    if (ret != SQLITE_OK)
        return ret;

    for (int i = 0; i < args.len; i++) {
        CWEB_VArg arg = args.ptr[i];
        switch (arg.type) {
            case CWEB_VARG_TYPE_C   : ret = sqlite3_bind_text  (stmt, i+1, &arg.c, 1, NULL); break;
            case CWEB_VARG_TYPE_S   : ret = sqlite3_bind_int   (stmt, i+1, arg.s);   break;
            case CWEB_VARG_TYPE_I   : ret = sqlite3_bind_int   (stmt, i+1, arg.i);   break;
            case CWEB_VARG_TYPE_L   : ret = sqlite3_bind_int64 (stmt, i+1, arg.l);   break;
            case CWEB_VARG_TYPE_LL  : ret = sqlite3_bind_int64 (stmt, i+1, arg.ll);  break;
            case CWEB_VARG_TYPE_SC  : ret = sqlite3_bind_int   (stmt, i+1, arg.sc);  break;
            case CWEB_VARG_TYPE_SS  : ret = sqlite3_bind_int   (stmt, i+1, arg.ss);  break;
            case CWEB_VARG_TYPE_SI  : ret = sqlite3_bind_int   (stmt, i+1, arg.si);  break;
            case CWEB_VARG_TYPE_SL  : ret = sqlite3_bind_int64 (stmt, i+1, arg.sl);  break;
            case CWEB_VARG_TYPE_SLL : ret = sqlite3_bind_int64 (stmt, i+1, arg.sll); break;
            case CWEB_VARG_TYPE_UC  : ret = sqlite3_bind_int   (stmt, i+1, arg.uc);  break;
            case CWEB_VARG_TYPE_US  : ret = sqlite3_bind_int   (stmt, i+1, arg.us);  break;
            case CWEB_VARG_TYPE_UI  : ret = sqlite3_bind_int64 (stmt, i+1, arg.ui);  break;
            case CWEB_VARG_TYPE_UL  : ret = sqlite3_bind_int64 (stmt, i+1, arg.ul);  break;
            case CWEB_VARG_TYPE_ULL : ret = sqlite3_bind_int64 (stmt, i+1, arg.ull); break; // TODO: overflow?
            case CWEB_VARG_TYPE_F   : ret = sqlite3_bind_double(stmt, i+1, arg.f);   break;
            case CWEB_VARG_TYPE_D   : ret = sqlite3_bind_double(stmt, i+1, arg.d);   break;
            case CWEB_VARG_TYPE_B   : ret = sqlite3_bind_int   (stmt, i+1, arg.b);   break;
            case CWEB_VARG_TYPE_STR : ret = sqlite3_bind_text  (stmt, i+1, arg.str.ptr, arg.str.len, NULL); break;
            case CWEB_VARG_TYPE_HASH: ret = sqlite3_bind_text  (stmt, i+1, arg.hash.data, strlen(arg.hash.data), SQLITE_TRANSIENT); break;

            default:
            ASSERT(0); // TODO
            break;
        }
        if (ret != SQLITE_OK) {
            fprintf(stderr, "Failed to bind paremeter: %s (%s:%d)\n", sqlite3_errmsg(cache->db), __FILE__, __LINE__); // TODO
            sqlite3_reset(stmt);
            return ret;
        }
    }

    *pstmt = stmt;
    return SQLITE_OK;
}

#endif // CWEB_ENABLE_DATABASE

static void dump_sql(char *fmt, CWEB_VArgs args)
{
    printf("SQL :: %s", fmt);
    if (args.len > 0) {
        printf(" (");
        for (int i = 0; i < args.len; i++) {
            char mem[128];
            StaticOutputBuffer buf = { mem, sizeof(mem), 0 };
            value_to_output(&buf, args.ptr[i]);
            printf("%.*s", buf.len, buf.dst);
            if (i+1 < args.len)
                printf(", ");
        }
        printf(")");
    }
    printf("\n");
}

int64_t cweb_database_insert_impl(CWEB *cweb, char *fmt, CWEB_VArgs args)
{
#ifdef CWEB_ENABLE_DATABASE
    if (cweb->trace_sql) dump_sql(fmt, args);

    sqlite3_stmt *stmt;
    int ret = sqlite3utils_prepare_and_bind_impl(cweb->dbcache, &stmt, fmt, args);
    if (ret != SQLITE_OK) {
        fprintf(stderr, "sqlite3 prepare+bind error: %s (%s:%d)\n", sqlite3_errmsg(cweb->db), __FILE__, __LINE__); // TODO
        return -1;
    }

    ret = sqlite3_step(stmt);
    if (ret != SQLITE_DONE) {
        fprintf(stderr, "sqlite3_step error: %s (%s:%d)\n", sqlite3_errmsg(cweb->db), __FILE__, __LINE__); // TODO
        sqlite3_reset(stmt);
        return -1;
    }

    int64_t insert_id = sqlite3_last_insert_rowid(cweb->db);
    if (insert_id < 0) {
        fprintf(stderr, "Insert ID is invalid: %s (%s:%d)\n", sqlite3_errmsg(cweb->db), __FILE__, __LINE__); // TODO
        sqlite3_reset(stmt);
        return -1;
    }

    sqlite3_reset(stmt);
    return insert_id;
#else
    return -1;
#endif
}

CWEB_QueryResult cweb_database_select_impl(CWEB *cweb, char *fmt, CWEB_VArgs args)
{
#ifdef CWEB_ENABLE_DATABASE
    if (cweb->trace_sql) dump_sql(fmt, args);

    sqlite3_stmt *stmt;
    int ret = sqlite3utils_prepare_and_bind_impl(cweb->dbcache, &stmt, fmt, args);
    if (ret != SQLITE_OK) {
        fprintf(stderr, "sqlite3 prepare+bind error: %s (%s:%d)\n", sqlite3_errmsg(cweb->db), __FILE__, __LINE__); // TODO
        return (CWEB_QueryResult) { NULL };
    }

    return (CWEB_QueryResult) { stmt };
#else
    return (CWEB_QueryResult) { NULL };
#endif
}

int cweb_next_query_row_impl(CWEB_QueryResult *res, CWEB_VArgs args)
{
#ifdef CWEB_ENABLE_DATABASE
    if (res->handle == NULL) {
        CWEB_TRACE("%s failed because database is initialized", __func__);
        return -1;
    }

    int ret = sqlite3_step(res->handle);

    if (ret == SQLITE_DONE) {
        CWEB_TRACE("%s returned no row", __func__);
        return 0;
    }

    if (ret != SQLITE_ROW) {
        CWEB_TRACE("%s didn't return ROW or DONE (%d)", __func__, ret);
        sqlite3_reset(res->handle);
        res->handle = NULL;
        return -1;
    }

    if (sqlite3_column_count(res->handle) != args.len) {
        CWEB_TRACE("%s returned an unexpected column count", __func__);
        sqlite3_reset(res->handle);
        res->handle = NULL;
        return -1;
    }

    for (int i = 0; i < args.len; i++) {
        switch (args.ptr[i].type) {

            case CWEB_VARG_TYPE_PI:
            {
                int64_t x = sqlite3_column_int64(res->handle, i);
                if (x < INT_MIN || x > INT_MAX) {
                    CWEB_TRACE("%s couldn't bind integer out of range", __func__);
                    sqlite3_reset(res->handle);
                    res->handle = NULL;
                    return -1;
                }
                *args.ptr[i].pi = (int) x;
            }
            break;

            case CWEB_VARG_TYPE_PL:
            {
                int64_t x = sqlite3_column_int64(res->handle, i);
                if (x < LONG_MIN || x > LONG_MAX) {
                    CWEB_TRACE("%s couldn't bind integer out of range", __func__);
                    sqlite3_reset(res->handle);
                    res->handle = NULL;
                    return -1;
                }
                *args.ptr[i].pl = (long) x;
            }
            break;

            case CWEB_VARG_TYPE_PLL:
            {
                int64_t x = sqlite3_column_int64(res->handle, i);
                *args.ptr[i].pll = x;
            }
            break;

            case CWEB_VARG_TYPE_PF:
            {
                double x = sqlite3_column_double(res->handle, i);
                *args.ptr[i].pf = (float) x;
            }
            break;

            case CWEB_VARG_TYPE_PD:
            {
                double x = sqlite3_column_double(res->handle, i);
                *args.ptr[i].pd = x;
            }
            break;

            case CWEB_VARG_TYPE_PSTR:
            {
                *args.ptr[i].pstr = (CWEB_String) {
                    sqlite3_column_text(res->handle, i),
                    sqlite3_column_bytes(res->handle, i),
                };
            }
            break;

            case CWEB_VARG_TYPE_PHASH:
            {
                if (sqlite3_column_type(res->handle, i) != SQLITE_TEXT) {
                    CWEB_TRACE("%s couldn't bind to hash argument due to the column not being a string", __func__);
                    sqlite3_reset(res->handle);
                    res->handle = NULL;
                    return -1;
                }

                char *ptr = sqlite3_column_text(res->handle, i);
                int   len = sqlite3_column_bytes(res->handle, i);

                CWEB_TRACE("%s: hash value (\"%.*s\", %d)", __func__, len, ptr, len);

                CWEB_PasswordHash *hash = args.ptr[i].phash;
                if ((int) sizeof(hash->data) <= len) {
                    CWEB_TRACE("%s couldn't bind to hash argument", __func__);
                    sqlite3_reset(res->handle);
                    res->handle = NULL;
                    return -1;
                }
                memset(hash->data, 0, sizeof(hash->data));
                memcpy(hash->data, ptr, len);
            }
            break;

            default:
            CWEB_TRACE("%s couldn't bind to unexpected argument type %s", __func__, type_names__[args.ptr[i].type]);
            sqlite3_reset(res->handle);
            res->handle = NULL;
            return -1;
        }
    }

    return 1;
#else
    (void) res;
    (void) args;
    CWEB_TRACE("%s is unsupported", __func__);
    return -1;
#endif
}

void cweb_free_query_result(CWEB_QueryResult *res)
{
#ifdef CWEB_ENABLE_DATABASE
    if (res->handle) {
        sqlite3_reset(res->handle);
        res->handle = NULL;
    }
#else
    (void) res;
#endif
}

int cweb_global_init(void)
{
    if (http_global_init())
        return -1;
    return 0;
}

void cweb_global_free(void)
{
    http_global_free();
    crash_logger_free();
}

CWEB *cweb_init(CWEB_String addr, uint16_t port, uint16_t secure_port,
    CWEB_String cert_key, CWEB_String private_key)
{
    CWEB *cweb = malloc(sizeof(CWEB));
    if (cweb == NULL)
        return NULL;

    cweb->pool_cap = 1<<20;
    cweb->pool = malloc(cweb->pool_cap);
    if (cweb->pool == NULL) {
        free(cweb);
        return NULL;
    }

#ifdef CWEB_ENABLE_TEMPLATE
    cweb->tpcache = template_cache_init(4);
    if (cweb->tpcache == NULL) {
        free(cweb->pool);
        free(cweb);
        return NULL;
    }
    cweb->enable_template_cache = true;
#endif

    cweb->session_storage = session_storage_init(1024);
    if (cweb->session_storage == NULL) {
#ifdef CWEB_ENABLE_TEMPLATE
        template_cache_free(cweb->tpcache);
#endif
        free(cweb->pool);
        free(cweb);
        return NULL;
    }

    cweb->server = http_server_init_ex((HTTP_String) { addr.ptr, addr.len }, port, secure_port, (HTTP_String) { cert_key.ptr, cert_key.len }, (HTTP_String) { private_key.ptr, private_key.len });
    if (cweb->server == NULL) {
        session_storage_free(cweb->session_storage);
#ifdef CWEB_ENABLE_TEMPLATE
        template_cache_free(cweb->tpcache);
#endif
        free(cweb->pool);
        free(cweb);
        return NULL;
    }
    cweb->port = port;
    cweb->secure_port = secure_port;

#ifdef CWEB_ENABLE_DATABASE
    cweb->db = NULL;
    cweb->dbcache = NULL;
    cweb->trace_sql = false;
#endif

    // If set, allows logins and signups over HTTP, which is highly insecure.
    // This allows compiling the application without TLS when developing.
    cweb->allow_insecure_login = true;

    if (cweb->allow_insecure_login)
        printf("WARNING: allow_insecure_login is true\n");

    return cweb;
}

void cweb_free(CWEB *cweb)
{
    http_server_free(cweb->server);
    session_storage_free(cweb->session_storage);
#ifdef CWEB_ENABLE_TEMPLATE
    template_cache_free(cweb->tpcache);
#endif
#ifdef CWEB_ENABLE_DATABASE
    if (cweb->db) {
        sqlite_cache_free(cweb->dbcache);
        sqlite3_close(cweb->db);
    }
#endif
    free(cweb);
}

int cweb_add_website(CWEB *cweb, CWEB_String domain, CWEB_String cert_file, CWEB_String key_file)
{
    return http_server_add_website(cweb->server,
        (HTTP_String) { domain.ptr,    domain.len },
        (HTTP_String) { cert_file.ptr, cert_file.len },
        (HTTP_String) { key_file.ptr,  key_file.len }
    );
}

int cweb_create_test_certificate(CWEB_String C, CWEB_String O,
    CWEB_String CN, CWEB_String cert_file, CWEB_String key_file)
{
    return http_create_test_certificate(
        (HTTP_String) { C.ptr, C.len },
        (HTTP_String) { O.ptr, O.len },
        (HTTP_String) { CN.ptr, CN.len },
        (HTTP_String) { cert_file.ptr, cert_file.len },
        (HTTP_String) { key_file.ptr, key_file.len }
    );
}

void cweb_version(void)
{
    printf("%s\n", sqlite3_libversion());
}

void cweb_trace_sql(CWEB *cweb, bool enable)
{
#ifdef CWEB_ENABLE_DATABASE
    cweb->trace_sql = enable;
#endif
}

void cweb_enable_template_cache(CWEB *cweb, bool enable)
{
    cweb->enable_template_cache = enable;
}

int cweb_enable_database(CWEB *cweb, CWEB_String database_file, CWEB_String schema_file)
{
#ifdef CWEB_ENABLE_DATABASE
    if (cweb->db != NULL)
        return -1; // Already enabled

    char file_copy[1<<12];
    if (database_file.len >= SIZEOF(file_copy))
        return -1;
    memcpy(file_copy, database_file.ptr, database_file.len);
    file_copy[database_file.len] = '\0';

    int ret = sqlite3_open(file_copy, &cweb->db);
    if (ret != SQLITE_OK) {
        sqlite3_close(cweb->db);
        cweb->db = NULL;
        return -1;
    }

    ret = sqlite3_exec(cweb->db, "PRAGMA foreign_keys = ON;", NULL, NULL, NULL);
    if (ret != SQLITE_OK) {
        sqlite3_close(cweb->db);
        cweb->db = NULL;
        return -1;
    }

    LoadedFile *schema = load_file(schema_file);
    if (schema == NULL) {
        sqlite3_close(cweb->db);
        cweb->db = NULL;
        return -1;
    }

    ret = sqlite3_exec(cweb->db, schema->data, NULL, NULL, NULL);
    if (ret != SQLITE_OK) {
        free_loaded_files(schema);
        sqlite3_close(cweb->db);
        cweb->db = NULL;
        return -1;
    }

    free_loaded_files(schema);

    cweb->dbcache = sqlite_cache_init(cweb->db, 5);
    if (cweb->dbcache == NULL) {
        sqlite3_close(cweb->db);
        cweb->db = NULL;
        return -1;
    }

    return 0;
#else
    return -1;
#endif
}

void cweb_enable_crash_logger(CWEB_String file)
{
    if (crash_logger_init(file.ptr, file.len) < 0)
        printf("WARNING: Failed to set up crash logger\n");
}

CWEB_Request *cweb_wait(CWEB *cweb)
{
    CWEB_Request *req = &cweb->req;

    int ret = http_server_wait(cweb->server, &req->req, &req->builder);
    if (ret) return NULL; // Error or signal

    HTTP_String session_token = http_get_cookie(req->req, HTTP_STR("sess_token"));

    req->cweb = cweb;
    req->arena = (WL_Arena) { cweb->pool, cweb->pool_cap, 0 };
    req->just_created_session = false;
    req->sess = (CWEB_String) { session_token.ptr, session_token.len };

    if (find_session(cweb->session_storage, req->sess, &req->csrf, &req->user_id) < 0) {
        req->user_id = -1;
        req->sess = (CWEB_String) { NULL, 0 };
        req->csrf = (CWEB_String) { NULL, 0 };
    }

    return req;
}

bool cweb_match_domain(CWEB_Request *req, CWEB_String str)
{
    uint16_t port        = req->cweb->port;
    uint16_t secure_port = req->cweb->secure_port;

    HTTP_String str2 = { str.ptr, str.len };

    if (port > 0
        && http_match_host(req->req, str2, port))
        return true;

    if (secure_port > 0
        && http_match_host(req->req, str2, secure_port))
        return true;

    return false;
}

bool cweb_match_endpoint(CWEB_Request *req, CWEB_String str)
{
    return http_streq(req->req->url.path, (HTTP_String) { str.ptr, str.len });
}

CWEB_String cweb_get_path(CWEB_Request *req)
{
    HTTP_String path = req->req->url.path;
    return (CWEB_String) { path.ptr, path.len };
}

CWEB_String cweb_get_param_s(CWEB_Request *req, CWEB_String name)
{
    HTTP_String src = req->req->url.query;
    if (req->req->method == HTTP_METHOD_POST)
        src = req->req->body;

    HTTP_String res = http_get_param(src,
        (HTTP_String) { name.ptr, name.len },
        req->arena.ptr + req->arena.cur,
        req->arena.len - req->arena.cur
    );
    if (res.ptr >= req->arena.ptr && res.ptr < req->arena.ptr + req->arena.len)
        req->arena.cur += res.len;
    return (CWEB_String) { res.ptr, res.len };
}

int cweb_get_param_i(CWEB_Request *req, CWEB_String name)
{
    HTTP_String src = req->req->url.query;
    if (req->req->method == HTTP_METHOD_POST)
        src = req->req->body;

    return http_get_param_i(src, (HTTP_String) { name.ptr, name.len });
}

static int set_auth_cookie_if_necessary(CWEB_Request *req)
{
    if (req->just_created_session) {
        char cookie[1<<9];
        int cookie_len = snprintf(cookie, sizeof(cookie), "Set-Cookie: sess_token=%.*s; Path=/; HttpOnly%s", req->sess.len, req->sess.ptr, req->cweb->allow_insecure_login ? "" : "; Secure");
        if (cookie_len < 0 || cookie_len >= (int) sizeof(cookie))
            return -500;
        http_response_builder_header(req->builder, (HTTP_String) { cookie, cookie_len });
    }
    return 0;
}

void cweb_respond_basic(CWEB_Request *req, int status, CWEB_String content)
{
    http_response_builder_status(req->builder, status);
    int ret = set_auth_cookie_if_necessary(req);
    if (ret < 0) {
        http_response_builder_undo(req->builder);
        http_response_builder_status(req->builder, -ret);
        http_response_builder_done(req->builder);
        return;
    }
    http_response_builder_body(req->builder, (HTTP_String) { content.ptr, content.len });
    http_response_builder_done(req->builder);
}

static void evaluate_format(StaticOutputBuffer *out, CWEB_String format, CWEB_VArgs args)
{
    char *src = format.ptr;
    int   len = format.len;
    int   cur = 0;
    int   arg_idx = 0;

    for (;;) {

        int off = cur;
        while (cur < len && src[cur] != '{' && src[cur] != '\\')
            cur++;

        if (cur > off)
            append_to_output(out, src + off, cur - off);

        if (cur == len)
            break;
        cur++;

        if (src[cur-1] == '{') {

            while (cur < len && src[cur] != '}')
                cur++;

            if (cur < len) {
                ASSERT(src[cur] == '}');
                cur++;
            }

            if (arg_idx < args.len) {
                value_to_output(out, args.ptr[arg_idx]);
                arg_idx++;
            }

        } else {
            ASSERT(src[cur-1] == '\\');
            if (cur < len) {
                append_to_output(out, &src[cur], 1);
                cur++;
            }
        }
    }
}

CWEB_String cweb_format_impl(CWEB_Request *req, char *fmt, CWEB_VArgs args)
{
    StaticOutputBuffer out = { 
        .dst = req->arena.ptr + req->arena.cur,
        .cap = req->arena.len - req->arena.cur,
        .len = 0
    };
    evaluate_format(&out, (CWEB_String) { fmt, strlen(fmt) }, args);
    if (out.len > req->arena.len - req->arena.cur)
        return (CWEB_String) { NULL, 0 };
    req->arena.cur += out.len;
    return (CWEB_String) { out.dst, out.len };
}

void cweb_respond_redirect(CWEB_Request *req, CWEB_String target)
{
    CWEB_String location_header = cweb_format(req, "Location: {}", target);
    if (location_header.len == 0) {
        http_response_builder_status(req->builder, 500);
        http_response_builder_done(req->builder);
        return;
    }

    http_response_builder_status(req->builder, 303);
    int ret = set_auth_cookie_if_necessary(req);
    if (ret < 0) {
        http_response_builder_undo(req->builder);
        http_response_builder_status(req->builder, -ret);
        http_response_builder_done(req->builder);
        return;
    }
    http_response_builder_header(req->builder, (HTTP_String) { location_header.ptr, location_header.len });
    http_response_builder_done(req->builder);
}

int cweb_set_user_id(CWEB_Request *req, int user_id)
{
    if (user_id != req->user_id) {

        if (!req->req->secure && !req->cweb->allow_insecure_login)
            return -1;

        int ret;
        if (user_id == -1) ret = delete_session(req->cweb->session_storage, req->sess);
        else               ret = create_session(req->cweb->session_storage, user_id, &req->sess, &req->csrf);

        if (ret < 0) return -1;

        req->just_created_session = true;
    }

    return 0;
}

int cweb_get_user_id(CWEB_Request *req)
{
    return req->user_id;
}

CWEB_String cweb_get_csrf(CWEB_Request *req)
{
    return req->csrf;
}

////////////////////////////////////////////////////////////////
// TEMPLATE
////////////////////////////////////////////////////////////////
#ifdef CWEB_ENABLE_TEMPLATE

static TemplateCache *template_cache_init(int capacity_log2)
{
    TemplateCache *cache = malloc(sizeof(TemplateCache) + (1 << capacity_log2) * sizeof(CachedProgram));
    if (cache == NULL)
        return NULL;

    cache->count = 0;
    cache->capacity_log2 = capacity_log2;

    for (int i = 0; i < (1 << capacity_log2); i++)
        cache->pool[i].pathlen = -1;
    return cache;
}

static void template_cache_free(TemplateCache *cache)
{
    free(cache);
}

static int template_cache_lookup(TemplateCache *cache, WL_String path)
{
    int mask = (1 << cache->capacity_log2) - 1;
    int hash = djb2(path.ptr, path.len);
    int i = hash & mask;
    int perturb = hash;
    for (;;) {

        if (cache->pool[i].pathlen == -1)
            return i;

        if (wl_streq(path, cache->pool[i].path, cache->pool[i].pathlen))
            return i;

        perturb >>= 5;
        i = (i * 5 + 1 + perturb) & mask;
    }

    return -1;
}

static int compile(WL_String path, WL_Program *program, WL_Arena *arena)
{
    WL_Compiler *compiler = wl_compiler_init(arena);
    if (compiler == NULL) {
        TRACE("Couldn't initialize WL compiler object");
        return -1;
    }

    LoadedFile *loaded_file_head = NULL;
    LoadedFile **loaded_file_tail = &loaded_file_head;

    for (int i = 0;; i++) {

        LoadedFile *loaded_file = load_file((CWEB_String) { path.ptr, path.len });
        if (loaded_file == NULL) {
            TRACE("Couldn't load file '%.*s'", path.len, path.ptr);
            free_loaded_files(loaded_file_head);
            return -1;
        }

        *loaded_file_tail = loaded_file;
        loaded_file_tail = &loaded_file->next;

        WL_String content = { loaded_file->data, loaded_file->len };
        WL_AddResult result = wl_compiler_add(compiler, path, content);

        if (result.type == WL_ADD_ERROR) {
            TRACE("Compilation failed (%s)", wl_compiler_error(compiler).ptr);
            free_loaded_files(loaded_file_head);
            return -1;
        }

        if (result.type == WL_ADD_LINK) break;

        ASSERT(result.type == WL_ADD_AGAIN);
        path = result.path;
    }

    int ret = wl_compiler_link(compiler, program);
    if (ret < 0) {
        TRACE("Compilation failed (%s)", wl_compiler_error(compiler).ptr);
        return -1;
    }

    free_loaded_files(loaded_file_head);

    TRACE("Compilation succeded");
    return 0;
}

static int query_routine(WL_Runtime *rt, SQLiteCache *dbcache)
{
    if (dbcache == NULL) {
        wl_push_none(rt); // Allow not pushing anything on the WL machine
        return -1;
    }

    int num_args = wl_arg_count(rt);
    if (num_args == 0)
        return 0;

    WL_String format;
    if (!wl_arg_str(rt, 0, &format))
        return -1;

    sqlite3_stmt *stmt;
    int ret = sqlite3utils_prepare(dbcache, &stmt, format.ptr, format.len);
    if (ret != SQLITE_OK)
        return -1;

    for (int i = 1; i < num_args; i++) {

        int64_t ival;
        double  fval;
        WL_String str;

        if (wl_arg_none(rt, i))
            ret = sqlite3_bind_null(stmt, i);
        else if (wl_arg_s64(rt, i, &ival))
            ret = sqlite3_bind_int64(stmt, i, ival);
        else if (wl_arg_f64(rt, i, &fval))
            ret = sqlite3_bind_double(stmt, i, fval);
        else if (wl_arg_str(rt, i, &str))
            ret = sqlite3_bind_text(stmt, i, str.ptr, str.len, NULL);
        else {
            ASSERT(0); // TODO
        }

        if (ret != SQLITE_OK) {
            sqlite3_reset(stmt);
            return -1;
        }
    }

    wl_push_array(rt, 0);

    while (sqlite3_step(stmt) == SQLITE_ROW) {

        int num_cols = sqlite3_column_count(stmt);
        if (num_cols < 0) {
            sqlite3_reset(stmt);
            return -1;
        }

        wl_push_map(rt, num_cols);

        for (int i = 0; i < num_cols; i++) {
            ret = sqlite3_column_type(stmt, i);
            switch (ret) {

                case SQLITE_INTEGER:
                {
                    int64_t x = sqlite3_column_int64(stmt, i);
                    wl_push_s64(rt, x);
                }
                break;

                case SQLITE_FLOAT:
                {
                    double x = sqlite3_column_double(stmt, i);
                    wl_push_f64(rt, x);
                }
                break;

                case SQLITE_TEXT:
                {
                    const void *x = sqlite3_column_text(stmt, i);
                    int n = sqlite3_column_bytes(stmt, i);
                    wl_push_str(rt, (WL_String) { (char*) x, n });
                }
                break;

                case SQLITE_BLOB:
                {
                    const void *x = sqlite3_column_blob(stmt, i);
                    int n = sqlite3_column_bytes(stmt, i);
                    wl_push_str(rt, (WL_String) { (char*) x, n });
                }
                break;

                case SQLITE_NULL:
                {
                    wl_push_none(rt);
                }
                break;
            }

            const char *name = sqlite3_column_name(stmt, i);

            wl_push_str(rt, (WL_String) { (char*) name, strlen(name) });
            wl_insert(rt);
        }

        wl_append(rt);
    }

    sqlite3_reset(stmt);
    return 0;
}

static int get_or_create_program(TemplateCache *cache, WL_String path, bool force_create, WL_Arena *arena, WL_Program *program)
{
    if (cache == NULL)
        return -1;

    int i = template_cache_lookup(cache, path);

    if (cache->pool[i].pathlen != -1 && force_create) {
        cache->pool[i].pathlen = -1;
        free(cache->pool[i].program.ptr);
    }

    if (cache->pool[i].pathlen == -1) {

        WL_Program program;
        int ret = compile(path, &program, arena);
        if (ret < 0) return -1;

        void *p = malloc(program.len);
        if (p == NULL)
            return -1;
        memcpy(p, program.ptr, program.len);
        program.ptr = p;

        if ((int) sizeof(cache->pool->path) <= path.len)
            return -1;
        memcpy(cache->pool[i].path, path.ptr, path.len);
        cache->pool[i].path[path.len] = '\0';
        cache->pool[i].pathlen = path.len;
        cache->pool[i].program = program;
    }

    *program = cache->pool[i].program;
    return 0;
}
#endif

void cweb_respond_template_impl(CWEB_Request *req, int status, CWEB_String template_file, CWEB_VArgs args)
{
#ifdef CWEB_ENABLE_TEMPLATE
    http_response_builder_status(req->builder, status);
    int ret = set_auth_cookie_if_necessary(req);
    if (ret < 0) {
        http_response_builder_undo(req->builder);
        http_response_builder_status(req->builder, -ret);
        http_response_builder_done(req->builder);
        return;
    }

    WL_Program program;
    ret = get_or_create_program(req->cweb->tpcache, (WL_String) { template_file.ptr, template_file.len }, !req->cweb->enable_template_cache, &req->arena, &program);
    if (ret < 0) {
        http_response_builder_undo(req->builder);
        http_response_builder_status(req->builder, 500);
        http_response_builder_done(req->builder);
        return;
    }

    //wl_dump_program(program);

    WL_Runtime *rt = wl_runtime_init(&req->arena, program);
    if (rt == NULL) {
        http_response_builder_undo(req->builder);
        http_response_builder_status(req->builder, 500);
        http_response_builder_done(req->builder);
        return;
    }

    for (bool done = false; !done; ) {

        WL_EvalResult result = wl_runtime_eval(rt);
        switch (result.type) {

            case WL_EVAL_DONE:
            http_response_builder_done(req->builder);
            done = true;
            break;

            case WL_EVAL_ERROR:
            CWEB_TRACE("template evaluation error: %s", wl_runtime_error(rt).ptr);
            http_response_builder_undo(req->builder);
            http_response_builder_status(req->builder, 500);
            http_response_builder_done(req->builder);
            return;

            case WL_EVAL_SYSVAR:
            if (wl_streq(result.str, "login_user_id", -1)) {

                if (req->user_id < 0)
                    wl_push_none(rt);
                else
                    wl_push_s64(rt, req->user_id);

            } else if (wl_streq(result.str, "csrf", -1)) {

                if (req->csrf.len == 0)
                    wl_push_none(rt);
                else
                    wl_push_str(rt, (WL_String) { req->csrf.ptr, req->csrf.len });
            }
            break;

            case WL_EVAL_SYSCALL:
            if (wl_streq(result.str, "query", -1)) {
                query_routine(rt, req->cweb->dbcache);
                break;
            }
            if (wl_streq(result.str, "args", -1)) {

                if (wl_arg_count(rt) != 1) {
                    // TODO
                    break;
                }

                int64_t idx;
                if (!wl_arg_s64(rt, 0, &idx)) {
                    // TODO
                    break;
                }

                if (idx < 0 || idx >= args.len) {
                    // TODO
                    break;
                }

                CWEB_VArg arg = args.ptr[idx];
                switch (arg.type) {
                    case CWEB_VARG_TYPE_C  : wl_push_s64(rt, arg.c);   break;
                    case CWEB_VARG_TYPE_S  : wl_push_s64(rt, arg.s);   break;
                    case CWEB_VARG_TYPE_I  : wl_push_s64(rt, arg.i);   break;
                    case CWEB_VARG_TYPE_L  : wl_push_s64(rt, arg.l);   break;
                    case CWEB_VARG_TYPE_LL : wl_push_s64(rt, arg.ll);  break;
                    case CWEB_VARG_TYPE_SC : wl_push_s64(rt, arg.sc);  break;
                    case CWEB_VARG_TYPE_SS : wl_push_s64(rt, arg.ss);  break;
                    case CWEB_VARG_TYPE_SI : wl_push_s64(rt, arg.si);  break;
                    case CWEB_VARG_TYPE_SL : wl_push_s64(rt, arg.sl);  break;
                    case CWEB_VARG_TYPE_SLL: wl_push_s64(rt, arg.sll); break;
                    case CWEB_VARG_TYPE_F  : wl_push_f64(rt, arg.f);   break;
                    case CWEB_VARG_TYPE_D  : wl_push_f64(rt, arg.d);   break;
                    case CWEB_VARG_TYPE_B  : if (arg.b) wl_push_true(rt); else wl_push_false(rt); break;
                    case CWEB_VARG_TYPE_STR: wl_push_str(rt, (WL_String) { arg.str.ptr, arg.str.len }); break;
                    default:break;
                }
                break;
            }
            break;

            case WL_EVAL_OUTPUT:
            http_response_builder_body(req->builder, (HTTP_String) { result.str.ptr, result.str.len });
            break;

            default:
            break;
        }
    }
#else
    http_response_builder_status(req->builder, 500);
    http_response_builder_done(req->builder);
#endif
}

////////////////////////////////////////////////////////////////
// CRASH LOGGER
////////////////////////////////////////////////////////////////
#if defined(__linux__) && defined(__x86_64__)

#define _GNU_SOURCE
#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/reg.h>
#include <sys/stat.h>
#include <ucontext.h>

typedef struct {
    uint64_t base_addr;
    int count;
    void *symbols;
    void *strings;
} SymbolTable;

static int is_hex(char c)
{
    return (c >= '0' && c <= '9') || 
           (c >= 'a' && c <= 'f') || 
           (c >= 'A' && c <= 'F');
}

static uint64_t query_base_addr(void)
{
    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd < 0) 
        return -1;

    char buf[128];
    int ret = read(fd, buf, sizeof(buf));
    if (ret < 0) {
        close(fd);
        return -1;
    }

    close(fd);

    if (ret == 0 || !is_hex(buf[0]))
        return -1;

    int i = 0;
    uint64_t base_addr = 0;
    for (;;) {
        char c = buf[i++];

        int d;
        if (0) {}
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else d = c - '0';

        if (base_addr > (UINT64_MAX - d) / 16)
            return -1;
        base_addr = base_addr * 16 + d;

        if (i == ret)
            return -1;

        if (buf[i] == '-')
            break;

        if (!is_hex(buf[i]))
            return -1;
    }

    return base_addr;
}

static int current_executable_path(char *dst, int cap)
{
    if (cap == 0)
        return -1;

    int ret = readlink("/proc/self/exe", dst, cap-1);
    if (ret < 0)
        return -1;
    dst[ret] = '\0';
    return ret;
}

static int load_symbols_from_elf(void *src, int len, SymbolTable *st)
{
    // NOTE: It's assumed is properly aligned
    assert(((uintptr_t) src & 15) == 0);

    // Check that the file contains a full header
    if (len < (int) sizeof(Elf64_Ehdr))
        return -1;
    Elf64_Ehdr *ehdr = (Elf64_Ehdr*) src;

    // Check that the file contains the full list
    // of section headers
    if (ehdr->e_shoff + ehdr->e_shnum * sizeof(Elf64_Shdr) > len)
        return -1;
    Elf64_Shdr *shdrs = (Elf64_Shdr*) (src + ehdr->e_shoff);

    Elf64_Shdr *shstrtab_hdr = &shdrs[ehdr->e_shstrndx]; // TODO: bounds check
    char *shstrtab = src + shstrtab_hdr->sh_offset;

    // Iterate over the section headers to find the
    // one reative to symbols and their strings
    Elf64_Shdr *symtab_hdr = NULL;
    Elf64_Shdr *strtab_hdr = NULL;

    for (int i = 0; i < ehdr->e_shnum; i++) {
        char *section_name = shstrtab + shdrs[i].sh_name;
        if (0) {}
        else if (!strcmp(section_name, ".symtab")) symtab_hdr = &shdrs[i];
        else if (!strcmp(section_name, ".strtab")) strtab_hdr = &shdrs[i];
    }

    if (symtab_hdr == NULL || strtab_hdr == NULL) {
        return -1;
    }

    void *mem = malloc(symtab_hdr->sh_size + strtab_hdr->sh_size);
    if (mem == NULL) {
        return -1;
    }

    st->count = symtab_hdr->sh_size / sizeof(Elf64_Sym);
    st->symbols = mem;
    st->strings = (char*) st->symbols + symtab_hdr->sh_size;

    memcpy(st->symbols, src + symtab_hdr->sh_offset, symtab_hdr->sh_size);
    memcpy(st->strings, src + strtab_hdr->sh_offset, strtab_hdr->sh_size);

    return 0;
}

static char *read_file(char *path, int *len)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return NULL;

    struct stat buf;
    if (fstat(fd, &buf) < 0) {
        close(fd);
        return NULL;
    }
    *len = buf.st_size;

    char *ptr = malloc(*len + 1);
    if (ptr == NULL) {
        close(fd);
        return NULL;
    }

    for (int num = 0; num < *len; ) {

        int ret = read(fd, ptr + num, *len - num);
        if (ret <= 0) {
            free(ptr);
            close(fd);
            return NULL;
        }

        num += ret;
    }

    ptr[*len] = '\0';
    return ptr;
}

static int symbol_table_from_current_process(SymbolTable *st)
{
    uint64_t base_addr = query_base_addr();
    if (base_addr == -1)
        return -1;
    st->base_addr = base_addr;

    char path[1<<10];
    if (current_executable_path(path, sizeof(path)) < 0)
        return -1;

    char *exe_ptr;
    int   exe_len;
    exe_ptr = read_file(path, &exe_len);
    if (exe_ptr == NULL)
        return -1;

    if (load_symbols_from_elf(exe_ptr, exe_len, st) < 0) {
        free(exe_ptr);
        return -1;
    }

    free(exe_ptr);
    return 0;
}

static void symbol_table_free(SymbolTable *st)
{
    free(st->symbols);
}

static char *symbol_table_find(SymbolTable *st, uint64_t addr)
{
    for (int i = 0; i < st->count; i++) {
        Elf64_Sym *sym = (Elf64_Sym*) st->symbols + i;

        if (ELF64_ST_TYPE(sym->st_info) != STT_FUNC)
            continue;

        if (sym->st_value == 0)
            continue;

        uint64_t sym_beg = st->base_addr + sym->st_value;
        uint64_t sym_end = st->base_addr + sym->st_value + sym->st_size;

        if (addr >= sym_beg && addr < sym_end)
            return (char*) st->strings + sym->st_name;
    }

    return NULL;
}

#if 0
static void symbol_table_dump(SymbolTable *st)
{
    for (int i = 0; i < st->count; i++) {
        Elf64_Sym *sym = (Elf64_Sym*) st->symbols + i;

        if (ELF64_ST_TYPE(sym->st_info) != STT_FUNC)
            continue;

        if (sym->st_value == 0)
            continue;

        char *name = (char*) st->strings + sym->st_name;
        printf("%s\n", name);
    }
}
#endif

typedef struct {
    char    *name;
    uint64_t addr;
} StackFrame;

static int walk_stack(uint64_t rip, uint64_t rbp, SymbolTable *st, StackFrame *frames, int max_frames)
{
    int frame_count = 0;

    if (frame_count < max_frames) {
        frames[frame_count].addr = rip - st->base_addr;
        frames[frame_count].name = symbol_table_find(st, rip);
        frame_count++;
    }

    while (rbp != 0) {

        if (rbp & 0xF)
            break;

        uint64_t *frame_ptr = (uint64_t*) rbp;

        uint64_t next_rbp    = frame_ptr[0];
        uint64_t return_addr = frame_ptr[1];

        if (next_rbp != 0 && next_rbp <= rbp)
            break;

        if (return_addr == 0)
            break;

        if (frame_count == max_frames)
            break;
        frames[frame_count].addr = return_addr - st->base_addr;
        frames[frame_count].name = symbol_table_find(st, return_addr);
        frame_count++;

        rbp = next_rbp;
    }

    return frame_count;
}

static bool        crash_logger_symbol_init = false;
static char*       crash_logger_file_name = NULL;
static SymbolTable crash_logger_symbol_table;
static char*       crash_logger_signal_stack;

static void crash_handler(int sig, siginfo_t *info, void *ucontext)
{
    if (crash_logger_symbol_init) {

        // Buffer for evaluating format strings
        char tmp[1<<9];
        int len;

        ucontext_t *ctx = (ucontext_t*) ucontext;
        uint64_t rip = ctx->uc_mcontext.gregs[REG_RIP];
        uint64_t rbp = ctx->uc_mcontext.gregs[REG_RBP];

        StackFrame frames[64];
        int count = walk_stack(rip, rbp, &crash_logger_symbol_table, frames, 64);

        int fd = open(crash_logger_file_name, O_WRONLY | O_CREAT, 0666);
        if (fd < 0)
            exit(1);

        CWEB_String sig_name = {0};
        switch (sig) {
            case SIGSEGV: sig_name = CWEB_STR("Segmentation fault");       break;
            case SIGBUS : sig_name = CWEB_STR("Bus error");                break;
            case SIGILL : sig_name = CWEB_STR("Illegal instruction");      break;
            case SIGFPE : sig_name = CWEB_STR("Floating point exception"); break;
            case SIGTRAP: sig_name = CWEB_STR("Trace trap");               break;
            case SIGSYS : sig_name = CWEB_STR("Bad system call");          break;
            case SIGABRT: sig_name = CWEB_STR("Abort");                    break;
        }
        if (sig_name.len == 0) {
            len = snprintf(tmp, sizeof(tmp), "(unknown signal %d)\n", sig);
            write(fd, tmp, len);
        } else {
            write(fd, sig_name.ptr, sig_name.len);
            write(fd, "\n", 1);
        }

        for (int i = 0; i < count; i++) {
            len = snprintf(tmp, sizeof(tmp), "  [%d] 0x%lx %s\n", i, frames[i].addr, 
                frames[i].name ? frames[i].name : "?");
            write(fd, tmp, len);
        }

        close(fd);
    }
    exit(1);
}

static int crash_logger_init(char *file_name, int file_name_len)
{
    {
        char *file_name_copy = malloc(file_name_len + 1);
        if (file_name_copy == NULL)
            return -1;
        memcpy(file_name_copy, file_name, file_name_len);
        file_name_copy[file_name_len] = '\0';
        crash_logger_file_name = file_name_copy;
    }

    if (symbol_table_from_current_process(&crash_logger_symbol_table) < 0) {
        free(crash_logger_file_name);
        return -1;
    }

    // Set up alternate signal stack
    {
        crash_logger_signal_stack = malloc(SIGSTKSZ);
        if (crash_logger_signal_stack == NULL) {
            symbol_table_free(&crash_logger_symbol_table);
            free(crash_logger_file_name);
            return -1;
        }

        stack_t ss;
        ss.ss_sp = crash_logger_signal_stack;
        ss.ss_size = SIGSTKSZ;
        ss.ss_flags = 0;
        if (sigaltstack(&ss, NULL) < 0) {
            free(crash_logger_signal_stack);
            symbol_table_free(&crash_logger_symbol_table);
            free(crash_logger_file_name);
            return -1;
        }
    }

    {
        // Register the crash handler
        struct sigaction sa;
        sa.sa_sigaction = crash_handler;
        sa.sa_flags = SA_SIGINFO | SA_ONSTACK;  // Add SA_ONSTACK flag
        sigemptyset(&sa.sa_mask);

        // Memory errors
        sigaction(SIGSEGV, &sa, NULL);  // Segmentation fault (invalid memory access)
        sigaction(SIGBUS, &sa, NULL);   // Bus error (misaligned access, hardware error)

        // Execution errors
        sigaction(SIGILL, &sa, NULL);   // Illegal instruction
        sigaction(SIGFPE, &sa, NULL);   // Floating point exception
        sigaction(SIGTRAP, &sa, NULL);  // Trace trap

        // System/resource errors
        sigaction(SIGSYS, &sa, NULL);   // Bad system call
        sigaction(SIGABRT, &sa, NULL);  // Abort (from assert, abort(), etc.)

        // Optional: Resource limit violations
        sigaction(SIGXCPU, &sa, NULL);  // CPU time limit exceeded
        sigaction(SIGXFSZ, &sa, NULL);  // File size limit exceeded
    }

    crash_logger_symbol_init = true;
    return 0;
}

static void crash_logger_free(void)
{
    if (!crash_logger_symbol_init)
        return;

    free(crash_logger_signal_stack);
    symbol_table_free(&crash_logger_symbol_table);
    free(crash_logger_file_name);

    crash_logger_symbol_init = false;
}

#else

static int crash_logger_init(char *file_name, int file_name_len)
{
    (void) file_name;
    (void) file_name_len;
    return -1;
}

static void crash_logger_free(void)
{
}

#endif
