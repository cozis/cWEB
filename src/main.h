#include <stdint.h>
#include <stdbool.h>

#ifndef CWEB_AMALGAMATION
#include "wl.h"
#include "chttp.h"
#endif

#define CWEB_STR(X) (CWEB_String) { (X), (int) sizeof(X)-1 }

typedef struct {
    char *ptr;
    int   len;
} CWEB_String;

CWEB_String cweb_trim(CWEB_String s);
bool        cweb_streq(CWEB_String a, CWEB_String b);

typedef enum {
    CWEB_VARG_TYPE_C,
    CWEB_VARG_TYPE_S,
    CWEB_VARG_TYPE_I,
    CWEB_VARG_TYPE_L,
    CWEB_VARG_TYPE_LL,
    CWEB_VARG_TYPE_SC,
    CWEB_VARG_TYPE_SS,
    CWEB_VARG_TYPE_SI,
    CWEB_VARG_TYPE_SL,
    CWEB_VARG_TYPE_SLL,
    CWEB_VARG_TYPE_UC,
    CWEB_VARG_TYPE_US,
    CWEB_VARG_TYPE_UI,
    CWEB_VARG_TYPE_UL,
    CWEB_VARG_TYPE_ULL,
    CWEB_VARG_TYPE_F,
    CWEB_VARG_TYPE_D,
    CWEB_VARG_TYPE_B,
    CWEB_VARG_TYPE_STR,
    CWEB_VARG_TYPE_PC,
    CWEB_VARG_TYPE_PS,
    CWEB_VARG_TYPE_PI,
    CWEB_VARG_TYPE_PL,
    CWEB_VARG_TYPE_PLL,
    CWEB_VARG_TYPE_PSC,
    CWEB_VARG_TYPE_PSS,
    CWEB_VARG_TYPE_PSI,
    CWEB_VARG_TYPE_PSL,
    CWEB_VARG_TYPE_PSLL,
    CWEB_VARG_TYPE_PUC,
    CWEB_VARG_TYPE_PUS,
    CWEB_VARG_TYPE_PUI,
    CWEB_VARG_TYPE_PUL,
    CWEB_VARG_TYPE_PULL,
    CWEB_VARG_TYPE_PF,
    CWEB_VARG_TYPE_PD,
    CWEB_VARG_TYPE_PB,
    CWEB_VARG_TYPE_PSTR,
} CWEB_VArgType;

typedef struct {
    CWEB_VArgType type;
    union {
        char c;
        short s;
        int i;
        long l;
        long long ll;
        signed char sc;
        signed short ss;
        signed int si;
        signed long sl;
        signed long long sll;
        unsigned char uc;
        unsigned short us;
        unsigned int ui;
        unsigned long ul;
        unsigned long long ull;
        float f;
        double d;
        bool b;
        CWEB_String str;
        char *pc;
        short *ps;
        int *pi;
        long *pl;
        long long *pll;
        signed char *psc;
        signed short *pss;
        signed int *psi;
        signed long *psl;
        signed long long *psll;
        unsigned char *puc;
        unsigned short *pus;
        unsigned int *pui;
        unsigned long *pul;
        unsigned long long *pull;
        float *pf;
        double *pd;
        bool *pb;
        CWEB_String *pstr;
    };
} CWEB_VArg;

CWEB_VArg cweb_varg_from_c    (char c);
CWEB_VArg cweb_varg_from_s    (short s);
CWEB_VArg cweb_varg_from_i    (int i);
CWEB_VArg cweb_varg_from_l    (long l);
CWEB_VArg cweb_varg_from_ll   (long long ll);
CWEB_VArg cweb_varg_from_sc   (char sc);
CWEB_VArg cweb_varg_from_ss   (short ss);
CWEB_VArg cweb_varg_from_si   (int si);
CWEB_VArg cweb_varg_from_sl   (long sl);
CWEB_VArg cweb_varg_from_sll  (long long sll);
CWEB_VArg cweb_varg_from_uc   (char uc);
CWEB_VArg cweb_varg_from_us   (short us);
CWEB_VArg cweb_varg_from_ui   (int ui);
CWEB_VArg cweb_varg_from_ul   (long ul);
CWEB_VArg cweb_varg_from_ull  (long long ull);
CWEB_VArg cweb_varg_from_f    (float f);
CWEB_VArg cweb_varg_from_d    (double d);
CWEB_VArg cweb_varg_from_b    (bool b);
CWEB_VArg cweb_varg_from_str  (CWEB_String str);
CWEB_VArg cweb_varg_from_pc   (char *pc);
CWEB_VArg cweb_varg_from_ps   (short *ps);
CWEB_VArg cweb_varg_from_pi   (int *pi);
CWEB_VArg cweb_varg_from_pl   (long *pl);
CWEB_VArg cweb_varg_from_pll  (long long *pll);
CWEB_VArg cweb_varg_from_psc  (char *psc);
CWEB_VArg cweb_varg_from_pss  (short *pss);
CWEB_VArg cweb_varg_from_psi  (int *psi);
CWEB_VArg cweb_varg_from_psl  (long *psl);
CWEB_VArg cweb_varg_from_psll (long long *psll);
CWEB_VArg cweb_varg_from_puc  (char *puc);
CWEB_VArg cweb_varg_from_pus  (short *pus);
CWEB_VArg cweb_varg_from_pui  (int *pui);
CWEB_VArg cweb_varg_from_pul  (long *pul);
CWEB_VArg cweb_varg_from_pull (long long *pull);
CWEB_VArg cweb_varg_from_pf   (float *pf);
CWEB_VArg cweb_varg_from_pd   (double *pd);
CWEB_VArg cweb_varg_from_pb   (bool *pb);
CWEB_VArg cweb_varg_from_pstr (CWEB_String *pstr);

#define CWEB_VARG(X) (_Generic((X),           \
    char              : cweb_varg_from_c,     \
    short             : cweb_varg_from_s,     \
    int               : cweb_varg_from_i,     \
    long              : cweb_varg_from_l,     \
    long long         : cweb_varg_from_ll,    \
    signed char       : cweb_varg_from_sc,    \
    /*signed short      : cweb_varg_from_ss,*/  \
    /*signed int        : cweb_varg_from_si,*/  \
    /*signed long       : cweb_varg_from_sl,*/  \
    /*signed long long  : cweb_varg_from_sll,*/ \
    unsigned char     : cweb_varg_from_uc,    \
    unsigned short    : cweb_varg_from_us,    \
    unsigned int      : cweb_varg_from_ui,    \
    unsigned long     : cweb_varg_from_ul,    \
    unsigned long long: cweb_varg_from_ull,   \
    float             : cweb_varg_from_f,     \
    double            : cweb_varg_from_d,     \
    bool              : cweb_varg_from_b,     \
    CWEB_String       : cweb_varg_from_str,   \
    char*              : cweb_varg_from_pc,   \
    short*             : cweb_varg_from_ps,   \
    int*               : cweb_varg_from_pi,   \
    long*              : cweb_varg_from_pl,   \
    long long*         : cweb_varg_from_pll,  \
    signed char*       : cweb_varg_from_psc,  \
    /*signed short*     : cweb_varg_from_pss,*/  \
    /*signed int*       : cweb_varg_from_psi,*/  \
    /*signed long*      : cweb_varg_from_psl,*/  \
    /*signed long long* : cweb_varg_from_psll,*/ \
    unsigned char*     : cweb_varg_from_puc,  \
    unsigned short*    : cweb_varg_from_pus,  \
    unsigned int*      : cweb_varg_from_pui,  \
    unsigned long*     : cweb_varg_from_pul,  \
    unsigned long long*: cweb_varg_from_pull, \
    float*             : cweb_varg_from_pf,   \
    double*            : cweb_varg_from_pd,   \
    bool*              : cweb_varg_from_pb,   \
    CWEB_String*       : cweb_varg_from_pstr  \
))(X)

typedef struct {
    int len;
    CWEB_VArg *ptr;
} CWEB_VArgs;

#define CWEB_VARGS_1(a)             (CWEB_VArgs) {1, (CWEB_VArg[]) { CWEB_VARG(a) } }
#define CWEB_VARGS_2(a, b)          (CWEB_VArgs) {2, (CWEB_VArg[]) { CWEB_VARG(a), CWEB_VARG(b) } }
#define CWEB_VARGS_3(a, b, c)       (CWEB_VArgs) {3, (CWEB_VArg[]) { CWEB_VARG(a), CWEB_VARG(b), CWEB_VARG(c) } }
#define CWEB_VARGS_4(a, b, c, d)    (CWEB_VArgs) {4, (CWEB_VArg[]) { CWEB_VARG(a), CWEB_VARG(b), CWEB_VARG(c), CWEB_VARG(d) } }
#define CWEB_VARGS_5(a, b, c, d, e) (CWEB_VArgs) {5, (CWEB_VArg[]) { CWEB_VARG(a), CWEB_VARG(b), CWEB_VARG(c), CWEB_VARG(d), CWEB_VARG(e) } }
#define CWEB_DISPATCH__(_1, _2, _3, _4, _5, NAME, ...) NAME
#define CWEB_VARGS(...) CWEB_DISPATCH__(__VA_ARGS__, CWEB_VARGS_5, CWEB_VARGS_4, CWEB_VARGS_3, CWEB_VARGS_2, CWEB_VARGS_1)(__VA_ARGS__)

typedef struct CWEB CWEB;

typedef struct {

    CWEB *cweb;

    WL_Arena arena;

    HTTP_Request *req;
    HTTP_ResponseBuilder builder;

    // Session
    bool just_created_session;
    int  user_id;
    CWEB_String sess;
    CWEB_String csrf;

} CWEB_Request;

int  cweb_global_init(void);
void cweb_global_free(void);

int  cweb_init(CWEB *cweb, CWEB_String addr, uint16_t port);
void cweb_free(CWEB *cweb);

int cweb_enable_database(CWEB *cweb, CWEB_String file);

CWEB_Request cweb_wait(CWEB *cweb);

//////////////////////////////////////
// Session

CWEB_String cweb_get_session_csrf(CWEB_Request *req);
int         cweb_get_session_user_id(CWEB_Request *req);
int         cweb_set_session_user_id(CWEB_Request *req, int user_id);

//////////////////////////////////////
// Request

CWEB_String cweb_get_param_s(CWEB_Request *req, CWEB_String name);
int         cweb_get_param_i(CWEB_Request *req, CWEB_String name);

//////////////////////////////////////
// Response

void cweb_respond_basic(CWEB_Request *req, int status, CWEB_String content);
void cweb_respond_redirect(CWEB_Request *req, CWEB_String target);
void cweb_respond_template(CWEB_Request *req, int status, CWEB_String template_file, int resource_id);

//////////////////////////////////////
// Database

typedef struct {
    void *handle;
} CWEB_QueryResult;

int64_t          cweb_database_insert_impl(CWEB *cweb, const char *fmt, CWEB_VArgs args);
CWEB_QueryResult cweb_database_select_impl(CWEB *cweb, const char *fmt, CWEB_VArgs args);
int              cweb_next_query_row_impl(CWEB_QueryResult *res, CWEB_VArgs args);
void             cweb_free_query_result(CWEB_QueryResult *res);

#define cweb_database_insert(cweb, fmt, ...) cweb_database_insert_impl((cweb), (fmt), CWEB_VARGS(__VA_ARGS__))
#define cweb_database_select(cweb, fmt, ...) cweb_database_select_impl((cweb), (fmt), CWEB_VARGS(__VA_ARGS__))
#define cweb_next_query_row(res, ...)        cweb_next_query_row_impl((res), CWEB_VARGS(__VA_ARGS__))

//////////////////////////////////////
// Password

typedef struct {
    char data[61];
} CWEB_PasswordHash;

int cweb_hash_password(char *pass, int passlen, int cost, CWEB_PasswordHash *hash);
int cweb_check_password(char *pass, int passlen, CWEB_PasswordHash hash);
