#include <stdint.h>
#include <stdbool.h>

#define CWEB_ENABLE_DATABASE
#define CWEB_ENABLE_TEMPLATE

#define CWEB_STR(X) (CWEB_String) { (X), (int) sizeof(X)-1 }

typedef struct {
    char *ptr;
    int   len;
} CWEB_String;

typedef struct {
    char data[61];
} CWEB_PasswordHash;

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
    CWEB_VARG_TYPE_HASH,
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
    CWEB_VARG_TYPE_PHASH,
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
        CWEB_PasswordHash hash;
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
        CWEB_PasswordHash *phash;
    };
} CWEB_VArg;

typedef struct {
    int len;
    CWEB_VArg *ptr;
} CWEB_VArgs;

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
CWEB_VArg cweb_varg_from_hash (CWEB_PasswordHash hash);
CWEB_VArg cweb_varg_from_pc   (char *pc);
CWEB_VArg cweb_varg_from_ps   (short *ps);
CWEB_VArg cweb_varg_from_pi   (int *pi);
CWEB_VArg cweb_varg_from_pl   (long *pl);
CWEB_VArg cweb_varg_from_pll  (long long *pll);
CWEB_VArg cweb_varg_from_psc  (signed char *psc);
CWEB_VArg cweb_varg_from_pss  (signed short *pss);
CWEB_VArg cweb_varg_from_psi  (signed int *psi);
CWEB_VArg cweb_varg_from_psl  (signed long *psl);
CWEB_VArg cweb_varg_from_psll (signed long long *psll);
CWEB_VArg cweb_varg_from_puc  (unsigned char *puc);
CWEB_VArg cweb_varg_from_pus  (unsigned short *pus);
CWEB_VArg cweb_varg_from_pui  (unsigned int *pui);
CWEB_VArg cweb_varg_from_pul  (unsigned long *pul);
CWEB_VArg cweb_varg_from_pull (unsigned long long *pull);
CWEB_VArg cweb_varg_from_pf   (float *pf);
CWEB_VArg cweb_varg_from_pd   (double *pd);
CWEB_VArg cweb_varg_from_pb   (bool *pb);
CWEB_VArg cweb_varg_from_pstr (CWEB_String *pstr);
CWEB_VArg cweb_varg_from_phash(CWEB_PasswordHash *phash);

#define __CWEB_HELPER_ARG(X) (_Generic((X),   \
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
    CWEB_PasswordHash : cweb_varg_from_hash,  \
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
    CWEB_String*       : cweb_varg_from_pstr, \
    CWEB_PasswordHash* : cweb_varg_from_phash \
))(X)

// Helper macros
#define __CWEB_HELPER_DISPATCH_N(_0, _1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13, _14, _15, _16, N, ...) N
#define __CWEB_HELPER_CONCAT_0(A, B) A ## B
#define __CWEB_HELPER_CONCAT_1(A, B) __CWEB_HELPER_CONCAT_0(A, B)
#define __CWEB_HELPER_ARGS_0()                       (CWEB_VArgs) { 0, (CWEB_VArg[]) {}}
#define __CWEB_HELPER_ARGS_1(a)                      (CWEB_VArgs) { 1, (CWEB_VArg[]) { __CWEB_HELPER_ARG(a) }}
#define __CWEB_HELPER_ARGS_2(a, b)                   (CWEB_VArgs) { 2, (CWEB_VArg[]) { __CWEB_HELPER_ARG(a), __CWEB_HELPER_ARG(b) }}
#define __CWEB_HELPER_ARGS_3(a, b, c)                (CWEB_VArgs) { 3, (CWEB_VArg[]) { __CWEB_HELPER_ARG(a), __CWEB_HELPER_ARG(b), __CWEB_HELPER_ARG(c) }}
#define __CWEB_HELPER_ARGS_4(a, b, c, d)             (CWEB_VArgs) { 4, (CWEB_VArg[]) { __CWEB_HELPER_ARG(a), __CWEB_HELPER_ARG(b), __CWEB_HELPER_ARG(c), __CWEB_HELPER_ARG(d) }}
#define __CWEB_HELPER_ARGS_5(a, b, c, d, e)          (CWEB_VArgs) { 5, (CWEB_VArg[]) { __CWEB_HELPER_ARG(a), __CWEB_HELPER_ARG(b), __CWEB_HELPER_ARG(c), __CWEB_HELPER_ARG(d), __CWEB_HELPER_ARG(e) }}
#define __CWEB_HELPER_ARGS_6(a, b, c, d, e, f)       (CWEB_VArgs) { 6, (CWEB_VArg[]) { __CWEB_HELPER_ARG(a), __CWEB_HELPER_ARG(b), __CWEB_HELPER_ARG(c), __CWEB_HELPER_ARG(d), __CWEB_HELPER_ARG(e), __CWEB_HELPER_ARG(f) }}
#define __CWEB_HELPER_ARGS_7(a, b, c, d, e, f, g)    (CWEB_VArgs) { 7, (CWEB_VArg[]) { __CWEB_HELPER_ARG(a), __CWEB_HELPER_ARG(b), __CWEB_HELPER_ARG(c), __CWEB_HELPER_ARG(d), __CWEB_HELPER_ARG(e), __CWEB_HELPER_ARG(f), __CWEB_HELPER_ARG(g) }}
#define __CWEB_HELPER_ARGS_8(a, b, c, d, e, f, g, h) (CWEB_VArgs) { 8, (CWEB_VArg[]) { __CWEB_HELPER_ARG(a), __CWEB_HELPER_ARG(b), __CWEB_HELPER_ARG(c), __CWEB_HELPER_ARG(d), __CWEB_HELPER_ARG(e), __CWEB_HELPER_ARG(f), __CWEB_HELPER_ARG(g), __CWEB_HELPER_ARG(h) }}
#define __CWEB_COUNT_ARGS(...) __CWEB_HELPER_DISPATCH_N(DUMMY, ##__VA_ARGS__, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)

#define CWEB_VARGS(...) __CWEB_HELPER_CONCAT_1(__CWEB_HELPER_ARGS_, __CWEB_COUNT_ARGS(__VA_ARGS__))(__VA_ARGS__)

typedef struct CWEB CWEB;
typedef struct CWEB_Request CWEB_Request;

int  cweb_global_init(void);
void cweb_global_free(void);

CWEB *cweb_init(CWEB_String addr, uint16_t port);
void  cweb_free(CWEB *cweb);

int cweb_enable_database(CWEB *cweb, CWEB_String file);

// Pause execution until a request is available.
// TODO: When does this function return NULL?
CWEB_Request *cweb_wait(CWEB *cweb);

// Returns true iff the request matches the specified endpoint
bool cweb_match_endpoint(CWEB_Request *req, CWEB_String str);

// Returns the CSRF token associated to the current session 
CWEB_String cweb_get_csrf(CWEB_Request *req);

// Returns the user ID for the current session, or -1 if there is no session
int cweb_get_user_id(CWEB_Request *req);

// Sets the user ID for the current session (it must be a positive integer).
// If the ID is -1, the session is deleted.
int cweb_set_user_id(CWEB_Request *req, int user_id);

// Returns the request parameter with the specified name
// If the request uses POST, the parameter is taken from the body,
// else it's taken from the URL. If the parameter is not present,
// an empty string is returned.
CWEB_String cweb_get_param_s(CWEB_Request *req, CWEB_String name);

// Like cweb_get_param_s, but also parser the argument as an integer.
// If parsing fails or the parameter is missing, -1 is returned.
int cweb_get_param_i(CWEB_Request *req, CWEB_String name);

// Create a string by evaluating a format. Memory is allocated from the arena of the request.
// If the arena is full, an empty string is returned.
CWEB_String cweb_format_impl(CWEB_Request *req, char *fmt, CWEB_VArgs args);

// Helper
#define cweb_format(req, fmt, ...) cweb_format_impl((req), (fmt), CWEB_VARGS(__VA_ARGS__))

// Responds to the specified request with the given status code and content
void cweb_respond_basic(CWEB_Request *req, int status, CWEB_String content);

// Responds to the request by redirecting the client to the given target
void cweb_respond_redirect(CWEB_Request *req, CWEB_String target);

// Responds to the request by evaluating a WL template file
void cweb_respond_template(CWEB_Request *req, int status, CWEB_String template_file, int resource_id);

// Evaluates an SQL INSERT statement and returns the ID of the last inserted row. On error -1 is returned
int64_t cweb_database_insert_impl(CWEB *cweb, char *fmt, CWEB_VArgs args);

// Helper
#define cweb_database_insert(cweb, fmt, ...) cweb_database_insert_impl((cweb), (fmt), CWEB_VARGS(__VA_ARGS__))

// Iterator over database rows
typedef struct { void *handle; } CWEB_QueryResult;

// Evaluates an SQL SELECT statement, returning a scanner over the returned rows.
// You don't have to check for errors with this function
CWEB_QueryResult cweb_database_select_impl(CWEB *cweb, char *fmt, CWEB_VArgs args);

// Helper
#define cweb_database_select(cweb, fmt, ...) cweb_database_select_impl((cweb), (fmt), CWEB_VARGS(__VA_ARGS__))

// Returns the next row from the query result iterator.
int cweb_next_query_row_impl(CWEB_QueryResult *res, CWEB_VArgs args);

// Helper
#define cweb_next_query_row(res, ...) cweb_next_query_row_impl((res), CWEB_VARGS(__VA_ARGS__))

// Frees the result of a database query
void cweb_free_query_result(CWEB_QueryResult *res);

// Calculates the bcrypt hash of the specified password
int cweb_hash_password(char *pass, int passlen, int cost, CWEB_PasswordHash *hash);

// Checks whether the password matches the given hash
int cweb_check_password(char *pass, int passlen, CWEB_PasswordHash hash);
