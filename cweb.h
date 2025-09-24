/*
Copyright © 2025 Francesco Cozzuto

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the “Software”),
to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.
*/
#ifndef CWEB_INCLUDED
#define CWEB_INCLUDED

////////////////////////////////////////////////////////////////////////////////////////
// src/main.h
////////////////////////////////////////////////////////////////////////////////////////

#line 1 "src/main.h"
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

// Open an SQLite instance in file "database_file" and run the DDL script at "schema_file".
// Note that "database_file" may be ":memory:". 
int cweb_enable_database(CWEB *cweb, CWEB_String database_file, CWEB_String schema_file);

// Log all evaluated SQL statements to stdout
void cweb_trace_sql(CWEB *cweb, bool enable);

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
int cweb_hash_password(CWEB_String pass, int cost, CWEB_PasswordHash *hash);

// Checks whether the password matches the given hash
int cweb_check_password(CWEB_String pass, CWEB_PasswordHash hash);
#endif // CWEB_INCLUDED
#ifdef CWEB_IMPLEMENTATION
#define CWEB_AMALGAMATION
#define WL_NOINCLUDE
#define HTTP_NOINCLUDE
#define CRYPT_BLOWFISH_NOINCLUDE
#undef MIN
#undef MAX
#undef ASSERT
#undef SIZEOF
#undef TRACE

////////////////////////////////////////////////////////////////////////////////////////
// 3p/chttp.h
////////////////////////////////////////////////////////////////////////////////////////

#line 1 "3p/chttp.h"
#ifndef HTTP_AMALGAMATION
#define HTTP_AMALGAMATION

// This file was generated automatically. Do not modify directly!

////////////////////////////////////////////////////////////////////////////////////////
// src/basic.h
////////////////////////////////////////////////////////////////////////////////////////

#line 1 "src/basic.h"
#ifndef CHTTP_BASIC_INCLUDED
#define CHTTP_BASIC_INCLUDED

#include <stdbool.h>

// String type used throughout cHTTP.
typedef struct {
	char *ptr;
	int   len;
} HTTP_String;

// Compare two strings and return true iff they have
// the same contents.
bool http_streq(HTTP_String s1, HTTP_String s2);

// Compre two strings case-insensitively (uppercase and
// lowercase versions of a letter are considered the same)
// and return true iff they have the same contents.
bool http_streqcase(HTTP_String s1, HTTP_String s2);

// Remove spaces and tabs from the start and the end of
// a string. This doesn't change the original string and
// the new one references the contents of the original one.
HTTP_String http_trim(HTTP_String s);

// TODO: comment
void print_bytes(HTTP_String prefix, HTTP_String src);

// Macro to simplify converting string literals to
// HTTP_String.
//
// Instead of doing this:
//
//   char *s = "some string";
//
// You do this:
//
//   HTTP_String s = HTTP_STR("some string")
//
// This is a bit cumbersome, but better than null-terminated
// strings, having a pointer and length variable pairs whenever
// a function operates on a string. If this wasn't a library
// I would have done for
//
//   #define S(X) ...
//
// But I don't want to cause collisions with user code.
#define HTTP_STR(X) ((HTTP_String) {(X), sizeof(X)-1})

// Returns the number of items of a static array.
#define HTTP_COUNT(X) (sizeof(X) / sizeof((X)[0]))

// TODO: comment
#define HTTP_UNPACK(X) (X).len, (X).ptr

// Macro used to make invariants of the code more explicit.
//
// Say you have some function that operates on two integers
// and that by design their sum is always 100. This macro is
// useful to make that explicit:
//
//   void func(int a, int b)
//   {
//     HTTP_ASSERT(a + b == 100);
//     ...
//   }
//
// Assertions are about documentation, *not* error management.
//
// In non-release builds (where NDEBUG is not defined) asserted
// expressions are evaluated and if not true, the program is halted.
// This is quite nice as they offer a way to document code in
// a way that can be checked at runtime, unlike regular comments
// like this one.
#ifdef NDEBUG
#define HTTP_ASSERT(X) ((void) 0)
#else
#define HTTP_ASSERT(X) {if (!(X)) { __builtin_trap(); }}
#endif

#endif // CHTTP_BASIC_INCLUDED

////////////////////////////////////////////////////////////////////////////////////////
// src/parse.h
////////////////////////////////////////////////////////////////////////////////////////

#line 1 "src/parse.h"
#ifndef PARSE_INCLUDED
#define PARSE_INCLUDED

#ifndef HTTP_AMALGAMATION
#include "basic.h"
#endif

#define HTTP_MAX_HEADERS 32

typedef struct {
	unsigned int data;
} HTTP_IPv4;

typedef struct {
	unsigned short data[8];
} HTTP_IPv6;

typedef enum {
	HTTP_HOST_MODE_VOID = 0,
	HTTP_HOST_MODE_NAME,
	HTTP_HOST_MODE_IPV4,
	HTTP_HOST_MODE_IPV6,
} HTTP_HostMode;

typedef struct {
	HTTP_HostMode mode;
	HTTP_String   text;
	union {
		HTTP_String name;
		HTTP_IPv4   ipv4;
		HTTP_IPv6   ipv6;
	};
} HTTP_Host;

typedef struct {
	HTTP_String userinfo;
	HTTP_Host   host;
	int         port;
} HTTP_Authority;

// ZII
typedef struct {
	HTTP_String    scheme;
	HTTP_Authority authority;
	HTTP_String    path;
	HTTP_String    query;
	HTTP_String    fragment;
} HTTP_URL;

typedef enum {
	HTTP_METHOD_GET,
	HTTP_METHOD_HEAD,
	HTTP_METHOD_POST,
	HTTP_METHOD_PUT,
	HTTP_METHOD_DELETE,
	HTTP_METHOD_CONNECT,
	HTTP_METHOD_OPTIONS,
	HTTP_METHOD_TRACE,
	HTTP_METHOD_PATCH,
} HTTP_Method;

typedef struct {
	HTTP_String name;
	HTTP_String value;
} HTTP_Header;

typedef struct {
    bool        secure;
	HTTP_Method method;
	HTTP_URL    url;
	int         minor;
	int         num_headers;
	HTTP_Header headers[HTTP_MAX_HEADERS];
	HTTP_String body;
} HTTP_Request;

typedef struct {
    void*       context;
	int         minor;
	int         status;
	HTTP_String reason;
	int         num_headers;
	HTTP_Header headers[HTTP_MAX_HEADERS];
	HTTP_String body;
} HTTP_Response;

int         http_parse_ipv4     (char *src, int len, HTTP_IPv4     *ipv4);
int         http_parse_ipv6     (char *src, int len, HTTP_IPv6     *ipv6);
int         http_parse_url      (char *src, int len, HTTP_URL      *url);
int         http_parse_request  (char *src, int len, HTTP_Request  *req);
int         http_parse_response (char *src, int len, HTTP_Response *res);

int         http_find_header    (HTTP_Header *headers, int num_headers, HTTP_String name);

HTTP_String http_get_cookie     (HTTP_Request *req, HTTP_String name);
HTTP_String http_get_param      (HTTP_String body, HTTP_String str, char *mem, int cap);
int         http_get_param_i    (HTTP_String body, HTTP_String str);


#endif // PARSE_INCLUDED

////////////////////////////////////////////////////////////////////////////////////////
// src/engine.h
////////////////////////////////////////////////////////////////////////////////////////

#line 1 "src/engine.h"
#ifndef HTTP_ENGINE_INCLUDED
#define HTTP_ENGINE_INCLUDED

#ifndef HTTP_AMALGAMATION
#include "parse.h"
#endif

typedef enum {
	HTTP_MEMFUNC_MALLOC,
	HTTP_MEMFUNC_FREE,
} HTTP_MemoryFuncTag;

typedef void*(*HTTP_MemoryFunc)(HTTP_MemoryFuncTag tag,
	void *ptr, int len, void *data);

typedef struct {

	HTTP_MemoryFunc memfunc;
	void *memfuncdata;

	unsigned long long curs;

	char*        data;
	unsigned int head;
	unsigned int size;
	unsigned int used;
	unsigned int limit;

	char*        read_target;
	unsigned int read_target_size;

	int flags;
} HTTP_ByteQueue;

typedef unsigned long long HTTP_ByteQueueOffset;

#define HTTP_ENGINE_STATEBIT_CLIENT        (1 << 0)
#define HTTP_ENGINE_STATEBIT_CLOSED        (1 << 1)
#define HTTP_ENGINE_STATEBIT_RECV_BUF      (1 << 2)
#define HTTP_ENGINE_STATEBIT_RECV_ACK      (1 << 3)
#define HTTP_ENGINE_STATEBIT_SEND_BUF      (1 << 4)
#define HTTP_ENGINE_STATEBIT_SEND_ACK      (1 << 5)
#define HTTP_ENGINE_STATEBIT_REQUEST       (1 << 6)
#define HTTP_ENGINE_STATEBIT_RESPONSE      (1 << 7)
#define HTTP_ENGINE_STATEBIT_PREP          (1 << 8)
#define HTTP_ENGINE_STATEBIT_PREP_HEADER   (1 << 9)
#define HTTP_ENGINE_STATEBIT_PREP_BODY_BUF (1 << 10)
#define HTTP_ENGINE_STATEBIT_PREP_BODY_ACK (1 << 11)
#define HTTP_ENGINE_STATEBIT_PREP_ERROR    (1 << 12)
#define HTTP_ENGINE_STATEBIT_PREP_URL      (1 << 13)
#define HTTP_ENGINE_STATEBIT_PREP_STATUS   (1 << 14)
#define HTTP_ENGINE_STATEBIT_CLOSING       (1 << 15)

typedef enum {
	HTTP_ENGINE_STATE_NONE = 0,
	HTTP_ENGINE_STATE_CLIENT_PREP_URL      = HTTP_ENGINE_STATEBIT_CLIENT | HTTP_ENGINE_STATEBIT_PREP | HTTP_ENGINE_STATEBIT_PREP_URL,
	HTTP_ENGINE_STATE_CLIENT_PREP_HEADER   = HTTP_ENGINE_STATEBIT_CLIENT | HTTP_ENGINE_STATEBIT_PREP | HTTP_ENGINE_STATEBIT_PREP_HEADER,
	HTTP_ENGINE_STATE_CLIENT_PREP_BODY_BUF = HTTP_ENGINE_STATEBIT_CLIENT | HTTP_ENGINE_STATEBIT_PREP | HTTP_ENGINE_STATEBIT_PREP_BODY_BUF,
	HTTP_ENGINE_STATE_CLIENT_PREP_BODY_ACK = HTTP_ENGINE_STATEBIT_CLIENT | HTTP_ENGINE_STATEBIT_PREP | HTTP_ENGINE_STATEBIT_PREP_BODY_ACK,
	HTTP_ENGINE_STATE_CLIENT_PREP_ERROR    = HTTP_ENGINE_STATEBIT_CLIENT | HTTP_ENGINE_STATEBIT_PREP | HTTP_ENGINE_STATEBIT_PREP_ERROR,
	HTTP_ENGINE_STATE_CLIENT_SEND_BUF      = HTTP_ENGINE_STATEBIT_CLIENT | HTTP_ENGINE_STATEBIT_SEND_BUF,
	HTTP_ENGINE_STATE_CLIENT_SEND_ACK      = HTTP_ENGINE_STATEBIT_CLIENT | HTTP_ENGINE_STATEBIT_SEND_ACK,
	HTTP_ENGINE_STATE_CLIENT_RECV_BUF      = HTTP_ENGINE_STATEBIT_CLIENT | HTTP_ENGINE_STATEBIT_RECV_BUF,
	HTTP_ENGINE_STATE_CLIENT_RECV_ACK      = HTTP_ENGINE_STATEBIT_CLIENT | HTTP_ENGINE_STATEBIT_RECV_ACK,
	HTTP_ENGINE_STATE_CLIENT_READY         = HTTP_ENGINE_STATEBIT_CLIENT | HTTP_ENGINE_STATEBIT_RESPONSE,
	HTTP_ENGINE_STATE_CLIENT_CLOSED        = HTTP_ENGINE_STATEBIT_CLIENT | HTTP_ENGINE_STATEBIT_CLOSED,
	HTTP_ENGINE_STATE_SERVER_RECV_BUF      = HTTP_ENGINE_STATEBIT_RECV_BUF,
	HTTP_ENGINE_STATE_SERVER_RECV_ACK      = HTTP_ENGINE_STATEBIT_RECV_ACK,
	HTTP_ENGINE_STATE_SERVER_PREP_STATUS   = HTTP_ENGINE_STATEBIT_REQUEST | HTTP_ENGINE_STATEBIT_PREP | HTTP_ENGINE_STATEBIT_PREP_STATUS,
	HTTP_ENGINE_STATE_SERVER_PREP_HEADER   = HTTP_ENGINE_STATEBIT_REQUEST | HTTP_ENGINE_STATEBIT_PREP | HTTP_ENGINE_STATEBIT_PREP_HEADER,
	HTTP_ENGINE_STATE_SERVER_PREP_BODY_BUF = HTTP_ENGINE_STATEBIT_REQUEST | HTTP_ENGINE_STATEBIT_PREP | HTTP_ENGINE_STATEBIT_PREP_BODY_BUF,
	HTTP_ENGINE_STATE_SERVER_PREP_BODY_ACK = HTTP_ENGINE_STATEBIT_REQUEST | HTTP_ENGINE_STATEBIT_PREP | HTTP_ENGINE_STATEBIT_PREP_BODY_ACK,
	HTTP_ENGINE_STATE_SERVER_PREP_ERROR    = HTTP_ENGINE_STATEBIT_REQUEST | HTTP_ENGINE_STATEBIT_PREP | HTTP_ENGINE_STATEBIT_PREP_ERROR,
	HTTP_ENGINE_STATE_SERVER_SEND_BUF      = HTTP_ENGINE_STATEBIT_SEND_BUF,
	HTTP_ENGINE_STATE_SERVER_SEND_ACK      = HTTP_ENGINE_STATEBIT_SEND_ACK,
	HTTP_ENGINE_STATE_SERVER_CLOSED        = HTTP_ENGINE_STATEBIT_CLIENT,
} HTTP_EngineState;

typedef struct {
	HTTP_EngineState state;
	HTTP_ByteQueue   input;
	HTTP_ByteQueue   output;
	int numexch;
	int reqsize;
	int closing;
	int keepalive;
	HTTP_ByteQueueOffset response_offset;
	HTTP_ByteQueueOffset content_length_offset;
	HTTP_ByteQueueOffset content_length_value_offset;
	union {
		HTTP_Request  req;
		HTTP_Response res;
	} result;
} HTTP_Engine;

void             http_engine_init    (HTTP_Engine *eng, int client, HTTP_MemoryFunc memfunc, void *memfuncdata);
void             http_engine_free    (HTTP_Engine *eng);

void             http_engine_close   (HTTP_Engine *eng);
HTTP_EngineState http_engine_state   (HTTP_Engine *eng);

const char*      http_engine_statestr(HTTP_EngineState state); // TODO: remove

char*            http_engine_recvbuf (HTTP_Engine *eng, int *cap);
void             http_engine_recvack (HTTP_Engine *eng, int num);
char*            http_engine_sendbuf (HTTP_Engine *eng, int *len);
void             http_engine_sendack (HTTP_Engine *eng, int num);

HTTP_Request*    http_engine_getreq  (HTTP_Engine *eng);
HTTP_Response*   http_engine_getres  (HTTP_Engine *eng);

void             http_engine_url     (HTTP_Engine *eng, HTTP_Method method, HTTP_String url, int minor);
void             http_engine_status  (HTTP_Engine *eng, int status);
void             http_engine_header  (HTTP_Engine *eng, HTTP_String str);
void             http_engine_body    (HTTP_Engine *eng, HTTP_String str); 
void             http_engine_bodycap (HTTP_Engine *eng, int mincap);
char*            http_engine_bodybuf (HTTP_Engine *eng, int *cap);
void             http_engine_bodyack (HTTP_Engine *eng, int num);
void             http_engine_done    (HTTP_Engine *eng);
void             http_engine_undo    (HTTP_Engine *eng);

#endif // HTTP_ENGINE_INCLUDED

////////////////////////////////////////////////////////////////////////////////////////
// src/cert.h
////////////////////////////////////////////////////////////////////////////////////////

#line 1 "src/cert.h"
#ifndef CERT_INCLUDED
#define CERT_INCLUDED

#ifndef HTTP_AMALGAMATION
#include "basic.h"
#endif

// This is an utility to create self-signed certificates
// useful when testing HTTPS servers locally. This is only
// meant to be used by people starting out with a library
// and simplifying the zero to one phase.
//
// The C, O, and CN are respectively country name, organization name,
// and common name of the certificate. For instance:
//
//   C="IT"
//   O="My Organization"
//   CN="my_website.com"
//
// The output is a certificate file in PEM format and a private
// key file with the key used to sign the certificate.
int http_create_test_certificate(HTTP_String C, HTTP_String O, HTTP_String CN,
    HTTP_String cert_file, HTTP_String key_file);

#endif // CERT_INCLUDED

////////////////////////////////////////////////////////////////////////////////////////
// src/client.h
////////////////////////////////////////////////////////////////////////////////////////

#line 1 "src/client.h"
#ifndef CLIENT_INCLUDED
#define CLIENT_INCLUDED

#include <stdbool.h>

#ifndef HTTP_AMALGAMATION
#include "parse.h"
#endif

// Initialize the global state of cHTTP.
//
// cHTTP tries to avoid global state. What this function
// does is call the global initialization functions of
// its dependencies (OpenSSL and Winsock)
int http_global_init(void);

// Free the global state of cHTTP.
void http_global_free(void);

// Opaque type describing an "HTTP client". Any request
// that is started must always be associated to an HTTP
// client object.
typedef struct HTTP_Client HTTP_Client;

// Handle for a pending request. This should be considered
// opaque. Don't read or modify its fields!
typedef struct {
    void *data0;
    int   data1;
    int   data2;
} HTTP_RequestBuilder;

// Initialize a client object. If something goes wrong,
// NULL is returned.
HTTP_Client *http_client_init(void);

// Deinitialize a client object
void http_client_free(HTTP_Client *client);

// Create a request object associated to the given client.
// On success, 0 is returned and the handle is initialized.
// On error, -1 is returned.
int http_client_get_builder(HTTP_Client *client, HTTP_RequestBuilder *builder);

void http_request_builder_user_data(HTTP_RequestBuilder builder, void *user_data);

// Enable/disable I/O tracing for the specified request.
// This must be done when the request is in the initialization
// phase.
void http_request_builder_trace(HTTP_RequestBuilder builder, bool trace);

// Set the method and URL of the specified request object.
// This must be the first thing you do after http_client_request
// is called (you may http_request_trace before, but nothing
// else!)
void http_request_builder_line(HTTP_RequestBuilder builder, HTTP_Method method, HTTP_String url);

// Append a header to the specified request. You must call
// this after http_request_line and may do so multiple times.
void http_request_builder_header(HTTP_RequestBuilder builder, HTTP_String str);

// Append some data to the request's body. You must call
// this after either http_request_line or http_request_header.
void http_request_builder_body(HTTP_RequestBuilder builder, HTTP_String str);

// Mark the initialization of the request as completed and
// perform the request.
void http_request_builder_submit(HTTP_RequestBuilder builder);

// Free resources associated to a request. This must be called
// after the request has completed.
//
// TODO: allow aborting pending requests
void http_response_free(HTTP_Response *res);

// Wait for the completion of one request associated to
// the client. The handle of the resolved request is returned
// through the handle output parameter. If you're not
// interested in which request completed (like when you
// have only one pending request), you can pass NULL.
//
// On error -1 is retutned, else 0 is returned and the
// handle is initialized.
//
// Note that calling this function when no requests are
// pending is considered an error. 
int http_client_wait(HTTP_Client *client, HTTP_Response **res, void **user_data);

// TODO: comment
HTTP_Response *http_get(HTTP_String url,
    HTTP_String *headers, int num_headers);

// TODO: comment
HTTP_Response *http_post(HTTP_String url,
    HTTP_String *headers, int num_headers,
    HTTP_String body);

#endif // CLIENT_INCLUDED

////////////////////////////////////////////////////////////////////////////////////////
// src/server.h
////////////////////////////////////////////////////////////////////////////////////////

#line 1 "src/server.h"
#ifndef HTTP_SERVER_INCLUDED
#define HTTP_SERVER_INCLUDED

#include <stdint.h>

#ifndef HTTP_AMALGAMATION
#include "parse.h"
#endif

typedef struct {
    void *data0;
    int   data1;
    int   data2;
} HTTP_ResponseBuilder;

typedef struct HTTP_Server HTTP_Server;

HTTP_Server *http_server_init(HTTP_String addr, uint16_t port);

HTTP_Server *http_server_init_ex(HTTP_String addr, uint16_t port,
    uint16_t secure_port, HTTP_String cert_key, HTTP_String private_key);

void         http_server_free              (HTTP_Server *server);
int          http_server_wait              (HTTP_Server *server, HTTP_Request **req, HTTP_ResponseBuilder *handle);
int          http_server_add_website       (HTTP_Server *server, HTTP_String domain, HTTP_String cert_file, HTTP_String key_file);
void         http_response_builder_status  (HTTP_ResponseBuilder res, int status);
void         http_response_builder_header  (HTTP_ResponseBuilder res, HTTP_String str);
void         http_response_builder_body    (HTTP_ResponseBuilder res, HTTP_String str);
void         http_response_builder_bodycap (HTTP_ResponseBuilder res, int mincap);
char*        http_response_builder_bodybuf (HTTP_ResponseBuilder res, int *cap);
void         http_response_builder_bodyack (HTTP_ResponseBuilder res, int num);
void         http_response_builder_undo    (HTTP_ResponseBuilder res);
void         http_response_builder_done    (HTTP_ResponseBuilder res);

#endif // HTTP_SERVER_INCLUDED

////////////////////////////////////////////////////////////////////////////////////////
// src/router.h
////////////////////////////////////////////////////////////////////////////////////////

#line 1 "src/router.h"
#ifndef HTTP_ROUTER_INCLUDED
#define HTTP_ROUTER_INCLUDED

#ifndef HTTP_AMALGAMATION
#include "server.h"
#endif

typedef struct HTTP_Router HTTP_Router;
typedef void (*HTTP_RouterFunc)(HTTP_Request*, HTTP_ResponseBuilder, void*);;

HTTP_Router* http_router_init    (void);
void         http_router_free    (HTTP_Router *router);
void         http_router_resolve (HTTP_Router *router, HTTP_Request *req, HTTP_ResponseBuilder res);
void         http_router_dir     (HTTP_Router *router, HTTP_String endpoint, HTTP_String path);
void         http_router_func    (HTTP_Router *router, HTTP_Method method, HTTP_String endpoint, HTTP_RouterFunc func, void*);
int          http_serve          (char *addr, int port, HTTP_Router *router);

#endif // HTTP_ROUTER_INCLUDED
#endif // HTTP_AMALGAMATION

////////////////////////////////////////////////////////////////////////////////////////
// 3p/chttp.c
////////////////////////////////////////////////////////////////////////////////////////

#line 1 "3p/chttp.c"
#ifndef HTTP_NOINCLUDE
#include "chttp.h"
#endif

////////////////////////////////////////////////////////////////////////////////////////
// src/sec.h
////////////////////////////////////////////////////////////////////////////////////////

#line 1 "src/sec.h"
#ifndef SEC_INCLUDED
#define SEC_INCLUDED


#ifndef HTTP_AMALGAMATION
#include "basic.h"
#endif

#ifndef HTTPS_ENABLED

typedef struct {
} SecureContext;

#else

#define MAX_CERTS 10

#include <stdbool.h>

#include <openssl/ssl.h>

typedef struct {
    char domain[128];
    SSL_CTX *ctx;
} CertData;

typedef struct {

    bool is_server;

    SSL_CTX *ctx;

    // Only used when server
    int num_certs;
    CertData certs[MAX_CERTS];

} SecureContext;

#endif

void secure_context_global_init(void);
void secure_context_global_free(void);

int secure_context_init_as_client(SecureContext *sec);

int secure_context_init_as_server(SecureContext *sec,
    HTTP_String cert_file, HTTP_String key_file);

int secure_context_add_cert(SecureContext *sec,
    HTTP_String domain, HTTP_String cert_file,
    HTTP_String key_file);

void secure_context_free(SecureContext *sec);

#endif // SEC_INCLUDED

////////////////////////////////////////////////////////////////////////////////////////
// src/socket_raw.h
////////////////////////////////////////////////////////////////////////////////////////

#line 1 "src/socket_raw.h"
#ifndef SOCKET_RAW_INCLUDED
#define SOCKET_RAW_INCLUDED

#include <stdint.h>
#include <stdbool.h>

#ifdef _WIN32
#include <winsock2.h>
#define RAW_SOCKET SOCKET
#define BAD_SOCKET INVALID_SOCKET
#define POLL WSAPoll
#define CLOSE_SOCKET closesocket
#endif

#ifdef __linux__
#include <poll.h>
#include <unistd.h>
#define RAW_SOCKET int
#define BAD_SOCKET -1
#define POLL poll
#define CLOSE_SOCKET close
#endif

#ifndef HTTP_AMALGAMATION
#include "basic.h"
#endif

int  socket_raw_global_init(void);
void socket_raw_global_free(void);

int set_socket_blocking(RAW_SOCKET sock, bool value);

RAW_SOCKET listen_socket(HTTP_String addr, uint16_t port, bool reuse_addr, int backlog);

#endif // SOCKET_RAW_INCLUDED

////////////////////////////////////////////////////////////////////////////////////////
// src/socket.h
////////////////////////////////////////////////////////////////////////////////////////

#line 1 "src/socket.h"
#ifndef SOCKET_INCLUDED
#define SOCKET_INCLUDED

// This module implements the socket state machine to encapsulate
// the complexity of non-blocking TCP and TLS sockets.
//
// A socket is represented by the "Socket" structure, which may
// be in a number of states. As far as an user of the interface
// is concerned, the socket may be DIED, READY, or in an internal
// state that requires waiting for an event. Therefore, if the
// socket is not DIED or READY, the user needs to wait for the
// events specified in the [socket->events] field, then call the
// socket_update function. At some point the socket will become
// either READY or DIED.
//
// When the socket reaches the DIED state, the user must call
// socket_free.
//
// If the socket is ESTABLISHED_READY, the user may call socket_read,
// socket_write, or socket_close on it.

#ifndef HTTP_AMALGAMATION
#include "sec.h"
#include "parse.h"
#include "socket_raw.h"
#endif

typedef struct PendingConnect PendingConnect;

// These should only be relevant to socket.c
typedef enum {
    SOCKET_STATE_FREE,
    SOCKET_STATE_DIED,
    SOCKET_STATE_ESTABLISHED_WAIT,
    SOCKET_STATE_ESTABLISHED_READY,
    SOCKET_STATE_PENDING,
    SOCKET_STATE_ACCEPTED,
    SOCKET_STATE_CONNECTED,
    SOCKET_STATE_CONNECTING,
    SOCKET_STATE_SHUTDOWN,
} SocketState;

typedef struct {
    SocketState state;

    RAW_SOCKET raw;
    int events;

    void *user_data;
    PendingConnect *pending_connect;

#ifdef HTTPS_ENABLED
    SSL *ssl;
#endif

    SecureContext *sec;

} Socket;

void  socket_connect(Socket *sock, SecureContext *sec, HTTP_String hostname, uint16_t port, void *user_data);
void  socket_connect_ipv4(Socket *sock, SecureContext *sec, HTTP_IPv4 addr, uint16_t port, void *user_data);
void  socket_connect_ipv6(Socket *sock, SecureContext *sec, HTTP_IPv6 addr, uint16_t port, void *user_data);
void  socket_accept(Socket *sock, SecureContext *sec, RAW_SOCKET raw);
void  socket_update(Socket *sock);
void  socket_close(Socket *sock);
bool  socket_ready(Socket *sock);
bool  socket_died(Socket *sock);
int   socket_read(Socket *sock, char *dst, int max);
int   socket_write(Socket *sock, char *src, int len);
void  socket_free(Socket *sock);
bool  socket_secure(Socket *sock);
void  socket_set_user_data(Socket *sock, void *user_data);
void* socket_get_user_data(Socket *sock);

#endif // SOCKET_INCLUDED

////////////////////////////////////////////////////////////////////////////////////////
// src/socket_pool.h
////////////////////////////////////////////////////////////////////////////////////////

#line 1 "src/socket_pool.h"
#ifndef SOCKET_POOL_INCLUDED
#define SOCKET_POOL_INCLUDED

#ifndef HTTP_AMALGAMATION
#include "basic.h"
#include "socket.h"
#include "socket_raw.h"
#endif

typedef struct SocketPool SocketPool;

typedef int SocketHandle;

typedef enum {
    SOCKET_EVENT_DIED,
    SOCKET_EVENT_READY,
    SOCKET_EVENT_ERROR,
    SOCKET_EVENT_SIGNAL,
} SocketEventType;

typedef struct {
    SocketEventType type;
    SocketHandle handle;
    void *user_data;
} SocketEvent;

int  socket_pool_global_init(void);
void socket_pool_global_free(void);

SocketPool *socket_pool_init(HTTP_String addr,
    uint16_t port, uint16_t secure_port, int max_socks,
    bool reuse_addr, int backlog, HTTP_String cert_file,
    HTTP_String key_file);

void socket_pool_free(SocketPool *pool);

int socket_pool_add_cert(SocketPool *pool, HTTP_String domain, HTTP_String cert_file, HTTP_String key_file);

SocketEvent socket_pool_wait(SocketPool *pool);

void socket_pool_set_user_data(SocketPool *pool, SocketHandle handle, void *user_data);

void socket_pool_close(SocketPool *pool, SocketHandle handle);

int socket_pool_connect(SocketPool *pool, bool secure,
    HTTP_String addr, uint16_t port, void *user_data);

int socket_pool_connect_ipv4(SocketPool *pool, bool secure,
    HTTP_IPv4 addr, uint16_t port, void *user_data);

int socket_pool_connect_ipv6(SocketPool *pool, bool secure,
    HTTP_IPv6 addr, uint16_t port, void *user_data);

int socket_pool_read(SocketPool *pool, SocketHandle handle, char *dst, int len);

int socket_pool_write(SocketPool *pool, SocketHandle handle, char *src, int len);

bool socket_pool_secure(SocketPool *pool, SocketHandle handle);

#endif // SOCKET_POOL_INCLUDED

////////////////////////////////////////////////////////////////////////////////////////
// src/basic.c
////////////////////////////////////////////////////////////////////////////////////////

#line 1 "src/basic.c"
#include <stddef.h>
#include <string.h>

#ifndef HTTP_AMALGAMATION
#include "basic.h"
#endif

bool http_streq(HTTP_String s1, HTTP_String s2)
{
	if (s1.len != s2.len)
		return false;

    for (int i = 0; i < s1.len; i++)
		if (s1.ptr[i] != s2.ptr[i])
			return false;

	return true;
}

static char to_lower(char c)
{
	if (c >= 'A' && c <= 'Z')
		return c - 'A' + 'a';
	return c;
}

bool http_streqcase(HTTP_String s1, HTTP_String s2)
{
	if (s1.len != s2.len)
		return false;

	for (int i = 0; i < s1.len; i++)
		if (to_lower(s1.ptr[i]) != to_lower(s2.ptr[i]))
			return false;

	return true;
}

HTTP_String http_trim(HTTP_String s)
{
	int i = 0;
	while (i < s.len && (s.ptr[i] == ' ' || s.ptr[i] == '\t'))
		i++;

	if (i == s.len) {
		s.ptr = NULL;
		s.len = 0;
	} else {
		s.ptr += i;
		s.len -= i;
		while (s.ptr[s.len-1] == ' ' || s.ptr[s.len-1] == '\t')
			s.len--;
	}

	return s;
}

static bool is_printable(char c)
{
    return c >= ' ' && c <= '~';
}

#include <stdio.h>
void print_bytes(HTTP_String prefix, HTTP_String src)
{
    if (src.len == 0)
        return;

    FILE *stream = stdout;

    bool new_line = true;
    int cur = 0;
    for (;;) {
        int start = cur;

        while (cur < src.len && is_printable(src.ptr[cur]))
            cur++;

        if (new_line) {
            fwrite(prefix.ptr, 1, prefix.len, stream);
            new_line = false;
        }

        fwrite(src.ptr + start, 1, cur - start, stream);

        if (cur == src.len)
            break;

        if (src.ptr[cur] == '\n') {
            putc('\\', stream);
            putc('n',  stream);
            putc('\n', stream);
            new_line = true;
        } else if (src.ptr[cur] == '\r') {
            putc('\\', stream);
            putc('r',  stream);
        } else {
            putc('.', stream);
        }
        cur++;
    }
    putc('\n', stream);
}

////////////////////////////////////////////////////////////////////////////////////////
// src/parse.c
////////////////////////////////////////////////////////////////////////////////////////

#line 1 "src/parse.c"
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <limits.h>

#ifndef HTTP_AMALGAMATION
#include "parse.h"
#include "basic.h"
#endif

// From RFC 9112
//   request-target = origin-form
//                  / absolute-form
//                  / authority-form
//                  / asterisk-form
//   origin-form    = absolute-path [ "?" query ]
//   absolute-form  = absolute-URI
//   authority-form = uri-host ":" port
//   asterisk-form  = "*"
//
// From RFC 9110
//   URI-reference = <URI-reference, see [URI], Section 4.1>
//   absolute-URI  = <absolute-URI, see [URI], Section 4.3>
//   relative-part = <relative-part, see [URI], Section 4.2>
//   authority     = <authority, see [URI], Section 3.2>
//   uri-host      = <host, see [URI], Section 3.2.2>
//   port          = <port, see [URI], Section 3.2.3>
//   path-abempty  = <path-abempty, see [URI], Section 3.3>
//   segment       = <segment, see [URI], Section 3.3>
//   query         = <query, see [URI], Section 3.4>
//
//   absolute-path = 1*( "/" segment )
//   partial-URI   = relative-part [ "?" query ]
//
// From RFC 3986:
//   segment       = *pchar
//   pchar         = unreserved / pct-encoded / sub-delims / ":" / "@"
//   pct-encoded   = "%" HEXDIG HEXDIG
//   sub-delims    = "!" / "$" / "&" / "'" / "(" / ")"
//                 / "*" / "+" / "," / ";" / "="
//   unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"
//   query         = *( pchar / "/" / "?" )
//   absolute-URI  = scheme ":" hier-part [ "?" query ]
//   hier-part     = "//" authority path-abempty
//                 / path-absolute
//                 / path-rootless
//                 / path-empty
//   scheme      = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )

typedef struct {
	char *src;
	int len;
	int cur;
} Scanner;

static int is_digit(char c)
{
	return c >= '0' && c <= '9';
}

static int is_alpha(char c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

static int is_hex_digit(char c)
{
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

// From RFC 3986:
//   sub-delims = "!" / "$" / "&" / "'" / "(" / ")"
//              / "*" / "+" / "," / ";" / "="
static int is_sub_delim(char c)
{
	return c == '!' || c == '$' || c == '&' || c == '\''
		|| c == '(' || c == ')' || c == '*' || c == '+'
		|| c == ',' || c == ';' || c == '=';
}

// From RFC 3986:
//   unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
static int is_unreserved(char c)
{
	return is_alpha(c) || is_digit(c)
		|| c == '-' || c == '.'
		|| c == '_' || c == '~';
}

// From RFC 3986:
//   pchar = unreserved / pct-encoded / sub-delims / ":" / "@"
static int is_pchar(char c)
{
	return is_unreserved(c) || is_sub_delim(c) || c == ':' || c == '@';
}

static int is_tchar(char c)
{
	return is_digit(c) || is_alpha(c)
		|| c == '!' || c == '#' || c == '$'
		|| c == '%' || c == '&' || c == '\''
		|| c == '*' || c == '+' || c == '-'
		|| c == '.' || c == '^' || c == '_'
		|| c == '~';
}

static int is_vchar(char c)
{
	return c >= ' ' && c <= '~';
}

#define CONSUME_OPTIONAL_SEQUENCE(scanner, func)                                        \
    while ((scanner)->cur < (scanner)->len && (func)((scanner)->src[(scanner)->cur]))   \
        (scanner)->cur++;

static int
consume_absolute_path(Scanner *s)
{
	if (s->cur == s->len || s->src[s->cur] != '/')
		return -1; // ERROR
	s->cur++;

	for (;;) {

        CONSUME_OPTIONAL_SEQUENCE(s, is_pchar);

		if (s->cur == s->len || s->src[s->cur] != '/')
			break;
		s->cur++;
	}

	return 0;
}

// If abempty=1:
//   path-abempty  = *( "/" segment )
// else:
//   path-absolute = "/" [ segment-nz *( "/" segment ) ]
//   path-rootless = segment-nz *( "/" segment )
//   path-empty    = 0<pchar>
static int parse_path(Scanner *s, HTTP_String *path, int abempty)
{
	int start = s->cur;

	if (abempty) {

		// path-abempty
		while (s->cur < s->len && s->src[s->cur] == '/') {
			do
				s->cur++;
			while (s->cur < s->len && is_pchar(s->src[s->cur]));
		}

	} else if (s->cur < s->len && (s->src[s->cur] == '/')) {

		// path-absolute
		s->cur++;
		if (s->cur < s->len && is_pchar(s->src[s->cur])) {
			s->cur++;
			for (;;) {

                CONSUME_OPTIONAL_SEQUENCE(s, is_pchar);

				if (s->cur == s->len || s->src[s->cur] != '/')
					break;
				s->cur++;
			}
		}

	} else if (s->cur < s->len && is_pchar(s->src[s->cur])) {

		// path-rootless
		s->cur++;
		for (;;) {

            CONSUME_OPTIONAL_SEQUENCE(s, is_pchar)

			if (s->cur == s->len || s->src[s->cur] != '/')
				break;
			s->cur++;
		}

	} else {
		// path->empty
		// (do nothing)
	}

	*path = (HTTP_String) {
		s->src + start,
		s->cur - start,
	};
	if (path->len == 0)
		path->ptr = NULL;

	return 0;
}

// RFC 3986:
//   query = *( pchar / "/" / "?" )
static int is_query(char c)
{
	return is_pchar(c) || c == '/' || c == '?';
}

// RFC 3986:
//   fragment = *( pchar / "/" / "?" )
static int is_fragment(char c)
{
	return is_pchar(c) || c == '/' || c == '?';
}

static int little_endian(void)
{
    uint16_t x = 1;
    return *((uint8_t*) &x);
}

static void invert_bytes(void *p, int len)
{
	char *c = p;
	for (int i = 0; i < len/2; i++) {
		char tmp = c[i];
		c[i] = c[len-i-1];
		c[len-i-1] = tmp;
	}
}

static int parse_ipv4(Scanner *s, HTTP_IPv4 *ipv4)
{
	unsigned int out = 0;
	int i = 0;
	for (;;) {

		if (s->cur == s->len || !is_digit(s->src[s->cur]))
			return -1;

		int b = 0;
		do {
			int x = s->src[s->cur++] - '0';
			if (b > (UINT8_MAX - x) / 10)
				return -1;
			b = b * 10 + x;
		} while (s->cur < s->len && is_digit(s->src[s->cur]));

		out <<= 8;
		out |= (unsigned char) b;

		i++;
		if (i == 4)
			break;

		if (s->cur == s->len || s->src[s->cur] != '.')
			return -1;
		s->cur++;
	}

	if (little_endian())
		invert_bytes(&out, 4);

	ipv4->data = out;
	return 0;
}

static int hex_digit_to_int(char c)
{
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	if (c >= '0' && c <= '9') return c - '0';
	return -1;
}

static int parse_ipv6_comp(Scanner *s)
{
	unsigned short buf;

	if (s->cur == s->len || !is_hex_digit(s->src[s->cur]))
		return -1;
	buf = hex_digit_to_int(s->src[s->cur]);
	s->cur++;

	if (s->cur == s->len || !is_hex_digit(s->src[s->cur]))
		return buf;
	buf <<= 4;
	buf |= hex_digit_to_int(s->src[s->cur]);
	s->cur++;

	if (s->cur == s->len || !is_hex_digit(s->src[s->cur]))
		return buf;
	buf <<= 4;
	buf |= hex_digit_to_int(s->src[s->cur]);
	s->cur++;

	if (s->cur == s->len || !is_hex_digit(s->src[s->cur]))
		return buf;
	buf <<= 4;
	buf |= hex_digit_to_int(s->src[s->cur]);
	s->cur++;

	return (int) buf;
}

static int parse_ipv6(Scanner *s, HTTP_IPv6 *ipv6)
{
	unsigned short head[8];
	unsigned short tail[8];
	int head_len = 0;
	int tail_len = 0;

	if (s->len - s->cur > 1
		&& s->src[s->cur+0] == ':'
		&& s->src[s->cur+1] == ':')
		s->cur += 2;
	else {

		for (;;) {

			int ret = parse_ipv6_comp(s);
			if (ret < 0) return ret;

			head[head_len++] = (unsigned short) ret;
			if (head_len == 8) break;

			if (s->cur == s->len || s->src[s->cur] != ':')
				return -1;
			s->cur++;

			if (s->cur < s->len && s->src[s->cur] == ':') {
				s->cur++;
				break;
			}
		}
	}

	if (head_len < 8) {
		while (s->cur < s->len && is_hex_digit(s->src[s->cur])) {

			int ret = parse_ipv6_comp(s);
			if (ret < 0) return ret;

			tail[tail_len++] = (unsigned short) ret;
			if (head_len + tail_len == 8) break;

			if (s->cur == s->len || s->src[s->cur] != ':')
				break;
			s->cur++;
		}
	}

	for (int i = 0; i < head_len; i++)
		ipv6->data[i] = head[i];

	for (int i = 0; i < 8 - head_len - tail_len; i++)
		ipv6->data[head_len + i] = 0;

	for (int i = 0; i < tail_len; i++)
		ipv6->data[8 - tail_len + i] = tail[i];

	if (little_endian())
		for (int i = 0; i < 8; i++)
			invert_bytes(&ipv6->data[i], 2);

	return 0;
}

// From RFC 3986:
//   reg-name = *( unreserved / pct-encoded / sub-delims )
static int is_regname(char c)
{
	return is_unreserved(c) || is_sub_delim(c);
}

static int parse_regname(Scanner *s, HTTP_String *regname)
{
	if (s->cur == s->len || !is_regname(s->src[s->cur]))
		return -1;
	int start = s->cur;
	do
		s->cur++;
	while (s->cur < s->len && is_regname(s->src[s->cur]));
	regname->ptr = s->src + start;
	regname->len = s->cur - start;
	return 0;
}

static int parse_host(Scanner *s, HTTP_Host *host)
{
	int ret;
	if (s->cur < s->len && s->src[s->cur] == '[') {

		s->cur++;

		int start = s->cur;
		HTTP_IPv6 ipv6;
		ret = parse_ipv6(s, &ipv6);
		if (ret < 0) return ret;

		host->mode = HTTP_HOST_MODE_IPV6;
		host->ipv6 = ipv6;
		host->text = (HTTP_String) { s->src + start, s->cur - start };

		if (s->cur == s->len || s->src[s->cur] != ']')
			return -1;
		s->cur++;

	} else {

		int start = s->cur;
		HTTP_IPv4 ipv4;
		ret = parse_ipv4(s, &ipv4);
		if (ret >= 0) {
			host->mode = HTTP_HOST_MODE_IPV4;
			host->ipv4 = ipv4;
		} else {
			s->cur = start;

			HTTP_String regname;
			ret = parse_regname(s, &regname);
			if (ret < 0) return ret;

			host->mode = HTTP_HOST_MODE_NAME;
			host->name = regname;
		}
		host->text = (HTTP_String) { s->src + start, s->cur - start };
	}

	return 0;
}

// scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
static int is_scheme_head(char c)
{
	return is_alpha(c);
}

static int is_scheme_body(char c)
{
	return is_alpha(c)
		|| is_digit(c)
		|| c == '+'
		|| c == '-'
		|| c == '.';
}

// userinfo = *( unreserved / pct-encoded / sub-delims / ":" )
static int is_userinfo(char c)
{
	return is_unreserved(c) || is_sub_delim(c) || c == ':'; // TODO: PCT encoded
}

// authority = [ userinfo "@" ] host [ ":" port ]
static int parse_authority(Scanner *s, HTTP_Authority *authority)
{
	HTTP_String userinfo;
	{
		int start = s->cur;

        CONSUME_OPTIONAL_SEQUENCE(s, is_userinfo);

		if (s->cur < s->len && s->src[s->cur] == '@') {
			userinfo = (HTTP_String) {
				s->src + start,
				s->cur - start
			};
			s->cur++;
		} else {
			// Rollback
			s->cur = start;
			userinfo = (HTTP_String) {NULL, 0};
		}
	}

	HTTP_Host host;
	{
		int ret = parse_host(s, &host);
		if (ret < 0)
			return ret;
	}

	int port = 0;
	if (s->cur < s->len && s->src[s->cur] == ':') {
		s->cur++;
		if (s->cur < s->len && is_digit(s->src[s->cur])) {
			port = s->src[s->cur++] - '0';
			while (s->cur < s->len && is_digit(s->src[s->cur])) {
				int x = s->src[s->cur++] - '0';
				if (port > (UINT16_MAX - x) / 10)
					return -1; // ERROR: Port too big
				port = port * 10 + x;
			}
		}
	}

	authority->userinfo = userinfo;
	authority->host = host;
	authority->port = port;
	return 0;
}

static int parse_uri(Scanner *s, HTTP_URL *url, int allow_fragment)
{
	HTTP_String scheme = {0};
	{
		int start = s->cur;
		if (s->cur == s->len || !is_scheme_head(s->src[s->cur]))
			return -1; // ERROR: Missing scheme
		do
			s->cur++;
		while (s->cur < s->len && is_scheme_body(s->src[s->cur]));
		scheme = (HTTP_String) {
			s->src + start,
			s->cur - start,
		};

		if (s->cur == s->len || s->src[s->cur] != ':') 
			return -1; // ERROR: Missing ':' after scheme
		s->cur++;
	}

	int abempty = 0;
	HTTP_Authority authority = {0};
	if (s->len - s->cur > 1
		&& s->src[s->cur+0] == '/'
		&& s->src[s->cur+1] == '/') {

		s->cur += 2;

		int ret = parse_authority(s, &authority);
		if (ret < 0) return ret;

		abempty = 1;
	}

	HTTP_String path;
	int ret = parse_path(s, &path, abempty);
	if (ret < 0) return ret;

	HTTP_String query = {0};
	if (s->cur < s->len && s->src[s->cur] == '?') {
		int start = s->cur;
		do
			s->cur++;
		while (s->cur < s->len && is_query(s->src[s->cur]));
		query = (HTTP_String) {
			s->src + start,
			s->cur - start,
		};
	}

	HTTP_String fragment = {0};
	if (allow_fragment && s->cur < s->len && s->src[s->cur] == '#') {
		int start = s->cur;
		do
			s->cur++;
		while (s->cur < s->len && is_fragment(s->src[s->cur]));
		fragment = (HTTP_String) {
			s->src + start,
			s->cur - start,
		};
	}

	url->scheme    = scheme;
	url->authority = authority;
	url->path      = path;
	url->query     = query;
	url->fragment  = fragment;

	return 1;
}

// authority-form = host ":" port
// host           = IP-literal / IPv4address / reg-name
// IP-literal    = "[" ( IPv6address / IPvFuture  ) "]"
// reg-name      = *( unreserved / pct-encoded / sub-delims )
static int parse_authority_form(Scanner *s, HTTP_Host *host, int *port)
{
	int ret;
	
	ret = parse_host(s, host);
	if (ret < 0) return ret;

	// Default port value
	*port = 0;

	if (s->cur == s->len || s->src[s->cur] != ':')
		return 0; // No port
	s->cur++;

	if (s->cur == s->len || !is_digit(s->src[s->cur]))
		return 0; // No port

	int buf = 0;
	do {
		int x = s->src[s->cur++] - '0';
		if (buf > (UINT16_MAX - x) / 10)
			return -1; // ERROR
		buf = buf * 10 + x;
	} while (s->cur < s->len && is_digit(s->src[s->cur]));

	*port = buf;
	return 0;
}

static int parse_origin_form(Scanner *s, HTTP_String *path, HTTP_String *query)
{
	int ret, start;

	start = s->cur;
	ret = consume_absolute_path(s);
	if (ret < 0) return ret;
	*path = (HTTP_String) { s->src + start, s->cur - start };

	if (s->cur < s->len && s->src[s->cur] == '?') {
		start = s->cur;
		do
			s->cur++;
		while (s->cur < s->len && is_query(s->src[s->cur]));
		*query = (HTTP_String) { s->src + start, s->cur - start };
	} else
		*query = (HTTP_String) { NULL, 0 };

	return 0;
}

static int parse_asterisk_form(Scanner *s)
{
	if (s->len - s->cur < 2
		|| s->src[s->cur+0] != '*'
		|| s->src[s->cur+1] != ' ')
		return -1;
	s->cur++;
	return 0;
}

static int parse_request_target(Scanner *s, HTTP_URL *url)
{
	int ret;

	memset(url, 0, sizeof(HTTP_URL));

	// asterisk-form
	ret = parse_asterisk_form(s);
	if (ret >= 0) return ret;

	ret = parse_uri(s, url, 0);
	if (ret >= 0) return ret;

	ret = parse_authority_form(s, &url->authority.host, &url->authority.port);
	if (ret >= 0) return ret;

	ret = parse_origin_form(s, &url->path, &url->query);
	if (ret >= 0) return ret;

	return -1;
}

bool consume_str(Scanner *scan, HTTP_String token)
{
    HTTP_ASSERT(token.len > 0);

    if (token.len > scan->len - scan->cur)
        return false;

    for (int i = 0; i < token.len; i++)
        if (scan->src[scan->cur + i] != token.ptr[i])
            return false;

    scan->cur += token.len;
    return true;
}

static int is_header_body(char c)
{
	return is_vchar(c) || c == ' ' || c == '\t';
}

static int parse_headers(Scanner *s, HTTP_Header *headers, int max_headers)
{
	int num_headers = 0;
    while (!consume_str(s, HTTP_STR("\r\n"))) {

        // RFC 9112:
		//   field-line = field-name ":" OWS field-value OWS
		//
		// RFC 9110:
		//   field-value    = *field-content
		//   field-content  = field-vchar
		//                    [ 1*( SP / HTAB / field-vchar ) field-vchar ]
		//   field-vchar    = VCHAR / obs-text
		//   obs-text       = %x80-FF

		int start;
		
		if (s->cur == s->len || !is_tchar(s->src[s->cur]))
			return -1; // ERROR
		start = s->cur;
		do
			s->cur++;
		while (s->cur < s->len && is_tchar(s->src[s->cur]));
		HTTP_String name = { s->src + start, s->cur - start };

		if (s->cur == s->len || s->src[s->cur] != ':')
			return -1; // ERROR
		s->cur++;

        start = s->cur;
        CONSUME_OPTIONAL_SEQUENCE(s, is_header_body);
		HTTP_String body = { s->src + start, s->cur - start };
		body = http_trim(body);

        if (num_headers < max_headers)
            headers[num_headers++] = (HTTP_Header) { name, body };

        if (!consume_str(s, HTTP_STR("\r\n"))) {
            return -1;
        }
    }

    return num_headers;
}

typedef enum {
    TRANSFER_ENCODING_OPTION_CHUNKED,
    TRANSFER_ENCODING_OPTION_COMPRESS,
    TRANSFER_ENCODING_OPTION_DEFLATE,
    TRANSFER_ENCODING_OPTION_GZIP,
} TransferEncodingOption;

static bool is_space(char c)
{
    return c == ' ' || c == '\t';
}

static int
parse_transfer_encoding(HTTP_String src, TransferEncodingOption *dst, int max)
{
    Scanner s = { src.ptr, src.len, 0 };

    int num = 0;
    for (;;) {
        
        CONSUME_OPTIONAL_SEQUENCE(&s, is_space);

        TransferEncodingOption opt;
        if (0) {}
        else if (consume_str(&s, HTTP_STR("chunked")))  opt = TRANSFER_ENCODING_OPTION_CHUNKED;
        else if (consume_str(&s, HTTP_STR("compress"))) opt = TRANSFER_ENCODING_OPTION_COMPRESS;
        else if (consume_str(&s, HTTP_STR("deflate")))  opt = TRANSFER_ENCODING_OPTION_DEFLATE;
        else if (consume_str(&s, HTTP_STR("gzip")))     opt = TRANSFER_ENCODING_OPTION_GZIP;
        else return -1; // Invalid option

        if (num == max)
            return -1; // Too many options
        dst[num++] = opt;

        CONSUME_OPTIONAL_SEQUENCE(&s, is_space);

        if (s.cur == s.len)
            break;

        if (s.src[s.cur] != ',')
            return -1; // Missing comma separator
    }

    return num;
}

static int
parse_content_length(const char *src, int len, uint64_t *out)
{
    int cur = 0;
    while (cur < len && (src[cur] == ' ' || src[cur] == '\t'))
        cur++;

    if (cur == len || !is_digit(src[cur]))
        return -1;

    uint64_t buf = 0;
    do {
        int d = src[cur++] - '0';
        if (buf > (UINT64_MAX - d) / 10)
            return -1;
        buf = buf * 10 + d;
    } while (cur < len && is_digit(src[cur]));

    *out = buf;
    return 0;
}

static int parse_body(Scanner *s,
    HTTP_Header *headers, int num_headers,
    HTTP_String *body, bool body_expected)
{

    // RFC 9112 section 6:
    //   The presence of a message body in a request is signaled by a Content-Length or
    //   Transfer-Encoding header field. Request message framing is independent of method
    //   semantics.

    int header_index = http_find_header(headers, num_headers, HTTP_STR("Transfer-Encoding"));
    if (header_index != -1) {

        // RFC 9112 section 6.1:
        //   A server MAY reject a request that contains both Content-Length and Transfer-Encoding
        //   or process such a request in accordance with the Transfer-Encoding alone. Regardless,
        //   the server MUST close the connection after responding to such a request to avoid the
        //   potential attacks.
        if (http_find_header(headers, num_headers, HTTP_STR("Content-Length")) != -1)
            return -1;

        HTTP_String value = headers[header_index].value;

        // RFC 9112 section 6.1:
        //   If any transfer coding other than chunked is applied to a request's content, the
        //   sender MUST apply chunked as the final transfer coding to ensure that the message
        //   is properly framed. If any transfer coding other than chunked is applied to a
        //   response's content, the sender MUST either apply chunked as the final transfer
        //   coding or terminate the message by closing the connection.

        TransferEncodingOption opts[8];
        int num = parse_transfer_encoding(value, opts, HTTP_COUNT(opts));
        if (num != 1 || opts[0] != TRANSFER_ENCODING_OPTION_CHUNKED)
            return -1;

        HTTP_String chunks_maybe[128];
        HTTP_String *chunks = chunks_maybe;
        int num_chunks = 0;
        int max_chunks = HTTP_COUNT(chunks_maybe);

        #define FREE_CHUNK_LIST         \
            if (chunks != chunks_maybe) \
                free(chunks);

        char *content_start = s->src + s->cur;

        for (;;) {

            // RFC 9112 section 7.1:
            //   The chunked transfer coding wraps content in order to transfer it as a series of chunks,
            //   each with its own size indicator, followed by an OPTIONAL trailer section containing
            //   trailer fields.

            if (s->cur == s->len) {
                FREE_CHUNK_LIST
                return 0; // Incomplete request
            }

            if (!is_hex_digit(s->src[s->cur])) {
                FREE_CHUNK_LIST
                return -1;
            }

            int chunk_len = 0;

            do {
                char c = s->src[s->cur++];
                int  n = hex_digit_to_int(c);
                if (chunk_len > (INT_MAX - n) / 16) {
                    FREE_CHUNK_LIST
                    return -1; // overflow
                }
                chunk_len = chunk_len * 16 + n;
            } while (s->cur < s->len && is_hex_digit(s->src[s->cur]));

            if (s->cur == s->len) {
                FREE_CHUNK_LIST
                return 0; // Incomplete request
            }
            if (s->src[s->cur] != '\r') {
                FREE_CHUNK_LIST
                return -1;
            }
            s->cur++;

            if (s->cur == s->len) {
                FREE_CHUNK_LIST
                return 0;
            }
            if (s->src[s->cur] != '\n') {
                FREE_CHUNK_LIST
                return -1;
            }
            s->cur++;

            char *chunk_ptr = s->src + s->cur;

            if (chunk_len > s->len - s->cur) {
                FREE_CHUNK_LIST
                return 0; // Incomplete request
            }
            s->cur += chunk_len;

            if (s->cur == s->len)
                return 0; // Incomplete request
            if (s->src[s->cur] != '\r') {
                FREE_CHUNK_LIST
                return -1;
            }
            s->cur++;

            if (s->cur == s->len) {
                FREE_CHUNK_LIST
                return 0; // Incomplete request
            }
            if (s->src[s->cur] != '\n') {
                FREE_CHUNK_LIST
                return -1;
            }
            s->cur++;

            if (chunk_len == 0)
                break;

            if (num_chunks == max_chunks) {

                max_chunks *= 2;

                HTTP_String *new_chunks = malloc(max_chunks * sizeof(HTTP_String));
                if (new_chunks == NULL) {
                    if (chunks != chunks_maybe)
                        free(chunks);
                    return -1;
                }

                for (int i = 0; i < num_chunks; i++)
                    new_chunks[i] = chunks[i];

                if (chunks != chunks_maybe)
                    free(chunks);

                chunks = new_chunks;
            }
            chunks[num_chunks++] = (HTTP_String) { chunk_ptr, chunk_len };
        }

        char *content_ptr = content_start;
        for (int i = 0; i < num_chunks; i++) {
            memmove(content_ptr, chunks[i].ptr, chunks[i].len);
            content_ptr += chunks[i].len;
        }

        *body = (HTTP_String) {
            content_start,
            content_ptr - content_start
        };

        if (chunks != chunks_maybe)
            free(chunks);

        return 1;
    }

    // RFC 9112 section 6.3:
    //   If a valid Content-Length header field is present without Transfer-Encoding,
    //   its decimal value defines the expected message body length in octets.

    header_index = http_find_header(headers, num_headers, HTTP_STR("Content-Length"));
    if (header_index != -1) {

        // Have Content-Length
        HTTP_String value = headers[header_index].value;

        uint64_t tmp;
        if (parse_content_length(value.ptr, value.len, &tmp) < 0)
            return -1;
        if (tmp > INT_MAX)
            return -1;
        int len = (int) tmp;

        if (len > s->len - s->cur)
            return 0; // Incomplete request

        *body = (HTTP_String) { s->src + s->cur, len };

        s->cur += len;
        return 1;
    }

    // No Content-Length or Transfer-Encoding
    if (body_expected) return -1;

    *body = (HTTP_String) { NULL, 0 };
    return 1;
}

static int contains_head(char *src, int len)
{
    int cur = 0;
    while (len - cur > 3) {
        if (src[cur+0] == '\r' &&
            src[cur+1] == '\n' &&
            src[cur+2] == '\r' &&
            src[cur+3] == '\n')
            return 1;
        cur++;
    }
    return 0;
}

static int parse_request(Scanner *s, HTTP_Request *req)
{
    if (!contains_head(s->src + s->cur, s->len - s->cur))
        return 0;

    req->secure = false;

    if (0) {}
    else if (consume_str(s, HTTP_STR("GET ")))     req->method = HTTP_METHOD_GET;
    else if (consume_str(s, HTTP_STR("POST ")))    req->method = HTTP_METHOD_POST;
    else if (consume_str(s, HTTP_STR("PUT ")))     req->method = HTTP_METHOD_PUT;
    else if (consume_str(s, HTTP_STR("HEAD ")))    req->method = HTTP_METHOD_HEAD;
    else if (consume_str(s, HTTP_STR("DELETE ")))  req->method = HTTP_METHOD_DELETE;
    else if (consume_str(s, HTTP_STR("CONNECT "))) req->method = HTTP_METHOD_CONNECT;
    else if (consume_str(s, HTTP_STR("OPTIONS "))) req->method = HTTP_METHOD_OPTIONS;
    else if (consume_str(s, HTTP_STR("TRACE ")))   req->method = HTTP_METHOD_TRACE;
    else if (consume_str(s, HTTP_STR("PATCH ")))   req->method = HTTP_METHOD_PATCH;
    else return -1;

    {
        Scanner s2 = *s;
        int peek = s->cur;
        while (peek < s->len && s->src[peek] != ' ')
            peek++;
        if (peek == s->len)
            return -1;
        s2.len = peek;

        int ret = parse_request_target(&s2, &req->url);
        if (ret < 0) return ret;

        s->cur = s2.cur;
    }

    if (consume_str(s, HTTP_STR(" HTTP/1.1\r\n"))) {
        req->minor = 1;
    } else if (consume_str(s, HTTP_STR(" HTTP/1.0\r\n")) || consume_str(s, HTTP_STR(" HTTP/1\r\n"))) {
        req->minor = 0;
    } else {
        return -1;
    }

    int num_headers = parse_headers(s, req->headers, HTTP_MAX_HEADERS);
    if (num_headers < 0)
        return num_headers;
    req->num_headers = num_headers;

    bool body_expected = true;
    if (req->method == HTTP_METHOD_GET || req->method == HTTP_METHOD_DELETE) // TODO: maybe other methods?
        body_expected = false;

    return parse_body(s, req->headers, req->num_headers, &req->body, body_expected);
}

int http_find_header(HTTP_Header *headers, int num_headers, HTTP_String name)
{
	for (int i = 0; i < num_headers; i++)
		if (http_streqcase(name, headers[i].name))
			return i;
	return -1;
}

static int parse_response(Scanner *s, HTTP_Response *res)
{
	if (!contains_head(s->src + s->cur, s->len - s->cur))
		return 0;

    if (consume_str(s, HTTP_STR("HTTP/1.1 "))) {
        res->minor = 1;
    } else if (consume_str(s, HTTP_STR("HTTP/1.0 ")) || consume_str(s, HTTP_STR("HTTP/1 "))) {
        res->minor = 0;
    } else {
        return -1;
    }

    if (s->len - s->cur < 5
        || s->src[s->cur+0] != ' '
        || !is_digit(s->src[s->cur+1])
        || !is_digit(s->src[s->cur+2])
        || !is_digit(s->src[s->cur+3])
        || s->src[s->cur+4] != ' ')
        return -1;
    s->cur += 5;

    res->status =
        (s->src[s->cur-2] - '0') * 1 +
        (s->src[s->cur-3] - '0') * 10 +
        (s->src[s->cur-4] - '0') * 100;

    while (s->cur < s->len && (
        s->src[s->cur] == '\t' ||
        s->src[s->cur] == ' ' ||
        is_vchar(s->src[s->cur]))) // TODO: obs-text
        s->cur++;

    if (s->len - s->cur < 2
        || s->src[s->cur+0] != '\r'
        || s->src[s->cur+1] != '\n')
        return -1;
    s->cur += 2;

    int num_headers = parse_headers(s, res->headers, HTTP_MAX_HEADERS);
    if (num_headers < 0)
        return num_headers;
    res->num_headers = num_headers;

    bool body_expected = true; // TODO

    return parse_body(s, res->headers, res->num_headers, &res->body, body_expected);
}

int http_parse_ipv4(char *src, int len, HTTP_IPv4 *ipv4)
{
    Scanner s = {src, len, 0};
    int ret = parse_ipv4(&s, ipv4);
    if (ret < 0) return ret;
    return s.cur;
}

int http_parse_ipv6(char *src, int len, HTTP_IPv6 *ipv6)
{
    Scanner s = {src, len, 0};
    int ret = parse_ipv6(&s, ipv6);
    if (ret < 0) return ret;
    return s.cur;
}

int http_parse_url(char *src, int len, HTTP_URL *url)
{
    Scanner s = {src, len, 0};
    int ret = parse_uri(&s, url, 1);
    if (ret == 1)
        return s.cur;
    return ret;
}

int http_parse_request(char *src, int len, HTTP_Request *req)
{
    Scanner s = {src, len, 0};
    int ret = parse_request(&s, req);
    if (ret == 1)
        return s.cur;
    return ret;
}

int http_parse_response(char *src, int len, HTTP_Response *res)
{
    Scanner s = {src, len, 0};
    int ret = parse_response(&s, res);
    if (ret == 1)
        return s.cur;
    return ret;
}

HTTP_String http_get_cookie(HTTP_Request *req, HTTP_String name)
{
    // TODO: best-effort implementation

    for (int i = 0; i < req->num_headers; i++) {

        if (!http_streqcase(req->headers[i].name, HTTP_STR("Cookie")))
            continue;

        char *src = req->headers[i].value.ptr;
        int   len = req->headers[i].value.len;
        int   cur = 0;

        // Cookie: name1=value1; name2=value2; name3=value3

        for (;;) {

            while (cur < len && src[cur] == ' ')
                cur++;

            int off = cur;
            while (cur < len && src[cur] != '=')
                cur++;

            HTTP_String cookie_name = { src + off, cur - off };

            if (cur == len)
                break;
            cur++;

            off = cur;
            while (cur < len && src[cur] != ';')
                cur++;

            HTTP_String cookie_value = { src + off, cur - off };

            if (http_streq(name, cookie_name))
                return cookie_value;

            if (cur == len)
                break;
            cur++;
        }
    }

    return HTTP_STR("");
}

HTTP_String http_get_param(HTTP_String body, HTTP_String str, char *mem, int cap)
{
    // This is just a best-effort implementation

    char *src = body.ptr;
    int   len = body.len;
    int   cur = 0;

    if (cur < len && src[cur] == '?')
        cur++;

    while (cur < len) {

        HTTP_String name;
        {
            int off = cur;
            while (cur < len && src[cur] != '=' && src[cur] != '&')
                cur++;
            name = (HTTP_String) { src + off, cur - off };
        }

        HTTP_String body = HTTP_STR("");
        if (cur < len) {
            cur++;
            if (src[cur-1] == '=') {
                int off = cur;
                while (cur < len && src[cur] != '&')
                    cur++;
                body = (HTTP_String) { src + off, cur - off };

                if (cur < len)
                    cur++;
            }
        }

        if (http_streq(str, name)) {

            bool percent_encoded = false;
            for (int i = 0; i < body.len; i++)
                if (body.ptr[i] == '+' || body.ptr[i] == '%') {
                    percent_encoded = true;
                    break;
                }

            if (!percent_encoded)
                return body;

            if (body.len > cap)
                return (HTTP_String) { NULL, 0 };

            HTTP_String decoded = { mem, 0 };
            for (int i = 0; i < body.len; i++) {

                char c = body.ptr[i];
                if (c == '+')
                    c = ' ';
                else {
                    if (body.ptr[i] == '%') {
                        if (body.len - i < 3
                            || !is_hex_digit(body.ptr[i+1])
                            || !is_hex_digit(body.ptr[i+2]))
                            return (HTTP_String) { NULL, 0 };

                        int h = hex_digit_to_int(body.ptr[i+1]);
                        int l = hex_digit_to_int(body.ptr[i+2]);
                        c = (h << 4) | l;

                        i += 2;
                    }
                }

                decoded.ptr[decoded.len++] = c;
            }

            return decoded;
        }
    }

    return HTTP_STR("");
}

int http_get_param_i(HTTP_String body, HTTP_String str)
{
    char buf[128];
    HTTP_String out = http_get_param(body, str, buf, (int) sizeof(buf));
    if (out.len == 0 || !is_digit(out.ptr[0]))
        return -1;

    int cur = 0;
    int res = 0;
    do {
        int d = out.ptr[cur++] - '0';
        if (res > (INT_MAX - d) / 10)
            return -1;
        res = res * 10 + d;
    } while (cur < out.len && is_digit(out.ptr[cur]));

    return res;
}

////////////////////////////////////////////////////////////////////////////////////////
// src/engine.c
////////////////////////////////////////////////////////////////////////////////////////

#line 1 "src/engine.c"
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h> // TODO: remove some of these headers
#include <stddef.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>

#ifndef HTTP_AMALGAMATION
#include "basic.h"
#include "engine.h"
#endif

// This is the implementation of a byte queue useful
// for systems that need to process engs of bytes.
//
// It features sticky errors, a zero-copy interface,
// and a safe mechanism to patch previously written
// bytes.
//
// Only up to 4GB of data can be stored at once.

enum {
	BYTE_QUEUE_ERROR = 1 << 0,
	BYTE_QUEUE_READ  = 1 << 1,
	BYTE_QUEUE_WRITE = 1 << 2,
};

static void*
callback_malloc(HTTP_ByteQueue *queue, int len)
{
	return queue->memfunc(HTTP_MEMFUNC_MALLOC, NULL, len, queue->memfuncdata);
}

static void
callback_free(HTTP_ByteQueue *queue, void *ptr, int len)
{
	queue->memfunc(HTTP_MEMFUNC_FREE, ptr, len, queue->memfuncdata);
}

// Initialize the queue
static void
byte_queue_init(HTTP_ByteQueue *queue, unsigned int limit, HTTP_MemoryFunc memfunc, void *memfuncdata)
{
	queue->flags = 0;
	queue->head = 0;
	queue->size = 0;
	queue->used = 0;
	queue->curs = 0;
	queue->limit = limit;
	queue->data = NULL;
	queue->read_target = NULL;
	queue->memfunc = memfunc;
	queue->memfuncdata = memfuncdata;
}

// Deinitialize the queue
static void
byte_queue_free(HTTP_ByteQueue *queue)
{
	if (queue->read_target) {
		if (queue->read_target != queue->data)
			callback_free(queue, queue->read_target, queue->read_target_size);
		queue->read_target = NULL;
		queue->read_target_size = 0;
	}

	callback_free(queue, queue->data, queue->size);
	queue->data = NULL;
}

static int
byte_queue_error(HTTP_ByteQueue *queue)
{
	return queue->flags & BYTE_QUEUE_ERROR;
}

static int
byte_queue_empty(HTTP_ByteQueue *queue)
{
	return queue->used == 0;
}

// Start a read operation on the queue.
//
// This function returnes the pointer to the memory region containing the bytes
// to read. Callers can't read more than [*len] bytes from it. To complete the
// read, the [byte_queue_read_ack] function must be called with the number of
// bytes that were acknowledged by the caller.
//
// Note:
//   - You can't have more than one pending read.
static char*
byte_queue_read_buf(HTTP_ByteQueue *queue, int *len)
{
	if (queue->flags & BYTE_QUEUE_ERROR) {
		*len = 0;
		return NULL;
	}

	HTTP_ASSERT((queue->flags & BYTE_QUEUE_READ) == 0);
	queue->flags |= BYTE_QUEUE_READ;
	queue->read_target      = queue->data;
	queue->read_target_size = queue->size;

	*len = queue->used;
	if (queue->data == NULL)
		return NULL;
	return queue->data + queue->head;
}

// Complete a previously started operation on the queue.
static void
byte_queue_read_ack(HTTP_ByteQueue *queue, int num)
{
	HTTP_ASSERT(num >= 0);

	if (queue->flags & BYTE_QUEUE_ERROR)
		return;

	if ((queue->flags & BYTE_QUEUE_READ) == 0)
		return;

	queue->flags &= ~BYTE_QUEUE_READ;

	HTTP_ASSERT((unsigned int) num <= queue->used);
	queue->head += (unsigned int) num;
	queue->used -= (unsigned int) num;
	queue->curs += (unsigned int) num;

	if (queue->read_target) {
		if (queue->read_target != queue->data)
			callback_free(queue, queue->read_target, queue->read_target_size);
		queue->read_target = NULL;
		queue->read_target_size = 0;
	}
}

static char*
byte_queue_write_buf(HTTP_ByteQueue *queue, int *cap)
{
	if ((queue->flags & BYTE_QUEUE_ERROR) || queue->data == NULL) {
		*cap = 0;
		return NULL;
	}

	HTTP_ASSERT((queue->flags & BYTE_QUEUE_WRITE) == 0);
	queue->flags |= BYTE_QUEUE_WRITE;

	unsigned int ucap = queue->size - (queue->head + queue->used);
	if (ucap > INT_MAX) ucap = INT_MAX;

	*cap = (int) ucap;
	return queue->data + (queue->head + queue->used);
}

static void
byte_queue_write_ack(HTTP_ByteQueue *queue, int num)
{
	HTTP_ASSERT(num >= 0);

	if (queue->flags & BYTE_QUEUE_ERROR)
		return;

	if ((queue->flags & BYTE_QUEUE_WRITE) == 0)
		return;

	queue->flags &= ~BYTE_QUEUE_WRITE;
	queue->used += (unsigned int) num;
}

// Sets the minimum capacity for the next write operation
// and returns 1 if the content of the queue was moved, else
// 0 is returned.
//
// You must not call this function while a write is pending.
// In other words, you must do this:
//
//   byte_queue_write_setmincap(queue, mincap);
//   dst = byte_queue_write_buf(queue, &cap);
//   ...
//   byte_queue_write_ack(num);
//
// And NOT this:
//
//   dst = byte_queue_write_buf(queue, &cap);
//   byte_queue_write_setmincap(queue, mincap); <-- BAD
//   ...
//   byte_queue_write_ack(num);
//
static int
byte_queue_write_setmincap(HTTP_ByteQueue *queue, int mincap)
{
	HTTP_ASSERT(mincap >= 0);
	unsigned int umincap = (unsigned int) mincap;

	// Sticky error
	if (queue->flags & BYTE_QUEUE_ERROR)
		return 0;

	// In general, the queue's contents look like this:
	//
	//                           size
	//                           v
	//   [___xxxxxxxxxxxx________]
	//   ^   ^           ^
	//   0   head        head + used
	//
	// This function needs to make sure that at least [mincap]
	// bytes are available on the right side of the content.
	//
	// We have 3 cases:
	//
	//   1) If there is enough memory already, this function doesn't
	//      need to do anything.
	//
	//   2) If there isn't enough memory on the right but there is
	//      enough free memory if we cound the left unused region,
	//      then the content is moved back to the
	//      start of the buffer.
	//
	//   3) If there isn't enough memory considering both sides, this
	//      function needs to allocate a new buffer.
	//
	// If there are pending read or write operations, the application
	// is holding pointers to the buffer, so we need to make sure
	// to not invalidate them. The only real problem is pending reads
	// since this function can only be called before starting a write
	// opearation.
	//
	// To avoid invalidating the read pointer when we allocate a new
	// buffer, we don't free the old buffer. Instead, we store the
	// pointer in the "old" field so that the read ack function can
	// free it.
	//
	// To avoid invalidating the pointer when we are moving back the
	// content since there is enough memory at the start of the buffer,
	// we just avoid that. Even if there is enough memory considering
	// left and right free regions, we allocate a new buffer.

	HTTP_ASSERT((queue->flags & BYTE_QUEUE_WRITE) == 0);

	unsigned int total_free_space = queue->size - queue->used;
	unsigned int free_space_after_data = queue->size - queue->used - queue->head;

	int moved = 0;
	if (free_space_after_data < umincap) {

		if (total_free_space < umincap || (queue->read_target == queue->data)) {
			// Resize required

			if (queue->used + umincap > queue->limit) {
				queue->flags |= BYTE_QUEUE_ERROR;
				return 0;
			}

			unsigned int size;
			if (queue->size > UINT32_MAX / 2)
				size = UINT32_MAX;
			else
				size = 2 * queue->size;

			if (size < queue->used + umincap)
				size = queue->used + umincap;

			if (size > queue->limit)
				size = queue->limit;

			char *data = callback_malloc(queue, size);
			if (!data) {
				queue->flags |= BYTE_QUEUE_ERROR;
				return 0;
			}

			if (queue->used > 0)
				memcpy(data, queue->data + queue->head, queue->used);

			if (queue->read_target != queue->data)
				callback_free(queue, queue->data, queue->size);

			queue->data = data;
			queue->head = 0;
			queue->size = size;

		} else {
			// Move required
			memmove(queue->data, queue->data + queue->head, queue->used);
			queue->head = 0;
		}

		moved = 1;
	}

	return moved;
}

static HTTP_ByteQueueOffset
byte_queue_offset(HTTP_ByteQueue *queue)
{
	if (queue->flags & BYTE_QUEUE_ERROR)
		return (HTTP_ByteQueueOffset) { 0 };
	return (HTTP_ByteQueueOffset) { queue->curs + queue->used };
}

static unsigned int
byte_queue_size_from_offset(HTTP_ByteQueue *queue, HTTP_ByteQueueOffset off)
{
	return queue->curs + queue->used - off;
}

static void
byte_queue_patch(HTTP_ByteQueue *queue, HTTP_ByteQueueOffset off,
	char *src, unsigned int len)
{
	if (queue->flags & BYTE_QUEUE_ERROR)
		return;

	// Check that the offset is in range
	HTTP_ASSERT(off >= queue->curs && off - queue->curs < queue->used);

	// Check that the length is in range
	HTTP_ASSERT(len <= queue->used - (off - queue->curs));

	// Perform the patch
	char *dst = queue->data + queue->head + (off - queue->curs);
	memcpy(dst, src, len);
}

static void
byte_queue_remove_from_offset(HTTP_ByteQueue *queue, HTTP_ByteQueueOffset offset)
{
	if (queue->flags & BYTE_QUEUE_ERROR)
		return;

	unsigned long long num = (queue->curs + queue->used) - offset;
	HTTP_ASSERT(num <= queue->used);

	queue->used -= num;
}

static void
byte_queue_write(HTTP_ByteQueue *queue, const char *str, int len)
{
    if (str == NULL) str = "";
	if (len < 0) len = strlen(str);

	int cap;
	byte_queue_write_setmincap(queue, len);
	char *dst = byte_queue_write_buf(queue, &cap);
	if (dst) memcpy(dst, str, len);
	byte_queue_write_ack(queue, len);
}

static void
byte_queue_write_fmt2(HTTP_ByteQueue *queue, const char *fmt, va_list args)
{
	if (queue->flags & BYTE_QUEUE_ERROR)
		return;

	va_list args2;
	va_copy(args2, args);

	int cap;
	byte_queue_write_setmincap(queue, 128);
	char *dst = byte_queue_write_buf(queue, &cap);

	int len = vsnprintf(dst, cap, fmt, args);
	if (len < 0) {
		queue->flags |= BYTE_QUEUE_ERROR;
		va_end(args2);
		return;
	}

	if (len > cap) {
		byte_queue_write_ack(queue, 0);
		byte_queue_write_setmincap(queue, len+1);
		dst = byte_queue_write_buf(queue, &cap);
		vsnprintf(dst, cap, fmt, args2);
	}

	byte_queue_write_ack(queue, len);

	va_end(args2);
}

static void
byte_queue_write_fmt(HTTP_ByteQueue *queue, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	byte_queue_write_fmt2(queue, fmt, args);
	va_end(args);
}

#define TEN_SPACES "          "

void http_engine_init(HTTP_Engine *eng, int client, HTTP_MemoryFunc memfunc, void *memfuncdata)
{
	if (client)
		eng->state = HTTP_ENGINE_STATE_CLIENT_PREP_URL;
	else
		eng->state = HTTP_ENGINE_STATE_SERVER_RECV_BUF;

	eng->closing = 0;
	eng->numexch = 0;

	byte_queue_init(&eng->input,  1<<20, memfunc, memfuncdata);
	byte_queue_init(&eng->output, 1<<20, memfunc, memfuncdata);
}

void http_engine_free(HTTP_Engine *eng)
{
	byte_queue_free(&eng->input);
	byte_queue_free(&eng->output);
	eng->state = HTTP_ENGINE_STATE_NONE;
}

void http_engine_close(HTTP_Engine *eng)
{
	if (eng->state & HTTP_ENGINE_STATEBIT_CLIENT)
		eng->state = HTTP_ENGINE_STATE_CLIENT_CLOSED;
	else
		eng->state = HTTP_ENGINE_STATE_SERVER_CLOSED;
}

HTTP_EngineState http_engine_state(HTTP_Engine *eng)
{
	return eng->state;
}

const char* http_engine_statestr(HTTP_EngineState state) { // TODO: remove
    switch (state) {
        case HTTP_ENGINE_STATE_NONE: return "NONE";
        case HTTP_ENGINE_STATE_CLIENT_PREP_URL: return "CLIENT_PREP_URL";
        case HTTP_ENGINE_STATE_CLIENT_PREP_HEADER: return "CLIENT_PREP_HEADER";
        case HTTP_ENGINE_STATE_CLIENT_PREP_BODY_BUF: return "CLIENT_PREP_BODY_BUF";
        case HTTP_ENGINE_STATE_CLIENT_PREP_BODY_ACK: return "CLIENT_PREP_BODY_ACK";
        case HTTP_ENGINE_STATE_CLIENT_PREP_ERROR: return "CLIENT_PREP_ERROR";
        case HTTP_ENGINE_STATE_CLIENT_SEND_BUF: return "CLIENT_SEND_BUF";
        case HTTP_ENGINE_STATE_CLIENT_SEND_ACK: return "CLIENT_SEND_ACK";
        case HTTP_ENGINE_STATE_CLIENT_RECV_BUF: return "CLIENT_RECV_BUF";
        case HTTP_ENGINE_STATE_CLIENT_RECV_ACK: return "CLIENT_RECV_ACK";
        case HTTP_ENGINE_STATE_CLIENT_READY: return "CLIENT_READY";
        case HTTP_ENGINE_STATE_CLIENT_CLOSED: return "CLIENT_CLOSED";
        case HTTP_ENGINE_STATE_SERVER_RECV_BUF: return "SERVER_RECV_BUF";
        case HTTP_ENGINE_STATE_SERVER_RECV_ACK: return "SERVER_RECV_ACK";
        case HTTP_ENGINE_STATE_SERVER_PREP_STATUS: return "SERVER_PREP_STATUS";
        case HTTP_ENGINE_STATE_SERVER_PREP_HEADER: return "SERVER_PREP_HEADER";
        case HTTP_ENGINE_STATE_SERVER_PREP_BODY_BUF: return "SERVER_PREP_BODY_BUF";
        case HTTP_ENGINE_STATE_SERVER_PREP_BODY_ACK: return "SERVER_PREP_BODY_ACK";
        case HTTP_ENGINE_STATE_SERVER_PREP_ERROR: return "SERVER_PREP_ERROR";
        case HTTP_ENGINE_STATE_SERVER_SEND_BUF: return "SERVER_SEND_BUF";
        case HTTP_ENGINE_STATE_SERVER_SEND_ACK: return "SERVER_SEND_ACK";
        case HTTP_ENGINE_STATE_SERVER_CLOSED: return "SERVER_CLOSED";
        default: return "UNKNOWN";
    }
}

char *http_engine_recvbuf(HTTP_Engine *eng, int *cap)
{
	if ((eng->state & HTTP_ENGINE_STATEBIT_RECV_BUF) == 0) {
		*cap = 0;
		return NULL;
	}

	eng->state &= ~HTTP_ENGINE_STATEBIT_RECV_BUF;
	eng->state |=  HTTP_ENGINE_STATEBIT_RECV_ACK;

	byte_queue_write_setmincap(&eng->input, 1<<9);
	if (byte_queue_error(&eng->input)) {
		*cap = 0;
		if (eng->state & HTTP_ENGINE_STATEBIT_CLIENT)
			eng->state = HTTP_ENGINE_STATE_CLIENT_CLOSED;
		else
			eng->state = HTTP_ENGINE_STATE_SERVER_CLOSED;
		return NULL;
	}

	return byte_queue_write_buf(&eng->input, cap);
}

static int
should_keep_alive(HTTP_Engine *eng)
{
	HTTP_ASSERT(eng->state & HTTP_ENGINE_STATEBIT_PREP);

#if 0
	// If the parent system doesn't want us to reuse
	// the connection, we certainly can't keep alive.
	if ((eng->state & TINYHTTP_STREAM_REUSE) == 0)
		return 0;
#endif

	if (eng->numexch >= 100) // TODO: Make this a parameter
		return 0;

	HTTP_Request *req = &eng->result.req;

	// If the client is using HTTP/1.0, we can't
	// keep alive.
	if (req->minor == 0)
		return 0;

	// TODO: This assumes "Connection" can only hold a single token,
	//       but this is not true.
	int i = http_find_header(req->headers, req->num_headers, HTTP_STR("Connection"));
	if (i >= 0 && http_streqcase(req->headers[i].value, HTTP_STR("Close")))
		return 0;

	return 1;
}

static void process_incoming_request(HTTP_Engine *eng)
{
	HTTP_ASSERT(eng->state == HTTP_ENGINE_STATE_SERVER_RECV_ACK
		|| eng->state == HTTP_ENGINE_STATE_SERVER_SEND_ACK
		|| eng->state == HTTP_ENGINE_STATE_SERVER_PREP_BODY_BUF
		|| eng->state == HTTP_ENGINE_STATE_SERVER_PREP_ERROR);

	char *src;
	int len;
	src = byte_queue_read_buf(&eng->input, &len);

	int ret = http_parse_request(src, len, &eng->result.req);

	if (ret == 0) {
		byte_queue_read_ack(&eng->input, 0);
		eng->state = HTTP_ENGINE_STATE_SERVER_RECV_BUF;
		return;
	}

	if (ret < 0) {
		byte_queue_read_ack(&eng->input, 0);
		byte_queue_write(&eng->output,
			"HTTP/1.1 400 Bad Request\r\n"
			"Connection: Close\r\n"
			"Content-Length: 0\r\n"
			"\r\n", -1
		);
		if (byte_queue_error(&eng->output))
			eng->state = HTTP_ENGINE_STATE_SERVER_CLOSED;
		else {
			eng->closing = 1;
			eng->state = HTTP_ENGINE_STATE_SERVER_SEND_BUF;
		}
		return;
	}

	HTTP_ASSERT(ret > 0);

	eng->state = HTTP_ENGINE_STATE_SERVER_PREP_STATUS;
	eng->reqsize = ret;
	eng->keepalive = should_keep_alive(eng);
	eng->response_offset = byte_queue_offset(&eng->output);
}

void http_engine_recvack(HTTP_Engine *eng, int num)
{
	if ((eng->state & HTTP_ENGINE_STATEBIT_RECV_ACK) == 0)
		return;

	byte_queue_write_ack(&eng->input, num);

	if (eng->state & HTTP_ENGINE_STATEBIT_CLIENT) {
		
		char *src;
		int len;
		src = byte_queue_read_buf(&eng->input, &len);

		int ret = http_parse_response(src, len, &eng->result.res);

		if (ret == 0) {
			byte_queue_read_ack(&eng->input, 0);
			eng->state = HTTP_ENGINE_STATE_CLIENT_RECV_BUF;
			return;
		}

		if (ret < 0) {
			eng->state = HTTP_ENGINE_STATE_CLIENT_CLOSED;
			return;
		}

		HTTP_ASSERT(ret > 0);

		eng->state = HTTP_ENGINE_STATE_CLIENT_READY;

	} else {
		process_incoming_request(eng);
	}
}

char *http_engine_sendbuf(HTTP_Engine *eng, int *len)
{
	if ((eng->state & HTTP_ENGINE_STATEBIT_SEND_BUF) == 0) {
		*len = 0;
		return NULL;
	}

	eng->state &= ~HTTP_ENGINE_STATEBIT_SEND_BUF;
	eng->state |=  HTTP_ENGINE_STATEBIT_SEND_ACK;

	return byte_queue_read_buf(&eng->output, len);
}

void http_engine_sendack(HTTP_Engine *eng, int num)
{
	if (eng->state != HTTP_ENGINE_STATE_SERVER_SEND_ACK &&
		eng->state != HTTP_ENGINE_STATE_CLIENT_SEND_ACK)
		return;

	byte_queue_read_ack(&eng->output, num);

	if (eng->state & HTTP_ENGINE_STATEBIT_CLIENT) {
		if (byte_queue_empty(&eng->output))
			eng->state = HTTP_ENGINE_STATE_CLIENT_RECV_BUF;
		else
			eng->state = HTTP_ENGINE_STATE_CLIENT_SEND_BUF;
	} else {
		if (byte_queue_empty(&eng->output)) {
			if (!eng->closing && eng->keepalive)
				process_incoming_request(eng);
			else
				eng->state = HTTP_ENGINE_STATE_SERVER_CLOSED;
		} else
			eng->state = HTTP_ENGINE_STATE_SERVER_SEND_BUF;
	}
}

HTTP_Request *http_engine_getreq(HTTP_Engine *eng)
{
	if ((eng->state & HTTP_ENGINE_STATEBIT_REQUEST) == 0)
		return NULL;
	return &eng->result.req;
}

HTTP_Response *http_engine_getres(HTTP_Engine *eng)
{
	if ((eng->state & HTTP_ENGINE_STATEBIT_RESPONSE) == 0)
		return NULL;
	return &eng->result.res;
}

void http_engine_url(HTTP_Engine *eng, HTTP_Method method, HTTP_String url, int minor)
{
	if (eng->state != HTTP_ENGINE_STATE_CLIENT_PREP_URL)
		return;

	eng->response_offset = byte_queue_offset(&eng->output); // TODO: rename response_offset to something that makes sense for clients

	HTTP_URL parsed_url;
	int ret = http_parse_url(url.ptr, url.len, &parsed_url);
	if (ret != url.len) {
		eng->state = HTTP_ENGINE_STATE_CLIENT_PREP_ERROR;
		return;
	}

	HTTP_String method_and_space = HTTP_STR("???");
	switch (method) {
		case HTTP_METHOD_GET    : method_and_space = HTTP_STR("GET ");     break;
		case HTTP_METHOD_HEAD   : method_and_space = HTTP_STR("HEAD ");    break;
		case HTTP_METHOD_POST   : method_and_space = HTTP_STR("POST ");    break;
		case HTTP_METHOD_PUT    : method_and_space = HTTP_STR("PUT ");     break;
		case HTTP_METHOD_DELETE : method_and_space = HTTP_STR("DELETE ");  break;
		case HTTP_METHOD_CONNECT: method_and_space = HTTP_STR("CONNECT "); break;
		case HTTP_METHOD_OPTIONS: method_and_space = HTTP_STR("OPTIONS "); break;
		case HTTP_METHOD_TRACE  : method_and_space = HTTP_STR("TRACE ");   break;
		case HTTP_METHOD_PATCH  : method_and_space = HTTP_STR("PATCH ");   break;
	}

	HTTP_String path = parsed_url.path;
	if (path.len == 0)
		path = HTTP_STR("/");

	byte_queue_write(&eng->output, method_and_space.ptr, method_and_space.len);
	byte_queue_write(&eng->output, path.ptr, path.len);
	byte_queue_write(&eng->output, parsed_url.query.ptr, parsed_url.query.len);
	byte_queue_write(&eng->output, minor ? " HTTP/1.1\r\nHost: " : " HTTP/1.0\r\nHost: ", -1);
	byte_queue_write(&eng->output, parsed_url.authority.host.text.ptr, parsed_url.authority.host.text.len);
	if (parsed_url.authority.port > 0)
		byte_queue_write_fmt(&eng->output, "%d", parsed_url.authority.port);
	byte_queue_write(&eng->output, "\r\n", 2);

	eng->keepalive = 1; // TODO

	eng->state = HTTP_ENGINE_STATE_CLIENT_PREP_HEADER;
}


static const char*
get_status_text(int code)
{
	switch(code) {

		case 100: return "Continue";
		case 101: return "Switching Protocols";
		case 102: return "Processing";

		case 200: return "OK";
		case 201: return "Created";
		case 202: return "Accepted";
		case 203: return "Non-Authoritative Information";
		case 204: return "No Content";
		case 205: return "Reset Content";
		case 206: return "Partial Content";
		case 207: return "Multi-Status";
		case 208: return "Already Reported";

		case 300: return "Multiple Choices";
		case 301: return "Moved Permanently";
		case 302: return "Found";
		case 303: return "See Other";
		case 304: return "Not Modified";
		case 305: return "Use Proxy";
		case 306: return "Switch Proxy";
		case 307: return "Temporary Redirect";
		case 308: return "Permanent Redirect";

		case 400: return "Bad Request";
		case 401: return "Unauthorized";
		case 402: return "Payment Required";
		case 403: return "Forbidden";
		case 404: return "Not Found";
		case 405: return "Method Not Allowed";
		case 406: return "Not Acceptable";
		case 407: return "Proxy Authentication Required";
		case 408: return "Request Timeout";
		case 409: return "Conflict";
		case 410: return "Gone";
		case 411: return "Length Required";
		case 412: return "Precondition Failed";
		case 413: return "Request Entity Too Large";
		case 414: return "Request-URI Too Long";
		case 415: return "Unsupported Media Type";
		case 416: return "Requested Range Not Satisfiable";
		case 417: return "Expectation Failed";
		case 418: return "I'm a teapot";
		case 420: return "Enhance your calm";
		case 422: return "Unprocessable Entity";
		case 426: return "Upgrade Required";
		case 429: return "Too many requests";
		case 431: return "Request Header Fields Too Large";
		case 449: return "Retry With";
		case 451: return "Unavailable For Legal Reasons";

		case 500: return "Internal Server Error";
		case 501: return "Not Implemented";
		case 502: return "Bad Gateway";
		case 503: return "Service Unavailable";
		case 504: return "Gateway Timeout";
		case 505: return "HTTP Version Not Supported";
		case 509: return "Bandwidth Limit Exceeded";
	}
	return "???";
}

void http_engine_status(HTTP_Engine *eng, int status)
{
	if (eng->state != HTTP_ENGINE_STATE_SERVER_PREP_STATUS)
		return;

	byte_queue_write_fmt(&eng->output,
		"HTTP/1.1 %d %s\r\n",
		status, get_status_text(status));

	eng->state = HTTP_ENGINE_STATE_SERVER_PREP_HEADER;
}

void http_engine_header(HTTP_Engine *eng, HTTP_String str)
{
	if ((eng->state & HTTP_ENGINE_STATEBIT_PREP_HEADER) == 0)
		return;

	// TODO: Check that the header is valid

	byte_queue_write(&eng->output, str.ptr, str.len);
	byte_queue_write(&eng->output, "\r\n", 2);
}

void http_engine_header_fmt2(HTTP_Engine *eng, const char *fmt, va_list args)
{
	if ((eng->state & HTTP_ENGINE_STATEBIT_PREP_HEADER) == 0)
		return;

	// TODO: Check that the header is valid

	byte_queue_write_fmt2(&eng->output, fmt, args);
	byte_queue_write(&eng->output, "\r\n", 2);
}

void http_engine_header_fmt(HTTP_Engine *eng, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	http_engine_header_fmt2(eng, fmt, args);
	va_end(args);
}

static void
complete_message_head(HTTP_Engine *eng)
{
	if (eng->keepalive) byte_queue_write(&eng->output, "Connection: Keep-Alive\r\n", -1);
	else                byte_queue_write(&eng->output, "Connection: Close\r\n", -1);

	byte_queue_write(&eng->output, "Content-Length: ", -1);
	eng->content_length_value_offset = byte_queue_offset(&eng->output);
	byte_queue_write(&eng->output, TEN_SPACES "\r\n", -1);

	byte_queue_write(&eng->output, "\r\n", -1);
	eng->content_length_offset = byte_queue_offset(&eng->output);
}

static void complete_message_body(HTTP_Engine *eng)
{
	unsigned int content_length = byte_queue_size_from_offset(&eng->output, eng->content_length_offset);

	if (content_length > UINT32_MAX) {
		// TODO
	}

	char tmp[10];

	tmp[0] = '0' + content_length / 1000000000; content_length %= 1000000000;
	tmp[1] = '0' + content_length / 100000000;  content_length %= 100000000;
	tmp[2] = '0' + content_length / 10000000;   content_length %= 10000000;
	tmp[3] = '0' + content_length / 1000000;    content_length %= 1000000;
	tmp[4] = '0' + content_length / 100000;     content_length %= 100000;
	tmp[5] = '0' + content_length / 10000;      content_length %= 10000;
	tmp[6] = '0' + content_length / 1000;       content_length %= 1000;
	tmp[7] = '0' + content_length / 100;        content_length %= 100;
	tmp[8] = '0' + content_length / 10;         content_length %= 10;
	tmp[9] = '0' + content_length;

	int i = 0;
	while (i < 9 && tmp[i] == '0')
		i++;

	byte_queue_patch(&eng->output, eng->content_length_value_offset, tmp + i, 10 - i);
}

void http_engine_body(HTTP_Engine *eng, HTTP_String str)
{
	http_engine_bodycap(eng, str.len);
	int cap;
	char *buf = http_engine_bodybuf(eng, &cap);
	if (buf) {
		memcpy(buf, str.ptr, str.len);
		http_engine_bodyack(eng, str.len);
	}
}

static void ensure_body_entered(HTTP_Engine *eng)
{
	if (eng->state & HTTP_ENGINE_STATEBIT_CLIENT) {

		if (eng->state == HTTP_ENGINE_STATE_CLIENT_PREP_HEADER) {
			complete_message_head(eng);
			eng->state = HTTP_ENGINE_STATE_CLIENT_PREP_BODY_BUF;
		}

	} else {

		if (eng->state == HTTP_ENGINE_STATE_SERVER_PREP_HEADER) {
			complete_message_head(eng);
			eng->state = HTTP_ENGINE_STATE_SERVER_PREP_BODY_BUF;
		}
	}
}

void http_engine_bodycap(HTTP_Engine *eng, int mincap)
{
	ensure_body_entered(eng);
	if (eng->state != HTTP_ENGINE_STATE_CLIENT_PREP_BODY_BUF &&
		eng->state != HTTP_ENGINE_STATE_SERVER_PREP_BODY_BUF)
		return;

	byte_queue_write_setmincap(&eng->output, mincap);
}

char *http_engine_bodybuf(HTTP_Engine *eng, int *cap)
{
	ensure_body_entered(eng);
	if (eng->state != HTTP_ENGINE_STATE_CLIENT_PREP_BODY_BUF &&
		eng->state != HTTP_ENGINE_STATE_SERVER_PREP_BODY_BUF) {
		*cap = 0;
		return NULL;
	}

	if (eng->state & HTTP_ENGINE_STATEBIT_CLIENT)
		eng->state = HTTP_ENGINE_STATE_CLIENT_PREP_BODY_ACK;
	else
		eng->state = HTTP_ENGINE_STATE_SERVER_PREP_BODY_ACK;

	return byte_queue_write_buf(&eng->output, cap);
}

void http_engine_bodyack(HTTP_Engine *eng, int num)
{
	if (eng->state != HTTP_ENGINE_STATE_CLIENT_PREP_BODY_ACK &&
		eng->state != HTTP_ENGINE_STATE_SERVER_PREP_BODY_ACK)
		return;

	byte_queue_write_ack(&eng->output, num);

	if (eng->state & HTTP_ENGINE_STATEBIT_CLIENT)
		eng->state = HTTP_ENGINE_STATE_CLIENT_PREP_BODY_BUF;
	else
		eng->state = HTTP_ENGINE_STATE_SERVER_PREP_BODY_BUF;
}

void http_engine_done(HTTP_Engine *eng)
{
	if ((eng->state & HTTP_ENGINE_STATEBIT_PREP) == 0)
		return;

	if (eng->state & HTTP_ENGINE_STATEBIT_CLIENT) {

		if (eng->state == HTTP_ENGINE_STATE_CLIENT_PREP_URL) {
			eng->state = HTTP_ENGINE_STATE_CLIENT_CLOSED;
			return;
		}

		if (eng->state == HTTP_ENGINE_STATE_CLIENT_PREP_HEADER) {
			complete_message_head(eng);
			eng->state = HTTP_ENGINE_STATE_CLIENT_PREP_BODY_BUF;
		}

		if (eng->state == HTTP_ENGINE_STATE_CLIENT_PREP_BODY_BUF)
			complete_message_body(eng);

		if (eng->state == HTTP_ENGINE_STATE_CLIENT_PREP_ERROR) {
			eng->state = HTTP_ENGINE_STATE_CLIENT_CLOSED;
			return;
		}

		if (byte_queue_error(&eng->output)) {
			eng->state = HTTP_ENGINE_STATE_CLIENT_CLOSED;
			return;
		}

		eng->state = HTTP_ENGINE_STATE_CLIENT_SEND_BUF;

	} else {

		if (eng->state == HTTP_ENGINE_STATE_SERVER_PREP_HEADER) {
			complete_message_head(eng);
			eng->state = HTTP_ENGINE_STATE_SERVER_PREP_BODY_BUF;
		}

		if (eng->state == HTTP_ENGINE_STATE_SERVER_PREP_BODY_BUF)
			complete_message_body(eng);

		if (eng->state == HTTP_ENGINE_STATE_SERVER_PREP_ERROR) {
			byte_queue_remove_from_offset(&eng->output, eng->response_offset);
			byte_queue_write(&eng->output,
				"HTTP/1.1 500 Internal Server Error\r\n"
				"Content-Length: 0\r\n"
				"Connection: Close\r\n"
				"\r\n",
				-1
			);
		}

		if (byte_queue_error(&eng->output)) {
			eng->state = HTTP_ENGINE_STATE_SERVER_CLOSED;
			return;
		}

		byte_queue_read_ack(&eng->input, eng->reqsize);
		eng->state = HTTP_ENGINE_STATE_SERVER_SEND_BUF;
	}
}

void http_engine_undo(HTTP_Engine *eng)
{
	if ((eng->state & HTTP_ENGINE_STATEBIT_PREP) == 0)
		return;

	byte_queue_write_ack(&eng->output, 0);
	byte_queue_remove_from_offset(&eng->output, eng->response_offset);

	if (eng->state & HTTP_ENGINE_STATEBIT_CLIENT)
		eng->state = HTTP_ENGINE_STATE_CLIENT_PREP_URL;
	else
		eng->state = HTTP_ENGINE_STATE_SERVER_PREP_STATUS;
}

////////////////////////////////////////////////////////////////////////////////////////
// src/cert.c
////////////////////////////////////////////////////////////////////////////////////////

#line 1 "src/cert.c"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HTTPS_ENABLED
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#endif

#ifndef HTTP_AMALGAMATION
#include "cert.h"
#endif

#ifdef HTTPS_ENABLED

static EVP_PKEY *generate_rsa_key_pair(int key_bits)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx)
        return NULL;

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, key_bits) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static X509 *create_certificate(EVP_PKEY *pkey, HTTP_String C, HTTP_String O, HTTP_String CN, int days)
{
    X509 *x509 = X509_new();
    if (!x509)
        return NULL;

    // Set version (version 3)
    X509_set_version(x509, 2);
    
    // Set serial number
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    
    // Set validity period
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L * days); // days * seconds_per_year

    // Set public key
    X509_set_pubkey(x509, pkey);

    // Set subject name
    X509_NAME *name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, (unsigned char*) C.ptr,  C.len,  -1, 0);
    X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC, (unsigned char*) O.ptr,  O.len,  -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*) CN.ptr, CN.len, -1, 0);

    // Set issuer name (same as subject for self-signed)
    X509_set_issuer_name(x509, name);

    if (!X509_sign(x509, pkey, EVP_sha256())) {
        X509_free(x509);
        return NULL;
    }

    return x509;
}

static int save_private_key(EVP_PKEY *pkey, HTTP_String file)
{
    char copy[1<<10];
    if (file.len >= (int) sizeof(copy))
        return -1;
    memcpy(copy, file.ptr, file.len);
    copy[file.len] = '\0';

    FILE *fp = fopen(copy, "wb");
    if (!fp)
        return -1;

    // Write private key in PEM format
    if (!PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL)) {
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return 0;
}

static int save_certificate(X509 *x509, HTTP_String file)
{
    char copy[1<<10];
    if (file.len >= (int) sizeof(copy))
        return -1;
    memcpy(copy, file.ptr, file.len);
    copy[file.len] = '\0';

    FILE *fp = fopen(copy, "wb");
    if (!fp)
        return -1;

    // Write certificate in PEM format
    if (!PEM_write_X509(fp, x509)) {
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return 0;
}

int http_create_test_certificate(HTTP_String C, HTTP_String O, HTTP_String CN,
    HTTP_String cert_file, HTTP_String key_file)
{
    EVP_PKEY *pkey = generate_rsa_key_pair(2048);
    if (pkey == NULL)
        return -1;

    X509 *x509 = create_certificate(pkey, C, O, CN, 1);
    if (x509 == NULL) {
        EVP_PKEY_free(pkey);
        return -1;
    }

    if (save_private_key(pkey, key_file) < 0) {
        X509_free(x509);
        EVP_PKEY_free(pkey);
        return -1;
    }

    if (save_certificate(x509, cert_file) < 0) {
        X509_free(x509);
        EVP_PKEY_free(pkey);
        return -1;
    }

    X509_free(x509);
    EVP_PKEY_free(pkey);
    return 0;
}

#else

int http_create_test_certificate(HTTP_String C, HTTP_String O, HTTP_String CN,
    HTTP_String cert_file, HTTP_String key_file)
{
    (void) C;
    (void) O;
    (void) CN;
    (void) cert_file;
    (void) key_file;
    return -1;
}

#endif

////////////////////////////////////////////////////////////////////////////////////////
// src/sec.c
////////////////////////////////////////////////////////////////////////////////////////

#line 1 "src/sec.c"
#ifndef HTTP_AMALGAMATION
#include "sec.h"
#endif

#ifndef HTTPS_ENABLED

void secure_context_global_init(void)
{
}

void secure_context_global_free(void)
{
}

int secure_context_init_as_client(SecureContext *sec)
{
    (void) sec;
    return 0;
}

int secure_context_init_as_server(SecureContext *sec,
    HTTP_String cert_file, HTTP_String key_file)
{
    (void) sec;
    (void) cert_file;
    (void) key_file;
    return 0;
}

int secure_context_add_cert(SecureContext *sec,
    HTTP_String domain, HTTP_String cert_file,
    HTTP_String key_file)
{
    (void) sec;
    (void) domain;
    (void) cert_file;
    (void) key_file;
    return -1;
}

void secure_context_free(SecureContext *sec)
{
    (void) sec;
}

#else

void secure_context_global_init(void)
{
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

void secure_context_global_free(void)
{
    EVP_cleanup();
}

int secure_context_init_as_client(SecureContext *sec)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx)
        return -1;

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    
    if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
        SSL_CTX_free(ctx);
        return -1;
    }

    sec->is_server = false;
    sec->ctx = ctx;
    sec->num_certs = 0;
    return 0;
}

static int servername_callback(SSL *ssl, int *ad, void *arg)
{
    SecureContext *sec = arg;

    (void) ad; // TODO: use this?

    const char *servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (servername == NULL)
        return SSL_TLSEXT_ERR_NOACK;
    
    for (int i = 0; i < sec->num_certs; i++) {
        CertData *cert = &sec->certs[i];
        if (!strcmp(cert->domain, servername)) {
            SSL_set_SSL_CTX(ssl, cert->ctx);
            return SSL_TLSEXT_ERR_OK;
        }
    }

    return SSL_TLSEXT_ERR_NOACK;
}

int secure_context_init_as_server(SecureContext *sec,
    HTTP_String cert_file, HTTP_String key_file)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx)
        return -1;

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    
    char cert_buffer[1024];
    if (cert_file.len >= (int) sizeof(cert_buffer)) {
        SSL_CTX_free(ctx);
        return -1;
    }
    memcpy(cert_buffer, cert_file.ptr, cert_file.len);
    cert_buffer[cert_file.len] = '\0';
    
    // Copy private key file path to static buffer
    char key_buffer[1024];
    if (key_file.len >= (int) sizeof(key_buffer)) {
        SSL_CTX_free(ctx);
        return -1;
    }
    memcpy(key_buffer, key_file.ptr, key_file.len);
    key_buffer[key_file.len] = '\0';
    
    // Load certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, cert_buffer, SSL_FILETYPE_PEM) != 1) {
        SSL_CTX_free(ctx);
        return -1;
    }
    
    if (SSL_CTX_use_PrivateKey_file(ctx, key_buffer, SSL_FILETYPE_PEM) != 1) {
        SSL_CTX_free(ctx);
        return -1;
    }
    
    // Verify that the private key matches the certificate
    if (SSL_CTX_check_private_key(ctx) != 1) {
        SSL_CTX_free(ctx);
        return -1;
    }

    SSL_CTX_set_tlsext_servername_callback(ctx, servername_callback);
    SSL_CTX_set_tlsext_servername_arg(ctx, sec);

    sec->is_server = true;
    sec->ctx = ctx;
    sec->num_certs = 0;
    return 0;
}

void secure_context_free(SecureContext *sec)
{
    SSL_CTX_free(sec->ctx);
    for (int i = 0; i < sec->num_certs; i++)
        SSL_CTX_free(sec->certs[i].ctx);
}

int secure_context_add_cert(SecureContext *sec,
    HTTP_String domain, HTTP_String cert_file,
    HTTP_String key_file)
{
    if (!sec->is_server)
        return -1;

    if (sec->num_certs == MAX_CERTS)
        return -1;

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx)
        return -1;

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    
    char cert_buffer[1024];
    if (cert_file.len >= (int) sizeof(cert_buffer)) {
        SSL_CTX_free(ctx);
        return -1;
    }
    memcpy(cert_buffer, cert_file.ptr, cert_file.len);
    cert_buffer[cert_file.len] = '\0';
    
    char key_buffer[1024];
    if (key_file.len >= (int) sizeof(key_buffer)) {
        SSL_CTX_free(ctx);
        return -1;
    }
    memcpy(key_buffer, key_file.ptr, key_file.len);
    key_buffer[key_file.len] = '\0';
    
    if (SSL_CTX_use_certificate_file(ctx, cert_buffer, SSL_FILETYPE_PEM) != 1) {
        SSL_CTX_free(ctx);
        return -1;
    }
    
    if (SSL_CTX_use_PrivateKey_file(ctx, key_buffer, SSL_FILETYPE_PEM) != 1) {
        SSL_CTX_free(ctx);
        return -1;
    }
    
    if (SSL_CTX_check_private_key(ctx) != 1) {
        SSL_CTX_free(ctx);
        return -1;
    }

    CertData *cert = &sec->certs[sec->num_certs];
    if (domain.len >= (int) sizeof(cert->domain)) {
        SSL_CTX_free(ctx);
        return -1;
    }
    memcpy(cert->domain, domain.ptr, domain.len);
    cert->domain[domain.len] = '\0';
    cert->ctx = ctx;
    sec->num_certs++;
    return 0;
}

#endif

////////////////////////////////////////////////////////////////////////////////////////
// src/socket_raw.c
////////////////////////////////////////////////////////////////////////////////////////

#line 1 "src/socket_raw.c"
#include <string.h>

#ifdef _WIN32
#include <ws2tcpip.h>
#endif

#ifdef __linux__
#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#endif

#ifndef HTTP_AMALGAMATION
#include "socket_raw.h"
#endif

int socket_raw_global_init(void)
{
#ifdef _WIN32
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0)
        return 1;
#endif
    return 0;
}

void socket_raw_global_free(void)
{
#ifdef _WIN32
    WSACleanup();
#endif
}

int set_socket_blocking(RAW_SOCKET sock, bool value)
{
#ifdef _WIN32
    u_long mode = !value;
    if (ioctlsocket(sock, FIONBIO, &mode) == SOCKET_ERROR)
        return -1;
#endif

#ifdef __linux__
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0)
        return -1;
    if (value) flags &= ~O_NONBLOCK;
    else       flags |= O_NONBLOCK;
    if (fcntl(sock, F_SETFL, flags) < 0)
        return -1;
#endif
    
    return 0;
}

RAW_SOCKET listen_socket(HTTP_String addr, uint16_t port, bool reuse_addr, int backlog)
{
    RAW_SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == BAD_SOCKET)
        return BAD_SOCKET;

    if (set_socket_blocking(sock, false) < 0) {
        CLOSE_SOCKET(sock);
        return BAD_SOCKET;
    }

    if (reuse_addr) {
        int one = 1;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void*) &one, sizeof(one));
    }

    struct in_addr addr_buf;
    if (addr.len == 0)
        addr_buf.s_addr = htonl(INADDR_ANY);
    else {

        char copy[100];
        if (addr.len >= (int) sizeof(copy)) {
            CLOSE_SOCKET(sock);
            return BAD_SOCKET;
        }
        memcpy(copy, addr.ptr, addr.len);
        copy[addr.len] = '\0';

        if (inet_pton(AF_INET, copy, &addr_buf) < 0) {
            CLOSE_SOCKET(sock);
            return BAD_SOCKET;
        }
    }

    struct sockaddr_in bind_buf;
    bind_buf.sin_family = AF_INET;
    bind_buf.sin_addr   = addr_buf;
    bind_buf.sin_port   = htons(port);
    if (bind(sock, (struct sockaddr*) &bind_buf, sizeof(bind_buf)) < 0) { // TODO: how does bind fail on windows?
        CLOSE_SOCKET(sock);
        return BAD_SOCKET;
    }

    if (listen(sock, backlog) < 0) { // TODO: how does listen fail on windows?
        CLOSE_SOCKET(sock);
        return BAD_SOCKET;
    }

    return sock;
}

////////////////////////////////////////////////////////////////////////////////////////
// src/socket.c
////////////////////////////////////////////////////////////////////////////////////////

#line 1 "src/socket.c"
#include <stdio.h> // snprintf
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
#include <ws2tcpip.h>
#endif

#ifdef __linux__
#include <netdb.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#endif

#ifdef HTTPS_ENABLED
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#ifndef HTTP_AMALGAMATION
#include "basic.h"
#include "socket.h"
#endif

typedef struct {
    bool is_ipv4;
    union {
        HTTP_IPv4 ipv4;
        HTTP_IPv6 ipv6;
    };
} PendingConnectAddr;

struct PendingConnect {
    uint16_t port;
    int      cursor;
    int      num_addrs;
    int      max_addrs;
    PendingConnectAddr *addrs;
    char*    hostname; // null-terminated
    int      hostname_len;
};

static PendingConnect*
pending_connect_init(HTTP_String hostname, uint16_t port, int max_addrs)
{
    PendingConnect *pending_connect = malloc(sizeof(PendingConnect) + max_addrs * sizeof(PendingConnectAddr) + hostname.len + 1);
    if (pending_connect == NULL)
        return NULL;
    pending_connect->port = port;
    pending_connect->cursor = 0;
    pending_connect->num_addrs = 0;
    pending_connect->max_addrs = max_addrs;
    pending_connect->addrs = (PendingConnectAddr*) (pending_connect + 1);
    pending_connect->hostname = (char*) (pending_connect->addrs + max_addrs);
    memcpy(pending_connect->hostname, hostname.ptr, hostname.len);
    pending_connect->hostname[hostname.len] = '\0';
    pending_connect->hostname_len = hostname.len;
    return pending_connect;
}

static void
pending_connect_free(PendingConnect *pending_connect)
{
    free(pending_connect);
}

static void
pending_connect_add_ipv4(PendingConnect *pending_connect, HTTP_IPv4 ipv4)
{
    if (pending_connect->num_addrs == pending_connect->max_addrs)
        return;
    pending_connect->addrs[pending_connect->num_addrs++] = (PendingConnectAddr) { .is_ipv4=true, .ipv4=ipv4 };
}

static void
pending_connect_add_ipv6(PendingConnect *pending_connect, HTTP_IPv6 ipv6)
{
    if (pending_connect->num_addrs == pending_connect->max_addrs)
        return;
    pending_connect->addrs[pending_connect->num_addrs++] = (PendingConnectAddr) { .is_ipv4=false, .ipv6=ipv6 };
}

static int
next_connect_addr(PendingConnect *pending_connect, PendingConnectAddr *addr)
{
    if (pending_connect->cursor == pending_connect->num_addrs)
        return -1;
    *addr = pending_connect->addrs[pending_connect->cursor++];
    return 0;
}

// Initializes a FREE socket with the information required to
// connect to specified host name. The resulting socket state
// is DIED if an error occurred or PENDING.
void socket_connect(Socket *sock, SecureContext *sec,
    HTTP_String hostname, uint16_t port, void *user_data)
{
    PendingConnect *pending_connect;

    int max_addrs = 30;
    pending_connect = pending_connect_init(hostname, port, max_addrs);
    if (pending_connect == NULL) {
        sock->state = SOCKET_STATE_DIED;
        sock->events = 0;
        return;
    }

    char portstr[16];
    int len = snprintf(portstr, sizeof(portstr), "%u", port);
    if (len < 0 || len >= (int) sizeof(portstr)) {
        pending_connect_free(pending_connect);
        sock->state = SOCKET_STATE_DIED;
        sock->events = 0;
        return;
    }

    // DNS query
    struct addrinfo hints = {0};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res = NULL;
    int ret = getaddrinfo(pending_connect->hostname, portstr, &hints, &res);
    if (ret != 0) {
        pending_connect_free(pending_connect);
        sock->state = SOCKET_STATE_DIED;
        sock->events = 0;
        return;
    }

    for (struct addrinfo *rp = res; rp; rp = rp->ai_next) {
        if (rp->ai_family == AF_INET) {
            HTTP_IPv4 *ipv4 = (void*) &((struct sockaddr_in*)rp->ai_addr)->sin_addr;
            pending_connect_add_ipv4(pending_connect, *ipv4);
        } else if (rp->ai_family == AF_INET6) {
            HTTP_IPv6 *ipv6 = (void*) &((struct sockaddr_in6*)rp->ai_addr)->sin6_addr;
            pending_connect_add_ipv6(pending_connect, *ipv6);
        }
    }

    freeaddrinfo(res);

    sock->state = SOCKET_STATE_PENDING;
    sock->events = 0;

    sock->raw = BAD_SOCKET;
    sock->user_data = user_data;
    sock->pending_connect = pending_connect;
    sock->sec = sec;

#ifdef HTTPS_ENABLED
    sock->ssl = NULL;
#endif

    socket_update(sock);
}

// Just like socket_connect, but the raw IPv4 address is specified
void socket_connect_ipv4(Socket *sock, SecureContext *sec,
    HTTP_IPv4 addr, uint16_t port, void *user_data)
{
    PendingConnect *pending_connect;
    
    pending_connect = pending_connect_init(HTTP_STR(""), port, 1);
    if (pending_connect == NULL) {
        sock->state = SOCKET_STATE_DIED;
        sock->events = 0;
        return;
    }

    pending_connect_add_ipv4(pending_connect, addr);

    sock->state = SOCKET_STATE_PENDING;
    sock->events = 0;

    sock->raw = BAD_SOCKET;
    sock->user_data = user_data;
    sock->pending_connect = pending_connect;
    sock->sec = sec;

#ifdef HTTPS_ENABLED
    sock->ssl = NULL;
#endif

    socket_update(sock);
}

// Just like socket_connect, but the raw IPv6 address is specified
void socket_connect_ipv6(Socket *sock, SecureContext *sec,
    HTTP_IPv6 addr, uint16_t port, void *user_data)
{
    PendingConnect *pending_connect;
    
    pending_connect = pending_connect_init(HTTP_STR(""), port, 1);
    if (pending_connect == NULL) {
        sock->state = SOCKET_STATE_DIED;
        sock->events = 0;
        return;
    }

    pending_connect_add_ipv6(pending_connect, addr);

    sock->state = SOCKET_STATE_PENDING;
    sock->events = 0;

    sock->raw = BAD_SOCKET;
    sock->user_data = user_data;
    sock->pending_connect = pending_connect;
    sock->sec = sec;

#ifdef HTTPS_ENABLED
    sock->ssl = NULL;
#endif

    socket_update(sock);
}

void socket_accept(Socket *sock, SecureContext *sec, RAW_SOCKET raw)
{
    sock->state = SOCKET_STATE_ACCEPTED;
    sock->raw = raw;
    sock->events = 0;
    sock->user_data = NULL;
    sock->pending_connect = NULL;
    sock->sec = sec;

#ifdef HTTPS_ENABLED
    sock->ssl = NULL;
#endif

    if (set_socket_blocking(raw, false) < 0) {
        sock->state  = SOCKET_STATE_DIED;
        sock->events = 0;
        return;
    }

    socket_update(sock);
}

void socket_close(Socket *sock)
{
    // TODO: maybe we don't want to always set to SHUTDOWN. What if the socket is DIED for instance?
    sock->state  = SOCKET_STATE_SHUTDOWN;
    sock->events = 0;
    socket_update(sock);
}

bool socket_ready(Socket *sock)
{
    return sock->state == SOCKET_STATE_ESTABLISHED_READY;
}

bool socket_died(Socket *sock)
{
    return sock->state == SOCKET_STATE_DIED;
}

// TODO: when is the pending_connect data freed?

static bool connect_pending(void)
{
#ifdef _WIN32
    return WSAGetLastError() == WSAEWOULDBLOCK;
#else
    return errno == EINPROGRESS;
#endif
}

static bool
connect_failed_because_or_peer_2(int err)
{
#ifdef _WIN32
    return err == WSAECONNREFUSED
        || err == WSAETIMEDOUT
        || err == WSAENETUNREACH
        || err == WSAEHOSTUNREACH;
#else
    return err == ECONNREFUSED
        || err == ETIMEDOUT
        || err == ENETUNREACH
        || err == EHOSTUNREACH;
#endif
}

static bool
connect_failed_because_or_peer(void)
{
#ifdef _WIN32
    int err = WSAGetLastError();
#else
    int err = errno;
#endif
    return connect_failed_because_or_peer_2(err);
}

// Processes the socket until it's either ready, died, or would block
void socket_update(Socket *sock)
{
    sock->events = 0;

    bool again;
    do {

        again = false;

        switch (sock->state) {
        case SOCKET_STATE_PENDING:
        {
            // In this state we need to pop an address from the pending connect
            // data and try connect to it. This state is reached when a socket
            // is initialized using one of the socket_connect functions or by
            // failing to connect before the established state is reached.

            // If this isn't the first connection attempt we may have old
            // descriptors that need freeing before trying again.
            {
#ifdef HTTPS_ENABLED
                if (sock->ssl) {
                    SSL_free(sock->ssl);
                    sock->ssl = NULL;
                }
#endif
                if (sock->raw != BAD_SOCKET)
                    CLOSE_SOCKET(sock->raw);
            }

            // Pop the next address from the pending connect data
            PendingConnectAddr addr;
            if (next_connect_addr(sock->pending_connect, &addr) < 0) {
                sock->state  = SOCKET_STATE_DIED;
                sock->events = 0;
                break;
            }
            uint16_t port = sock->pending_connect->port;

            // Create a kernel socket object
            int family = addr.is_ipv4 ? AF_INET : AF_INET6;
            RAW_SOCKET raw = socket(family, SOCK_STREAM, 0);
            if (raw == BAD_SOCKET) {
                sock->state  = SOCKET_STATE_PENDING;
                sock->events = 0;
                again = true;
                break;
            }

            // Configure it
            if (set_socket_blocking(raw, false) < 0) {
                CLOSE_SOCKET(raw);
                sock->state  = SOCKET_STATE_DIED;
                sock->events = 0;
                break;
            }

            // Now perform the connect

            struct sockaddr_in  connect_buf_4;
            struct sockaddr_in6 connect_buf_6;
            struct sockaddr*    connect_buf;
            int    connect_buf_len;

            if (addr.is_ipv4) {

                connect_buf = (struct sockaddr*) &connect_buf_4;
                connect_buf_len = sizeof(connect_buf_4);

                connect_buf_4.sin_family = AF_INET;
                connect_buf_4.sin_port = htons(port);
                memcpy(&connect_buf_4.sin_addr, &addr.ipv4, sizeof(HTTP_IPv4));

            } else {

                connect_buf = (struct sockaddr*) &connect_buf_6;
                connect_buf_len = sizeof(connect_buf_6);

                connect_buf_6.sin6_family = AF_INET6;
                connect_buf_6.sin6_port = htons(port);
                memcpy(&connect_buf_6.sin6_addr, &addr.ipv6, sizeof(HTTP_IPv6));
            }

            int ret = connect(raw, connect_buf, connect_buf_len);

            // We divide the connect() results in four categories:
            //
            //   1) The connect resolved immediately. I'm not sure how this can happen,
            //      but we may as well handle it. This allows us to skip a step.
            //
            //   2) The connect operation is pending. This is what we expect most of the time.
            //
            //   3) The connect operation failed because the target address wasn't good
            //      for some reason. It make sense to try connecting to a different address
            //
            //   4) The connect operation failed for unknown reasons. There isn't much we
            //      can do at this point.

            if (ret == 0) {
                // Connected immediately
                sock->raw    = raw;
                sock->state  = SOCKET_STATE_CONNECTED;
                sock->events = 0;
                again = true;
                break;
            }

            if (connect_pending()) { // TODO: I'm pretty sure all the error numbers need to be changed for windows
                // Connection pending
                sock->raw = raw;
                sock->state = SOCKET_STATE_CONNECTING;
                sock->events = POLLOUT;
                break;
            }

            // Connect failed

            // If remote peer not working, try next address
            if (connect_failed_because_or_peer()) {
                sock->state = SOCKET_STATE_PENDING;
                sock->events = 0;
                again = true;
            } else {
                sock->state = SOCKET_STATE_DIED;
                sock->events = 0;
            }
        }
        break;

        case SOCKET_STATE_CONNECTING:
        {
            // We reach this point when a connect() operation on the
            // socket started and then the descriptor was marked as
            // ready for output. This means the operation is complete.

            int err = 0;
            socklen_t len = sizeof(err);

            if (getsockopt(sock->raw, SOL_SOCKET, SO_ERROR, (void*) &err, &len) < 0 || err != 0) {

                // If remote peer not working, try next address
                if (connect_failed_because_or_peer_2(err)) {
                    sock->state = SOCKET_STATE_PENDING;
                    sock->events = 0;
                    again = true;
                    break;
                }

                sock->state = SOCKET_STATE_DIED;
                sock->events = 0;
                break;
            }

            // Connect succeeded
            sock->state = SOCKET_STATE_CONNECTED;
            sock->events = 0;
            again = true;
        }
        break;

        case SOCKET_STATE_CONNECTED:
        {
            if (!socket_secure(sock)) {

                pending_connect_free(sock->pending_connect);
                sock->pending_connect = NULL;

                sock->events = 0;
                sock->state = SOCKET_STATE_ESTABLISHED_READY;

            } else {
#ifdef HTTPS_ENABLED
                // Start SSL handshake

                if (sock->ssl == NULL) {
                    sock->ssl = SSL_new(sock->sec->ctx);
                    if (sock->ssl == NULL) {
                        ERR_print_errors_fp(stderr); // TODO: remove
                        sock->state  = SOCKET_STATE_DIED;
                        sock->events = 0;
                        break;
                    }

                    if (SSL_set_fd(sock->ssl, sock->raw) != 1) {
                        sock->state  = SOCKET_STATE_DIED;
                        sock->events = 0;
                        break;
                    }

                    char *hostname = NULL;
                    if (sock->pending_connect->hostname[0])
                        hostname = sock->pending_connect->hostname;

                    if (hostname)
                        SSL_set_tlsext_host_name(sock->ssl, hostname);
                }

                int ret = SSL_connect(sock->ssl);
                if (ret == 1) {
                    // Handshake done

                    pending_connect_free(sock->pending_connect);
                    sock->pending_connect = NULL;

                    sock->state  = SOCKET_STATE_ESTABLISHED_READY;
                    sock->events = 0;
                    break;
                }

                int err = SSL_get_error(sock->ssl, ret);
                if (err == SSL_ERROR_WANT_READ) {
                    sock->events = POLLIN;
                    break;
                }

                if (err == SSL_ERROR_WANT_WRITE) {
                    sock->events = POLLOUT;
                    break;
                }

                sock->state  = SOCKET_STATE_PENDING;
                sock->events = 0;
                again = true;
#else
                assert(0);
#endif
            }
        }
        break;

        case SOCKET_STATE_ACCEPTED:
        {
            if (!socket_secure(sock)) {
                sock->state  = SOCKET_STATE_ESTABLISHED_READY;
                sock->events = 0;
            } else {
#ifdef HTTPS_ENABLED
                // Start server-side SSL handshake
                if (!sock->ssl) {

                    sock->ssl = SSL_new(sock->sec->ctx);
                    if (sock->ssl == NULL) {
                        sock->state  = SOCKET_STATE_DIED;
                        sock->events = 0;
                        break;
                    }

                    if (SSL_set_fd(sock->ssl, sock->raw) != 1) {
                        sock->state  = SOCKET_STATE_DIED;
                        sock->events = 0;
                        break;
                    }
                }

                int ret = SSL_accept(sock->ssl);
                if (ret == 1) {
                    // Handshake done
                    sock->state = SOCKET_STATE_ESTABLISHED_READY;
                    sock->events = 0;
                    break;
                }

                int err = SSL_get_error(sock->ssl, ret);
                if (err == SSL_ERROR_WANT_READ) {
                    sock->events = POLLIN;
                    break;
                }

                if (err == SSL_ERROR_WANT_WRITE) {
                    sock->events = POLLOUT;
                    break;
                }

                // Server socket error - close the connection
                sock->state  = SOCKET_STATE_DIED;
                sock->events = 0;
#else
               assert(0);
#endif
            }
        }
        break;

        case SOCKET_STATE_ESTABLISHED_WAIT:
        {
            sock->state = SOCKET_STATE_ESTABLISHED_READY;
            sock->events = 0;
        }
        break;

        case SOCKET_STATE_SHUTDOWN:
        {
            if (!socket_secure(sock)) {
                sock->state = SOCKET_STATE_DIED;
                sock->events = 0;
            } else {
#ifdef HTTPS_ENABLED
                int ret = SSL_shutdown(sock->ssl);
                if (ret == 1) {
                    sock->state  = SOCKET_STATE_DIED;
                    sock->events = 0;
                    break;
                }

                int err = SSL_get_error(sock->ssl, ret);
                if (err == SSL_ERROR_WANT_READ) {
                    sock->events = POLLIN;
                    break;
                }
                
                if (err == SSL_ERROR_WANT_WRITE) {
                    sock->events = POLLOUT;
                    break;
                }

                sock->state  = SOCKET_STATE_DIED;
                sock->events = 0;
#else
                assert(0);
#endif
            }
        }
        break;

        default:
            // Do nothing
            break;
        }

    } while (again);
}

static bool would_block(void)
{
#ifdef _WIN32
    int err = WSAGetLastError();
    return err == WSAEWOULDBLOCK;
#else
    return errno == EAGAIN || errno == EWOULDBLOCK;
#endif
}

static bool interrupted(void)
{
#ifdef _WIN32
    return false;
#else
    return errno == EINTR;
#endif
}

int socket_read(Socket *sock, char *dst, int max)
{
    // If not ESTABLISHED, set state to DIED and return
    if (sock->state != SOCKET_STATE_ESTABLISHED_READY) {
        sock->state = SOCKET_STATE_DIED;
        sock->events = 0;
        return 0;
    }

    if (!socket_secure(sock)) {
        int ret = recv(sock->raw, dst, max, 0);
        if (ret == 0) {
            sock->state  = SOCKET_STATE_DIED;
            sock->events = 0;
        } else {
            if (ret < 0) {
                if (would_block()) {
                    sock->state  = SOCKET_STATE_ESTABLISHED_WAIT;
                    sock->events = POLLIN;
                } else {
                    if (!interrupted()) {
                        sock->state  = SOCKET_STATE_DIED;
                        sock->events = 0;
                    }
                }
                ret = 0;
            }
        }
        return ret;
    } else {
#ifdef HTTPS_ENABLED
        int ret = SSL_read(sock->ssl, dst, max);
        if (ret <= 0) {
            int err = SSL_get_error(sock->ssl, ret);
            if (err == SSL_ERROR_WANT_READ) {
                sock->state  = SOCKET_STATE_ESTABLISHED_WAIT;
                sock->events = POLLIN;
            } else if (err == SSL_ERROR_WANT_WRITE) {
                sock->state = SOCKET_STATE_ESTABLISHED_WAIT;
                sock->events = POLLOUT;
            } else {
                fprintf(stderr, "OpenSSL error in socket_read: ");
                ERR_print_errors_fp(stderr);
                sock->state  = SOCKET_STATE_DIED;
                sock->events = 0;
            }
            ret = 0;
        }
        return ret;
#else
        assert(0);
        return -1;
#endif
    }
}

int socket_write(Socket *sock, char *src, int len)
{
    // If not ESTABLISHED, set state to DIED and return
    if (sock->state != SOCKET_STATE_ESTABLISHED_READY) {
        sock->state  = SOCKET_STATE_DIED;
        sock->events = 0;
        return 0;
    }

    if (!socket_secure(sock)) {
        int ret = send(sock->raw, src, len, 0);
        if (ret < 0) {
            if (would_block()) {
                sock->state  = SOCKET_STATE_ESTABLISHED_WAIT;
                sock->events = POLLOUT;
            } else {
                if (!interrupted()) {
                    sock->state = SOCKET_STATE_DIED;
                    sock->events = 0;
                }
            }
            ret = 0;
        }
        return ret;
    } else {
#ifdef HTTPS_ENABLED
        int ret = SSL_write(sock->ssl, src, len);
        if (ret <= 0) {
            int err = SSL_get_error(sock->ssl, ret);
            if (err == SSL_ERROR_WANT_READ) {
                sock->state  = SOCKET_STATE_ESTABLISHED_WAIT;
                sock->events = POLLIN;
            } else if (err == SSL_ERROR_WANT_WRITE) {
                sock->state  = SOCKET_STATE_ESTABLISHED_WAIT;
                sock->events = POLLOUT;
            } else {
                fprintf(stderr, "OpenSSL error in socket_write: ");
                ERR_print_errors_fp(stderr);
                sock->state  = SOCKET_STATE_DIED;
                sock->events = 0;
            }
            ret = 0;
        }
        return ret;
#else
        assert(0);
#endif
    }
}

bool socket_secure(Socket *sock)
{
#ifdef HTTPS_ENABLED
    return sock->sec != NULL;
#else
    (void) sock;
    return false;
#endif
}

void socket_free(Socket *sock)
{
    if (sock->pending_connect != NULL)
        pending_connect_free(sock->pending_connect);

    if (sock->raw != BAD_SOCKET)
        CLOSE_SOCKET(sock->raw);

#ifdef HTTPS_ENABLED
    if (sock->ssl)
        SSL_free(sock->ssl);
#endif

    sock->state = SOCKET_STATE_FREE;
}

void socket_set_user_data(Socket *sock, void *user_data)
{
    sock->user_data = user_data;
}

void *socket_get_user_data(Socket *sock)
{
    return sock->user_data;
}

////////////////////////////////////////////////////////////////////////////////////////
// src/socket_pool.c
////////////////////////////////////////////////////////////////////////////////////////

#line 1 "src/socket_pool.c"
#include <assert.h>
#include <stdlib.h>

#ifdef __linux__
#include <errno.h>
#include <sys/socket.h>
#endif

#ifndef HTTP_AMALGAMATION
#include "socket_pool.h"
#endif

#define SOCKET_HARD_LIMIT (1<<10)
#define MAX_CERTS 10

struct SocketPool {

    SecureContext sec;

    RAW_SOCKET listen_sock;
    RAW_SOCKET secure_sock;

    int num_socks;
    int max_socks;
    Socket socks[];
};

int socket_pool_global_init(void)
{
    int ret = socket_raw_global_init();
    if (ret < 0)
        return -1;

    secure_context_global_init();
    return 0;
}

void socket_pool_global_free(void)
{
    secure_context_global_free();
    socket_raw_global_free();
}

SocketPool *socket_pool_init(HTTP_String addr,
    uint16_t port, uint16_t secure_port, int max_socks,
    bool reuse_addr, int backlog, HTTP_String cert_file,
    HTTP_String key_file)
{
    if (max_socks > SOCKET_HARD_LIMIT)
        return NULL;

    SocketPool *pool = malloc(sizeof(SocketPool) + max_socks * sizeof(Socket));
    if (pool == NULL)
        return NULL;

    pool->num_socks = 0;
    pool->max_socks = max_socks;

    for (int i = 0; i < pool->max_socks; i++)
        pool->socks[i].state = SOCKET_STATE_FREE;

    if (port == 0)
        pool->listen_sock = BAD_SOCKET;
    else {
        pool->listen_sock = listen_socket(addr, port, reuse_addr, backlog);
        if (pool->listen_sock == BAD_SOCKET) {
            free(pool);
            return NULL;
        }
    }

    if (secure_port == 0)
        pool->secure_sock = BAD_SOCKET;
    else {
#ifndef HTTPS_ENABLED
        (void) cert_file;
        (void) key_file;
        if (pool->listen_sock != BAD_SOCKET)
            CLOSE_SOCKET(pool->listen_sock);
        free(pool);
        return NULL;
#else
        if (secure_context_init_as_server(&pool->sec, cert_file, key_file) < 0) {
            if (pool->listen_sock != BAD_SOCKET)
                CLOSE_SOCKET(pool->listen_sock);
            free(pool);
            return NULL;
        }

        pool->secure_sock = listen_socket(addr, secure_port, reuse_addr, backlog);
        if (pool->secure_sock == BAD_SOCKET) {
            if (pool->listen_sock != BAD_SOCKET) CLOSE_SOCKET(pool->listen_sock);
            free(pool);
            return NULL;
        }
#endif
    }

#ifdef HTTPS_ENABLED
    if (port == 0 && secure_port == 0) {
        if (secure_context_init_as_client(&pool->sec) < 0) {
            if (pool->listen_sock != BAD_SOCKET) CLOSE_SOCKET(pool->listen_sock);
            if (pool->secure_sock != BAD_SOCKET) CLOSE_SOCKET(pool->secure_sock);
            free(pool);
            return NULL;
        }
    }
#endif

    for (int i = 0; i < max_socks; i++)
        pool->socks[i].state = SOCKET_STATE_FREE;

    return pool;
}

void socket_pool_free(SocketPool *pool)
{
    for (int i = 0, j = 0; j < pool->num_socks; i++) {

        Socket *sock = &pool->socks[i];

        if (sock->state == SOCKET_STATE_FREE)
            continue;
        j++;

        socket_free(sock);
    }

    secure_context_free(&pool->sec);

    if (pool->secure_sock != BAD_SOCKET) CLOSE_SOCKET(pool->secure_sock);
    if (pool->listen_sock != BAD_SOCKET) CLOSE_SOCKET(pool->listen_sock);
}

int socket_pool_add_cert(SocketPool *pool, HTTP_String domain, HTTP_String cert_file, HTTP_String key_file)
{
    return secure_context_add_cert(&pool->sec, domain, cert_file, key_file);
}

void socket_pool_set_user_data(SocketPool *pool, SocketHandle handle, void *user_data)
{
    Socket *sock = &pool->socks[handle];
    socket_set_user_data(sock, user_data);
}

void socket_pool_close(SocketPool *pool, SocketHandle handle)
{
    Socket *sock = &pool->socks[handle];
    socket_close(sock);
}

static Socket *find_free_socket(SocketPool *pool)
{
    if (pool->num_socks == pool->max_socks)
        return NULL;

    int i = 0;
    while (pool->socks[i].state != SOCKET_STATE_FREE)
        i++;

    return &pool->socks[i];
}

int socket_pool_connect(SocketPool *pool, bool secure,
    HTTP_String addr, uint16_t port, void *user_data)
{
    Socket *sock = find_free_socket(pool);
    if (sock == NULL)
        return -1;

    socket_connect(sock, secure ? &pool->sec : NULL, addr, port, user_data);

    if (socket_died(sock)) {
        socket_free(sock);
        return -1;
    }

    pool->num_socks++;
    return 0;
}

int socket_pool_connect_ipv4(SocketPool *pool, bool secure,
    HTTP_IPv4 addr, uint16_t port, void *user_data)
{
    Socket *sock = find_free_socket(pool);
    if (sock == NULL)
        return -1;

    socket_connect_ipv4(sock, secure ? &pool->sec : NULL, addr, port, user_data);

    if (socket_died(sock)) {
        socket_free(sock);
        return -1;
    }

    pool->num_socks++;
    return 0;
}

int socket_pool_connect_ipv6(SocketPool *pool, bool secure,
    HTTP_IPv6 addr, uint16_t port, void *user_data)
{
    Socket *sock = find_free_socket(pool);
    if (sock == NULL)
        return -1;

    socket_connect_ipv6(sock, secure ? &pool->sec : NULL, addr, port, user_data);

    if (socket_died(sock)) {
        socket_free(sock);
        return -1;
    }

    pool->num_socks++;
    return 0;
}

#include <stdio.h> // TODO: remove

SocketEvent socket_pool_wait(SocketPool *pool)
{
    for (;;) {

        // First, iterate over all sockets to find one that
        // died or is ready.

        for (int i = 0, j = 0; j < pool->num_socks; i++) {

            Socket *sock = &pool->socks[i];

            if (sock->state == SOCKET_STATE_FREE)
                continue;
            j++;

            if (socket_died(sock)) {
                void *user_data = socket_get_user_data(sock);
                socket_free(sock);
                pool->num_socks--;
                return (SocketEvent) { SOCKET_EVENT_DIED, -1, user_data };
            }

            if (socket_ready(sock))
                return (SocketEvent) { SOCKET_EVENT_READY, i, socket_get_user_data(sock) };

            assert(sock->events);
        }

        // If we reached this point, we either have no sockets
        // or all sockets need to wait for some event. Waiting
        // when no sockets are available is only allowed when
        // the pool is in server mode.

        int indices[SOCKET_HARD_LIMIT+2];
        struct pollfd polled[SOCKET_HARD_LIMIT+2];
        int num_polled = 0;

        if (pool->num_socks < pool->max_socks) {

            if (pool->listen_sock != BAD_SOCKET) {
                indices[num_polled] = -1;
                polled[num_polled].fd = pool->listen_sock;
                polled[num_polled].events = POLLIN;
                polled[num_polled].revents = 0;
                num_polled++;
            }

            if (pool->secure_sock != BAD_SOCKET) {
                indices[num_polled] = -1;
                polled[num_polled].fd = pool->secure_sock;
                polled[num_polled].events = POLLIN;
                polled[num_polled].revents = 0;
                num_polled++;
            }
        }

        for (int i = 0, j = 0; j < pool->num_socks; i++) {

            Socket *sock = &pool->socks[i];

            if (sock->state == SOCKET_STATE_FREE)
                continue;
            j++;

            indices[num_polled] = i;
            polled[num_polled].fd = sock->raw;
            polled[num_polled].events = sock->events;
            polled[num_polled].revents = 0;
            num_polled++;
        }

        if (num_polled == 0)
            return (SocketEvent) { SOCKET_EVENT_ERROR, -1, NULL };

        int ret = POLL(polled, num_polled, -1);
        if (ret < 0) {

            if (errno == EINTR)
                return (SocketEvent) { SOCKET_EVENT_SIGNAL, -1, NULL };

            return (SocketEvent) { SOCKET_EVENT_ERROR, -1, NULL };
        }

        for (int i = 0; i < num_polled; i++) {

            Socket *sock;
            
            if (polled[i].fd == pool->listen_sock || polled[i].fd == pool->secure_sock) {

                bool secure = false;
                if (polled[i].fd == pool->secure_sock)
                    secure = true;

                Socket *sock = find_free_socket(pool);
                if (sock == NULL)
                    continue;

                RAW_SOCKET raw = accept(polled[i].fd, NULL, NULL);
                if (raw == BAD_SOCKET)
                    continue;

                socket_accept(sock, secure ? &pool->sec : NULL, raw);

                if (socket_died(sock)) {
                    socket_free(sock);
                    continue;
                }

                pool->num_socks++;

            } else {
                int j = indices[i];
                sock = &pool->socks[j];

                if (polled[i].revents)
                    socket_update(sock);
            }
        }
    }

    // This branch is unreachable
    return (SocketEvent) { SOCKET_EVENT_ERROR, -1, NULL };
}

int socket_pool_read(SocketPool *pool, SocketHandle handle, char *dst, int len)
{
    return socket_read(&pool->socks[handle], dst, len);
}

int socket_pool_write(SocketPool *pool, SocketHandle handle, char *src, int len)
{
    return socket_write(&pool->socks[handle], src, len);
}

bool socket_pool_secure(SocketPool *pool, SocketHandle handle)
{
    return socket_secure(&pool->socks[handle]);
}

////////////////////////////////////////////////////////////////////////////////////////
// src/client.c
////////////////////////////////////////////////////////////////////////////////////////

#line 1 "src/client.c"
#include <stdint.h>
#include <assert.h>
#include <stdlib.h>
#include <stdbool.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#define POLL WSAPoll
#endif

#ifdef __linux__
#include <poll.h>
#define POLL poll
#endif

#ifndef HTTP_AMALGAMATION
#include "client.h"
#include "engine.h"
#include "socket_pool.h"
#endif

#define CLIENT_MAX_CONNS 256

typedef enum {
    CLIENT_CONNECTION_FREE,
    CLIENT_CONNECTION_INIT,
    CLIENT_CONNECTION_INIT_ERROR,
    CLIENT_CONNECTION_WAIT,
    CLIENT_CONNECTION_DONE,
} ClientConnectionState;

typedef struct {
    ClientConnectionState state;
    uint16_t     gen;
    SocketHandle sock;
    HTTP_Engine  eng;
    bool         trace;
    void*        user_data;
} ClientConnection;

struct HTTP_Client {

    SocketPool *socket_pool;

    int num_conns;
    ClientConnection conns[CLIENT_MAX_CONNS];

    int ready_head;
    int ready_count;
    int ready[CLIENT_MAX_CONNS];
};

int http_global_init(void)
{
    int ret = socket_pool_global_init();
    if (ret < 0)
        return -1;
    return 0;
}

void http_global_free(void)
{
    socket_pool_global_free();
}

// Rename the memory function
static void* client_memfunc(HTTP_MemoryFuncTag tag, void *ptr, int len, void *data) {
    (void)data;
    switch (tag) {
        case HTTP_MEMFUNC_MALLOC:
            return malloc(len);
        case HTTP_MEMFUNC_FREE:
            free(ptr);
            return NULL;
    }
    return NULL;
}

HTTP_Client *http_client_init(void)
{
    HTTP_Client *client = malloc(sizeof(HTTP_Client));
    if (client == NULL)
        return NULL;

    int max_socks = 100;
    SocketPool *socket_pool = socket_pool_init(HTTP_STR(""), 0, 0, max_socks, false, 0, HTTP_STR(""), HTTP_STR(""));
    if (socket_pool == NULL) {
        free(client);
        return NULL;
    }
    client->socket_pool = socket_pool;

    for (int i = 0; i < CLIENT_MAX_CONNS; i++) {
        client->conns[i].state = CLIENT_CONNECTION_FREE;
        client->conns[i].gen  = 1;
    }

    client->num_conns = 0;
    client->ready_head = 0;
    client->ready_count = 0;

    return client;
}

void http_client_free(HTTP_Client *client)
{
    for (int i = 0, j = 0; j < client->num_conns; i++) {

        if (client->conns[i].state == CLIENT_CONNECTION_FREE)
            continue;
        j++;

        // TODO
    }

    socket_pool_free(client->socket_pool);
    free(client);
}

int http_client_get_builder(HTTP_Client *client, HTTP_RequestBuilder *builder)
{
    if (client->num_conns == CLIENT_MAX_CONNS)
        return -1;

    int i = 0;
    while (client->conns[i].state != CLIENT_CONNECTION_FREE)
        i++;

    client->conns[i].sock = -1;
    client->conns[i].user_data = NULL;
    client->conns[i].trace = false;
    client->conns[i].state = CLIENT_CONNECTION_INIT;
    http_engine_init(&client->conns[i].eng, 1, client_memfunc, NULL);

    client->num_conns++;

    *builder = (HTTP_RequestBuilder) { client, i, client->conns[i].gen };
    return 0;
}

int http_client_wait(HTTP_Client *client, HTTP_Response **result, void **user_data)
{
    while (client->ready_count == 0) {

        SocketEvent event = socket_pool_wait(client->socket_pool);
        switch (event.type) {

            case SOCKET_EVENT_DIED:
            {
                ClientConnection *conn = event.user_data;
                conn->state = CLIENT_CONNECTION_DONE;

                int tail = (client->ready_head + client->ready_count) % CLIENT_MAX_CONNS;
                client->ready[tail] = conn - client->conns;
                client->ready_count++;
            }
            break;

            case SOCKET_EVENT_READY:
            {
                ClientConnection *conn = event.user_data;

                if (conn->sock == -1)
                    conn->sock = event.handle;

                HTTP_EngineState engine_state;
                engine_state = http_engine_state(&conn->eng);

                if (engine_state == HTTP_ENGINE_STATE_CLIENT_RECV_BUF) {
                    int len;
                    char *buf;
                    buf = http_engine_recvbuf(&conn->eng, &len);
                    if (buf) {
                        int ret = socket_pool_read(client->socket_pool, conn->sock, buf, len);
                        if (conn->trace)
                            print_bytes(HTTP_STR(">> "), (HTTP_String) { buf, ret });
                        http_engine_recvack(&conn->eng, ret);
                    }
                } else if (engine_state == HTTP_ENGINE_STATE_CLIENT_SEND_BUF) {
                    int len;
                    char *buf;
                    buf = http_engine_sendbuf(&conn->eng, &len);
                    if (buf) {
                        int ret = socket_pool_write(client->socket_pool, conn->sock, buf, len);
                        if (conn->trace)
                            print_bytes(HTTP_STR("<< "), (HTTP_String) { buf, ret });
                        http_engine_sendack(&conn->eng, ret);
                    }
                }

                engine_state = http_engine_state(&conn->eng);

                if (engine_state == HTTP_ENGINE_STATE_CLIENT_CLOSED ||
                    engine_state == HTTP_ENGINE_STATE_CLIENT_READY)
                    socket_pool_close(client->socket_pool, conn->sock);
            }
            break;

            case SOCKET_EVENT_ERROR:
            return -1;

            case SOCKET_EVENT_SIGNAL:
            return 1;
        }
    }

    int index = client->ready[client->ready_head];
    client->ready_head = (client->ready_head + 1) % CLIENT_MAX_CONNS;
    client->ready_count--;

    ClientConnection *conn = &client->conns[index];

    HTTP_Response *result2 = http_engine_getres(&conn->eng);

    if (result)
        *result = result2;

    if (user_data)
        *user_data = conn->user_data;

    if (result2 == NULL) {
        http_engine_free(&conn->eng);
        conn->state = CLIENT_CONNECTION_FREE;
        client->num_conns--;
    } else {
        result2->context = client;
    }

    return 0;
}

static ClientConnection *client_builder_to_conn(HTTP_RequestBuilder handle)
{
    if (handle.data0 == NULL)
        return NULL;

    HTTP_Client *client = handle.data0;

    if (handle.data1 >= CLIENT_MAX_CONNS)
        return NULL;

    ClientConnection *conn = &client->conns[handle.data1];

    if (handle.data2 != conn->gen)
        return NULL;

    return conn;
}

void http_request_builder_user_data(HTTP_RequestBuilder builder, void *user_data)
{
    ClientConnection *conn = client_builder_to_conn(builder);
    if (conn == NULL)
        return;
    if (conn->state != CLIENT_CONNECTION_INIT)
        return;

    conn->user_data = user_data;
}

void http_request_builder_trace(HTTP_RequestBuilder builder, bool trace)
{
    ClientConnection *conn = client_builder_to_conn(builder);
    if (conn == NULL)
        return;
    if (conn->state != CLIENT_CONNECTION_INIT)
        return;

    conn->trace = trace;
}

void http_request_builder_line(HTTP_RequestBuilder builder, HTTP_Method method, HTTP_String url)
{
    ClientConnection *conn = client_builder_to_conn(builder);
    if (conn == NULL)
        return;
    if (conn->state != CLIENT_CONNECTION_INIT)
        return;

    HTTP_Client *client = builder.data0;

    HTTP_URL parsed_url;
    int ret = http_parse_url(url.ptr, url.len, &parsed_url);
    if (ret != url.len) {
        conn->state = CLIENT_CONNECTION_INIT_ERROR;
        return;
    }

    bool secure = false;
    if (http_streq(parsed_url.scheme, HTTP_STR("https"))) {
        secure = true;
    } else if (!http_streq(parsed_url.scheme, HTTP_STR("http"))) {
        conn->state = CLIENT_CONNECTION_INIT_ERROR;
        return;
    }

    int port = parsed_url.authority.port;
    if (port == 0) {
        if (secure)
            port = 443;
        else
            port = 80;
    }

    switch (parsed_url.authority.host.mode) {
        case HTTP_HOST_MODE_IPV4: ret = socket_pool_connect_ipv4(client->socket_pool, secure, parsed_url.authority.host.ipv4, port, conn); break;
        case HTTP_HOST_MODE_IPV6: ret = socket_pool_connect_ipv6(client->socket_pool, secure, parsed_url.authority.host.ipv6, port, conn); break;
        case HTTP_HOST_MODE_NAME: ret = socket_pool_connect     (client->socket_pool, secure, parsed_url.authority.host.name, port, conn); break;
        case HTTP_HOST_MODE_VOID: ret = -1; return;
    }

    if (ret < 0) {
        conn->state = CLIENT_CONNECTION_INIT_ERROR;
        return;
    }

    http_engine_url(&conn->eng, method, url, 1);
}

void http_request_builder_header(HTTP_RequestBuilder handle, HTTP_String str)
{
    ClientConnection *conn = client_builder_to_conn(handle);
    if (conn == NULL)
        return;
    if (conn->state != CLIENT_CONNECTION_INIT)
        return;

    http_engine_header(&conn->eng, str);
}

void http_request_builder_body(HTTP_RequestBuilder handle, HTTP_String str)
{
    ClientConnection *conn = client_builder_to_conn(handle);
    if (conn == NULL)
        return;
    if (conn->state != CLIENT_CONNECTION_INIT)
        return;

    http_engine_body(&conn->eng, str);
}

void http_request_builder_submit(HTTP_RequestBuilder handle)
{
    HTTP_Client *client = handle.data0;
    ClientConnection *conn = client_builder_to_conn(handle);
    if (conn == NULL)
        return;
    if (conn->state != CLIENT_CONNECTION_INIT &&
        conn->state != CLIENT_CONNECTION_INIT_ERROR)
        return;

    // TODO: invalidate the handle

    if (conn->state == CLIENT_CONNECTION_INIT_ERROR) {

        conn->state = CLIENT_CONNECTION_DONE;

        int tail = (client->ready_head + client->ready_count) % CLIENT_MAX_CONNS;
        client->ready[tail] = conn - client->conns;
        client->ready_count++;

    } else {
        http_engine_done(&conn->eng);
        conn->state = CLIENT_CONNECTION_WAIT;
    }
}

void http_response_free(HTTP_Response *res)
{
    if (res == NULL)
        return;

    HTTP_Client *client = res->context;

    ClientConnection *conn = NULL;
    for (int i = 0, j = 0; j < client->num_conns; i++) {

        if (client->conns[i].state == CLIENT_CONNECTION_FREE)
            continue;
        j++;

        if (client->conns[i].state != CLIENT_CONNECTION_DONE)
            continue;

        if (http_engine_getres(&client->conns[i].eng) == res) {
            conn = &client->conns[i];
            break;
        }
    }

    HTTP_ASSERT(conn);

    http_engine_free(&conn->eng);
    conn->state = CLIENT_CONNECTION_FREE;
    client->num_conns--;
}

static HTTP_Client *default_client___; // TODO: deinitialize the default client when http_global_free is called

static HTTP_Client *get_default_client(void)
{
    if (default_client___ == NULL)
        default_client___ = http_client_init();
    return default_client___;
}

HTTP_Response *http_get(HTTP_String url, HTTP_String *headers, int num_headers)
{
    HTTP_Client *client = get_default_client();
    if (client == NULL)
        return NULL;

    HTTP_RequestBuilder builder;
    int ret = http_client_get_builder(client, &builder);
    if (ret < 0)
        return NULL;
    http_request_builder_line(builder, HTTP_METHOD_GET, url);
    for (int i = 0; i < num_headers; i++)
        http_request_builder_header(builder, headers[i]);
    http_request_builder_submit(builder);

    HTTP_Response *res;
    ret = http_client_wait(client, &res, NULL); // TODO: it's assumed there is only one request pending
    if (ret < 0)
        return NULL;

    return res;
}

HTTP_Response *http_post(HTTP_String url, HTTP_String *headers, int num_headers, HTTP_String body)
{
    HTTP_Client *client = get_default_client();
    if (client == NULL)
        return NULL;

    HTTP_RequestBuilder builder;
    int ret = http_client_get_builder(client, &builder);
    if (ret < 0)
        return NULL;
    http_request_builder_line(builder, HTTP_METHOD_POST, url);
    for (int i = 0; i < num_headers; i++)
        http_request_builder_header(builder, headers[i]);
    http_request_builder_body(builder, body);
    http_request_builder_submit(builder);

    HTTP_Response *res;
    ret = http_client_wait(client, &res, NULL); // TODO: it's assumed there is only one request pending
    if (ret < 0)
        return NULL;

    return res;
}

////////////////////////////////////////////////////////////////////////////////////////
// src/server.c
////////////////////////////////////////////////////////////////////////////////////////

#line 1 "src/server.c"
#include <stdint.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdbool.h>

#ifndef HTTP_AMALGAMATION
#include "engine.h"
#include "server.h"
#include "socket_pool.h"
#endif

#define MAX_CONNS (1<<10)

typedef struct {
    bool         used;
    uint16_t     gen;
    HTTP_Engine  engine;
    SocketHandle sock;
} Connection;

struct HTTP_Server {

    SocketPool *socket_pool;

    int num_conns;
    Connection conns[MAX_CONNS];

    int ready_head;
    int ready_count;
    int ready[MAX_CONNS];
};

HTTP_Server *http_server_init(HTTP_String addr, uint16_t port)
{
    return http_server_init_ex(addr, port, 0, HTTP_STR(""), HTTP_STR(""));
}

HTTP_Server *http_server_init_ex(HTTP_String addr, uint16_t port,
    uint16_t secure_port, HTTP_String cert_file, HTTP_String key_file)
{
    HTTP_Server *server = malloc(sizeof(HTTP_Server));
    if (server == NULL)
        return NULL;

    int backlog = 32;
    bool reuse_addr = true;
    SocketPool *socket_pool = socket_pool_init(addr, port, secure_port, MAX_CONNS, reuse_addr, backlog, cert_file, key_file);
    if (socket_pool == NULL) {
        free(server);
        return NULL;
    }

    server->socket_pool = socket_pool;
    server->num_conns = 0;
    server->ready_head = 0;
    server->ready_count = 0;

    for (int i = 0; i < MAX_CONNS; i++) {
        server->conns[i].used = false;
        server->conns[i].gen = 1;
    }

    return server;
}

void http_server_free(HTTP_Server *server)
{
    for (int i = 0, j = 0; j < server->num_conns; i++) {

        if (!server->conns[i].used)
            continue;
        j++;

        // TODO
    }

    socket_pool_free(server->socket_pool);
    free(server);
}

int http_server_add_website(HTTP_Server *server, HTTP_String domain, HTTP_String cert_file, HTTP_String key_file)
{
    return socket_pool_add_cert(server->socket_pool, domain, cert_file, key_file);
}

static void* server_memfunc(HTTP_MemoryFuncTag tag, void *ptr, int len, void *data) {
    (void)data;
    switch (tag) {
        case HTTP_MEMFUNC_MALLOC:
            return malloc(len);
        case HTTP_MEMFUNC_FREE:
            free(ptr);
            return NULL;
    }
    return NULL;
}

int http_server_wait(HTTP_Server *server, HTTP_Request **req, HTTP_ResponseBuilder *builder)
{
    while (server->ready_count == 0) {

        SocketEvent event = socket_pool_wait(server->socket_pool);
        switch (event.type) {

            case SOCKET_EVENT_DIED:
            {
                Connection *conn = event.user_data;
                HTTP_ASSERT(conn);

                http_engine_free(&conn->engine);
                conn->used = false;
                conn->gen++;
                server->num_conns--;
            }
            break;

            case SOCKET_EVENT_READY:
            {
                Connection *conn = event.user_data;
                if (conn == NULL) {

                    // Connection was just accepted

                    if (server->num_conns == MAX_CONNS) {
                        socket_pool_close(server->socket_pool, event.handle);
                        break;
                    }

                    int i = 0;
                    while (server->conns[i].used)
                        i++;

                    conn = &server->conns[i];
                    conn->used = true;
                    conn->sock = event.handle;
                    http_engine_init(&conn->engine, 0, server_memfunc, NULL);
                    socket_pool_set_user_data(server->socket_pool, event.handle, conn);
                    server->num_conns++;
                }

                switch (http_engine_state(&conn->engine)) {

                    int len;
                    char *buf;

                    case HTTP_ENGINE_STATE_SERVER_RECV_BUF:
                    buf = http_engine_recvbuf(&conn->engine, &len);
                    if (buf) {
                        int ret = socket_pool_read(server->socket_pool, conn->sock, buf, len);
                        http_engine_recvack(&conn->engine, ret);
                    }
                    break;

                    case HTTP_ENGINE_STATE_SERVER_SEND_BUF:
                    buf = http_engine_sendbuf(&conn->engine, &len);
                    if (buf) {
                        int ret = socket_pool_write(server->socket_pool, conn->sock, buf, len);
                        http_engine_sendack(&conn->engine, ret);
                    }
                    break;

                    default:
                    break;
                }

                switch (http_engine_state(&conn->engine)) {

                    int tail;

                    case HTTP_ENGINE_STATE_SERVER_PREP_STATUS:
                    tail = (server->ready_head + server->ready_count) % MAX_CONNS;
                    server->ready[tail] = conn - server->conns;
                    server->ready_count++;
                    break;

                    case HTTP_ENGINE_STATE_SERVER_CLOSED:
                    socket_pool_close(server->socket_pool, conn->sock);
                    break;

                    default:
                    break;
                }
            }
            break;

            case SOCKET_EVENT_ERROR:
            return -1;

            case SOCKET_EVENT_SIGNAL:
            return 1;
        }
    }

    int index = server->ready[server->ready_head];
    server->ready_head = (server->ready_head + 1) % MAX_CONNS;
    server->ready_count--;

    *req = http_engine_getreq(&server->conns[index].engine);
    (*req)->secure = socket_pool_secure(server->socket_pool, server->conns[index].sock);

    *builder = (HTTP_ResponseBuilder) { server, index, server->conns[index].gen };
    return 0;
}

static Connection*
server_builder_to_conn(HTTP_ResponseBuilder builder)
{
	HTTP_Server *server = builder.data0;
	if (builder.data1 >= MAX_CONNS)
		return NULL;

	Connection *conn = &server->conns[builder.data1];
	if (conn->gen != builder.data2)
		return NULL;

	return conn;
}

void http_response_builder_status(HTTP_ResponseBuilder res, int status)
{
	Connection *conn = server_builder_to_conn(res);
	if (conn == NULL)
		return;

	http_engine_status(&conn->engine, status);
}

void http_response_builder_header(HTTP_ResponseBuilder res, HTTP_String str)
{
	Connection *conn = server_builder_to_conn(res);
	if (conn == NULL)
		return;

	http_engine_header(&conn->engine, str);
}

void http_response_builder_body(HTTP_ResponseBuilder res, HTTP_String str)
{
	Connection *conn = server_builder_to_conn(res);
	if (conn == NULL)
		return;

	http_engine_body(&conn->engine, str);
}

void http_response_builder_bodycap(HTTP_ResponseBuilder res, int mincap)
{
	Connection *conn = server_builder_to_conn(res);
	if (conn == NULL)
		return;

	http_engine_bodycap(&conn->engine, mincap);
}

char *http_response_builder_bodybuf(HTTP_ResponseBuilder res, int *cap)
{
	Connection *conn = server_builder_to_conn(res);
	if (conn == NULL) {
		*cap = 0;
		return NULL;
	}

	return http_engine_bodybuf(&conn->engine, cap);
}

void http_response_builder_bodyack(HTTP_ResponseBuilder res, int num)
{
	Connection *conn = server_builder_to_conn(res);
	if (conn == NULL)
		return;

	http_engine_bodyack(&conn->engine, num);
}

void http_response_builder_undo(HTTP_ResponseBuilder res)
{
	Connection *conn = server_builder_to_conn(res);
	if (conn == NULL)
		return;

	http_engine_undo(&conn->engine);
}

void http_response_builder_done(HTTP_ResponseBuilder res)
{
    HTTP_Server *server = res.data0;
    Connection *conn = server_builder_to_conn(res);
    if (conn == NULL)
        return;

    http_engine_done(&conn->engine);

    conn->gen++;
    if (conn->gen == 0 || conn->gen == UINT16_MAX)
        conn->gen = 1;

    HTTP_EngineState state = http_engine_state(&conn->engine);

    if (state == HTTP_ENGINE_STATE_SERVER_PREP_STATUS) {
        int tail = (server->ready_head + server->ready_count) % MAX_CONNS;
        server->ready[tail] = res.data1;
        server->ready_count++;
    }

    if (state == HTTP_ENGINE_STATE_SERVER_CLOSED)
        socket_pool_close(server->socket_pool, conn->sock);
}

////////////////////////////////////////////////////////////////////////////////////////
// src/router.c
////////////////////////////////////////////////////////////////////////////////////////

#line 1 "src/router.c"
#include <string.h>
#include <stdlib.h>
#include <limits.h>

#ifdef _WIN32
#include <windows.h>
#endif

#ifdef __linux__
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#endif

#ifndef HTTP_AMALGAMATION
#include "router.h"
#endif

#ifndef HTTP_AMALGAMATION
bool is_alpha(char c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}
bool is_digit(char c)
{
	return c >= '0' && c <= '9';
}
#endif // HTTP_AMALGAMATION

typedef enum {
	ROUTE_STATIC_DIR,
	ROUTE_DYNAMIC,
} RouteType;

typedef struct {
	RouteType type;
	HTTP_String endpoint;
	HTTP_String path;
	HTTP_RouterFunc func;
	void *ptr;
} Route;

struct HTTP_Router {
	int num_routes;
	int max_routes;
	Route routes[];
};

HTTP_Router *http_router_init(void)
{
	int max_routes = 32;
	HTTP_Router *router = malloc(sizeof(HTTP_Router) + max_routes * sizeof(Route));
	if (router == NULL)
		return NULL;
	router->max_routes = max_routes;
	router->num_routes = 0;
	return router;
}

void http_router_free(HTTP_Router *router)
{
	free(router);
}

void http_router_dir(HTTP_Router *router, HTTP_String endpoint, HTTP_String path)
{
	if (router->num_routes == router->max_routes)
		abort();
	Route *route = &router->routes[router->num_routes++];
	route->type = ROUTE_STATIC_DIR;
	route->endpoint = endpoint;
	route->path = path;
}

void http_router_func(HTTP_Router *router, HTTP_Method method,
	HTTP_String endpoint, HTTP_RouterFunc func, void *ptr)
{
	if (router->num_routes == router->max_routes)
		abort();
	Route *route = &router->routes[router->num_routes++];
	(void) method; // TODO: Don't ignore the method
	route->type = ROUTE_DYNAMIC;
	route->endpoint = endpoint;
	route->func = func;
	route->ptr  = ptr;
}

static int valid_component_char(char c)
{
	return is_alpha(c) || is_digit(c) || c == '-' || c == '_' || c == '.'; // TODO
}

static int parse_and_sanitize_path(HTTP_String path, HTTP_String *comps, int max_comps)
{
	// We treat relative and absolute paths the same
	if (path.len > 0 && path.ptr[0] == '/') {
		path.ptr++;
		path.len--;
		if (path.len == 0)
			return 0;
	}

	int num = 0;
	int cur = 0;
	for (;;) {
		if (cur == path.len || !valid_component_char(path.ptr[cur]))
			return -1; // Empty component
		int start = cur;
		do
			cur++;
		while (cur < path.len && valid_component_char(path.ptr[cur]));
		HTTP_String comp = { path.ptr + start, cur - start };

		if (http_streq(comp, HTTP_STR(".."))) {
			if (num == 0)
				return -1;
			num--;
		} else if (!http_streq(comp, HTTP_STR("."))) {
			if (num == max_comps)
				return -1;
			comps[num++] = comp;
		}

		if (cur < path.len) {
			if (path.ptr[cur] != '/')
				return -1;
			cur++;
		}

		if (cur == path.len)
			break;
	}

	return num;
}

static int
serialize_parsed_path(HTTP_String *comps, int num_comps, char *dst, int max)
{
	int len = 0;
	for (int i = 0; i < num_comps; i++)
		len += comps[i].len + 1;

	if (len >= max)
		return -1;

	int copied = 0;
	for (int i = 0; i < num_comps; i++) {

		if (i > 0)
			dst[copied++] = '/';

		memcpy(dst + copied,
			comps[i].ptr,
			comps[i].len);

		copied += comps[i].len;
	}

	dst[copied] = '\0';
	return copied;
}

#define MAX_COMPS 32

static int sanitize_path(HTTP_String path, char *dst, int max)
{
	HTTP_String comps[MAX_COMPS];
	int num_comps = parse_and_sanitize_path(path, comps, MAX_COMPS);
	if (num_comps < 0) return -1;

	return serialize_parsed_path(comps, num_comps, dst, max);
}

static int swap_parents(HTTP_String original_parent_path, HTTP_String new_parent_path, HTTP_String path, char *mem, int max)
{
	int num_original_parent_path_comps;
	HTTP_String  original_parent_path_comps[MAX_COMPS];

	int num_new_parent_path_comps;
	HTTP_String  new_parent_path_comps[MAX_COMPS];

	int num_path_comps;
	HTTP_String  path_comps[MAX_COMPS];

	num_original_parent_path_comps = parse_and_sanitize_path(original_parent_path, original_parent_path_comps, MAX_COMPS);
	num_new_parent_path_comps      = parse_and_sanitize_path(new_parent_path,      new_parent_path_comps,      MAX_COMPS);
	num_path_comps                 = parse_and_sanitize_path(path,                 path_comps,                 MAX_COMPS);
	if (num_original_parent_path_comps < 0 || num_new_parent_path_comps < 0 || num_path_comps < 0)
		return -1;

	int match = 1;
	if (num_path_comps < num_original_parent_path_comps)
		match = 0;
	else {
		for (int i = 0; i < num_original_parent_path_comps; i++)
			if (!http_streq(original_parent_path_comps[i], path_comps[i])) {
				match = 0;
				break;
			}
	}
	if (!match)
		return 0;

	int num_result_comps = num_new_parent_path_comps + num_path_comps - num_original_parent_path_comps;
	if (num_result_comps < 0 || num_result_comps > MAX_COMPS)
		return -1;
	
	HTTP_String result_comps[MAX_COMPS];
	for (int i = 0; i < num_new_parent_path_comps; i++)
		result_comps[i] = new_parent_path_comps[i];
	
	for (int i = 0; i < num_path_comps; i++)
		result_comps[num_new_parent_path_comps + i] = path_comps[num_original_parent_path_comps + i];

	return serialize_parsed_path(result_comps, num_result_comps, mem, max);
}

#if _WIN32
typedef HANDLE File;
#else
typedef int File;
#endif

static int file_open(const char *path, File *handle, int *size)
{
#ifdef _WIN32
	*handle = CreateFileA(
		path,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);
	if (*handle == INVALID_HANDLE_VALUE) {
		DWORD error = GetLastError();
		if (error == ERROR_FILE_NOT_FOUND)
			return 1;
		if (error == ERROR_ACCESS_DENIED)
			return 1;
		return -1;
	}
	LARGE_INTEGER fileSize;
	if (!GetFileSizeEx(*handle, &fileSize)) {
		CloseHandle(*handle);
		return -1;
	}
	if (fileSize.QuadPart > INT_MAX) {
		CloseHandle(*handle);
		return -1;
	}
	*size = (int) fileSize.QuadPart;
	return 0;
#else
	*handle = open(path, O_RDONLY);
	if (*handle < 0) {
		if (errno == ENOENT)
			return 1;
		return -1;
	}
	struct stat info;
	if (fstat(*handle, &info) < 0) {
		close(*handle);
		return -1;
	}
	if (S_ISDIR(info.st_mode)) {
		close(*handle);
		return 1;
	}
	if (info.st_size > INT_MAX) {
		close(*handle);
		return -1;
	}
	*size = (int) info.st_size;
	return 0;
#endif
}

static void file_close(File file)
{
#ifdef _WIN32
	CloseHandle(file);
#else
	close(file);
#endif
}

static int file_read(File file, char *dst, int max)
{
#ifdef _WIN32
	DWORD num;
	BOOL ok = ReadFile(file, dst, max, &num, NULL);
	if (!ok)
		return -1;
	return (int) num;
#else
	return read(file, dst, max);
#endif
}

static int serve_file_or_index(HTTP_ResponseBuilder res, HTTP_String base_endpoint, HTTP_String base_path, HTTP_String endpoint)
{
	char mem[1<<12];
	int ret = swap_parents(base_endpoint, base_path, endpoint, mem, sizeof(mem));
	if (ret <= 0)
		return ret;
	HTTP_String path = {mem, ret}; // Note that this is zero terminated

	int size;
	File file;
	ret = file_open(path.ptr, &file, &size);
	if (ret == -1) {
		http_response_builder_status(res, 500);
		http_response_builder_done(res);
		return 1;
	}
	if (ret == 1) {

		// File missing

		char index[] = "index.html";
		if (path.len + sizeof(index) + 1 > sizeof(mem)) {
			http_response_builder_status(res, 500);
			http_response_builder_done(res);
			return 1;
		}
		path.ptr[path.len++] = '/';
		memcpy(path.ptr + path.len, index, sizeof(index));
		path.len += sizeof(index)-1;

		ret = file_open(path.ptr, &file, &size);
		if (ret == -1) {
			http_response_builder_status(res, 500);
			http_response_builder_done(res);
			return 1;
		}
		if (ret == 1)
			return 0; // File missing
	}
	HTTP_ASSERT(ret == 0);

	int cap;
	char *dst;
	http_response_builder_status(res, 200);
	http_response_builder_bodycap(res, size);
	dst = http_response_builder_bodybuf(res, &cap);
	if (dst) {
		int copied = 0;
		while (copied < size) {
			int ret = file_read(file, dst + copied, size - copied);
			if (ret < 0) goto err;
			if (ret == 0) break;
			copied += ret;
		}
		if (copied < size) goto err;
		http_response_builder_bodyack(res, size);
	}
	http_response_builder_done(res);
	file_close(file);
	return 1;
err:
	http_response_builder_bodyack(res, 0);
	http_response_builder_undo(res);
	http_response_builder_status(res, 500);
	http_response_builder_done(res);
	file_close(file);
	return 1;
}

static int serve_dynamic_route(Route *route, HTTP_Request *req, HTTP_ResponseBuilder res)
{
	char path_mem[1<<12];
	int path_len = sanitize_path(req->url.path, path_mem, (int) sizeof(path_mem));
	if (path_len < 0) {
		http_response_builder_status(res, 400);
		http_response_builder_body(res, HTTP_STR("Invalid path"));
		http_response_builder_done(res);
		return 1;
	}
	HTTP_String path = {path_mem, path_len};

	if (!http_streq(path, route->endpoint))
		return 0;

	route->func(req, res, route->ptr);
	return 1;
}

void http_router_resolve(HTTP_Router *router, HTTP_Request *req, HTTP_ResponseBuilder res)
{
	for (int i = 0; i < router->num_routes; i++) {
		Route *route = &router->routes[i];
		switch (route->type) {
		case ROUTE_STATIC_DIR:
			if (serve_file_or_index(res,
				route->endpoint,
				route->path,
				req->url.path))
				return;
			break;

		case ROUTE_DYNAMIC:
			if (serve_dynamic_route(route, req, res))
				return;
			break;

		default:
			http_response_builder_status(res, 500);
			http_response_builder_done(res);
			return;
		}
	}
	http_response_builder_status(res, 404);
	http_response_builder_done(res);
}

int http_serve(char *addr, int port, HTTP_Router *router)
{
	int ret;

	HTTP_Server *server = http_server_init_ex((HTTP_String) { addr, strlen(addr) }, port, 0, (HTTP_String) {}, (HTTP_String) {});
	if (server == NULL) {
		http_router_free(router);
		return -1;
	}

	for (;;) {
		HTTP_Request *req;
		HTTP_ResponseBuilder res;
		ret = http_server_wait(server, &req, &res);
		if (ret < 0) {
			http_server_free(server);
			http_router_free(router);
			return -1;
		}
		if (ret == 0)
			continue;
		http_router_resolve(router, req, res);
	}

	http_server_free(server);
	http_router_free(router);
	return 0;
}
#undef MIN
#undef MAX
#undef ASSERT
#undef SIZEOF
#undef TRACE
#define Scanner WL_Scanner
#define Token WL_Token
#define is_space is_space__wl
#define is_digit is_digit__wl
#define is_alpha is_alpha__wl
#define is_printable is_printable__wl
#define is_hex_digit is_hex_digit__wl
#define hex_digit_to_int hex_digit_to_int__wl
#define consume_str consume_str__wl

////////////////////////////////////////////////////////////////////////////////////////
// 3p/wl.h
////////////////////////////////////////////////////////////////////////////////////////

#line 1 "3p/wl.h"
#include <stdint.h>
#include <stdbool.h>

typedef struct WL_Runtime  WL_Runtime;
typedef struct WL_Compiler WL_Compiler;

typedef struct {
    char *ptr;
    int   len;
} WL_String;

typedef struct {
    char *ptr;
    int   len;
    int   cur;
} WL_Arena;

typedef struct {
    char *ptr;
    int   len;
} WL_Program;

typedef enum {
    WL_ADD_ERROR,
    WL_ADD_AGAIN,
    WL_ADD_LINK,
} WL_AddResultType;

typedef struct {
    WL_AddResultType type;
    WL_String        path;
} WL_AddResult;

typedef enum {
    WL_EVAL_NONE,
    WL_EVAL_DONE,
    WL_EVAL_ERROR,
    WL_EVAL_OUTPUT,
    WL_EVAL_SYSVAR,
    WL_EVAL_SYSCALL,
} WL_EvalResultType;

typedef struct {
    WL_EvalResultType type;
    WL_String str;
} WL_EvalResult;

WL_Compiler*  wl_compiler_init  (WL_Arena *arena);
WL_AddResult  wl_compiler_add   (WL_Compiler *compiler, WL_String path, WL_String content);
int           wl_compiler_link  (WL_Compiler *compiler, WL_Program *program);
WL_String     wl_compiler_error (WL_Compiler *compiler);
int           wl_dump_ast       (WL_Compiler *compiler, char *dst, int cap);
void          wl_dump_program   (WL_Program program);

WL_Runtime*   wl_runtime_init   (WL_Arena *arena, WL_Program program);
WL_EvalResult wl_runtime_eval   (WL_Runtime *rt);
WL_String     wl_runtime_error  (WL_Runtime *rt);
void          wl_runtime_dump   (WL_Runtime *rt);

bool wl_streq      (WL_String a, char *b, int blen);
int  wl_arg_count  (WL_Runtime *rt);
bool wl_arg_none   (WL_Runtime *rt, int idx);
bool wl_arg_bool   (WL_Runtime *rt, int idx, bool *x);
bool wl_arg_s64    (WL_Runtime *rt, int idx, int64_t *x);
bool wl_arg_f64    (WL_Runtime *rt, int idx, double *x);
bool wl_arg_str    (WL_Runtime *rt, int idx, WL_String *x);
bool wl_arg_array  (WL_Runtime *rt, int idx);
bool wl_arg_map    (WL_Runtime *rt, int idx);
bool wl_peek_none  (WL_Runtime *rt, int off);
bool wl_peek_bool  (WL_Runtime *rt, int off, bool *x);
bool wl_peek_s64   (WL_Runtime *rt, int off, int64_t *x);
bool wl_peek_f64   (WL_Runtime *rt, int off, double *x);
bool wl_peek_str   (WL_Runtime *rt, int off, WL_String *x);
bool wl_pop_any    (WL_Runtime *rt);
bool wl_pop_none   (WL_Runtime *rt);
bool wl_pop_bool   (WL_Runtime *rt, bool *x);
bool wl_pop_s64    (WL_Runtime *rt, int64_t *x);
bool wl_pop_f64    (WL_Runtime *rt, double *x);
bool wl_pop_str    (WL_Runtime *rt, WL_String *x);
void wl_push_none  (WL_Runtime *rt);
void wl_push_true  (WL_Runtime *rt);
void wl_push_false (WL_Runtime *rt);
void wl_push_s64   (WL_Runtime *rt, int64_t x);
void wl_push_f64   (WL_Runtime *rt, double x);
void wl_push_str   (WL_Runtime *rt, WL_String x);
void wl_push_array (WL_Runtime *rt, int cap);
void wl_push_map   (WL_Runtime *rt, int cap);
void wl_push_arg   (WL_Runtime *rt, int idx);
void wl_insert     (WL_Runtime *rt);
void wl_append     (WL_Runtime *rt);

////////////////////////////////////////////////////////////////////////////////////////
// 3p/wl.c
////////////////////////////////////////////////////////////////////////////////////////

#line 1 "3p/wl.c"
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#ifndef WL_NOINCLUDE
#include "wl.h"
#endif

/////////////////////////////////////////////////////////////////////////
// BASIC
/////////////////////////////////////////////////////////////////////////

typedef struct {
    char *ptr;
    int   len;
} String;

typedef struct {
    char *buf;
    int   cap;
    bool  yes;
} Error;

#define S(X) (String) { (X), SIZEOF(X)-1 }

#ifdef _WIN32
#define LLD "lld"
#define LLU "llu"
#else
#define LLD "ld"
#define LLU "lu"
#endif

#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))
#define MAX(X, Y) ((X) > (Y) ? (X) : (Y))
#define SIZEOF(X) (int) sizeof(X)
#define ALIGNOF(X) (int) _Alignof(X)
#define COUNT(X) (int) (sizeof(X)/sizeof((X)[0]))

#ifndef NDEBUG
#define UNREACHABLE __builtin_trap()
#define ASSERT(X) if (!(X)) __builtin_trap();
#else
#define UNREACHABLE {}
#define ASSERT(X) {}
#endif

static bool is_space(char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

static bool is_digit(char c)
{
    return c >= '0' && c <= '9';
}

static bool is_alpha(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

static bool is_printable(char c)
{
    return c >= ' ' && c <= '~';
}

static bool is_hex_digit(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

#if 0
static char to_lower(char c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A' + 'a';
    return c;
}
#endif

static int hex_digit_to_int(char c)
{
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;

    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;

    return c - '0';
}

static bool streq(String a, String b)
{
    if (a.len != b.len)
        return false;
    for (int i = 0; i < a.len; i++)
        if (a.ptr[i] != b.ptr[i])
            return false;
    return true;
}

#if 0
static bool streqcase(String a, String b)
{
    if (a.len != b.len)
        return false;
    for (int i = 0; i < a.len; i++)
        if (to_lower(a.ptr[i]) != to_lower(b.ptr[i]))
            return false;
    return true;
}
#endif

#define REPORT(err, fmt, ...) report((err), __FILE__, __LINE__, fmt, ## __VA_ARGS__)
static void report(Error *err, char *file, int line, char *fmt, ...)
{
    if (err->yes) return;

    if (err->cap > 0) {

        va_list args;
        va_start(args, fmt);
        int len = vsnprintf(err->buf, err->cap, fmt, args);
        va_end(args);
        ASSERT(len >= 0);

        if (err->cap > len) {
            int ret = snprintf(err->buf + len, err->cap - len,
                " (reported at %s:%d)", file, line);
            ASSERT(ret >= 0);
            len += ret;
        }

        if (len > err->cap)
            len = err->cap-1;
        err->buf[len] = '\0';
    }

    err->yes = true;
}

/////////////////////////////////////////////////////////////////////////
// ARENA
/////////////////////////////////////////////////////////////////////////

static void *alloc(WL_Arena *a, int len, int align)
{
    int pad = -(intptr_t) (a->ptr + a->cur) & (align-1);
    if (a->len - a->cur < len + pad)
        return NULL;
    void *ret = a->ptr + a->cur + pad;
    a->cur += pad + len;
    return ret;
}

static bool grow_alloc(WL_Arena *a, char *p, int new_len)
{
    int new_cur = (p - a->ptr) + new_len;
    if (new_cur > a->len)
        return false;
    a->cur = new_cur;
    return true;
}

#if 0
static String copystr(String s, WL_Arena *a)
{
    char *p = alloc(a, s.len, 1);
    if (p == NULL)
        return (String) { NULL, 0 };
    memcpy(p, s.ptr, s.len);
    return (String) { p, s.len };
}
#endif

/////////////////////////////////////////////////////////////////////////
// WRITER
/////////////////////////////////////////////////////////////////////////

typedef struct {
    char *dst;
    int   cap;
    int   len;
} Writer;

static void write_raw_mem(Writer *w, void *ptr, int len)
{
    if (w->cap > w->len) {
        int cpy = MIN(w->cap - w->len, len);
        if (ptr && w->dst)
            memcpy(w->dst + w->len, ptr, cpy);
    }
    w->len += len;
}

static void write_raw_u8 (Writer *w, uint8_t  x) { write_raw_mem(w, &x, SIZEOF(x)); }
//static void write_raw_u16(Writer *w, uint16_t x) { write_raw_mem(w, &x, SIZEOF(x)); }
static void write_raw_u32(Writer *w, uint32_t x) { write_raw_mem(w, &x, SIZEOF(x)); }
//static void write_raw_u64(Writer *w, uint64_t x) { write_raw_mem(w, &x, SIZEOF(x)); }
//static void write_raw_s8 (Writer *w, int8_t   x) { write_raw_mem(w, &x, SIZEOF(x)); }
//static void write_raw_s16(Writer *w, int16_t  x) { write_raw_mem(w, &x, SIZEOF(x)); }
//static void write_raw_s32(Writer *w, int32_t  x) { write_raw_mem(w, &x, SIZEOF(x)); }
static void write_raw_s64(Writer *w, int64_t  x) { write_raw_mem(w, &x, SIZEOF(x)); }
//static void write_raw_f32(Writer *w, float    x) { write_raw_mem(w, &x, SIZEOF(x)); }
static void write_raw_f64(Writer *w, double   x) { write_raw_mem(w, &x, SIZEOF(x)); }

static void write_text(Writer *w, String str)
{
    write_raw_mem(w, str.ptr, str.len);
}

static void write_text_s64(Writer *w, int64_t n)
{
    int len;
    if (w->len < w->cap)
        len = snprintf(w->dst + w->len, w->cap - w->len, "%" LLD, n);
    else
        len = snprintf(NULL, 0, "%" LLD, n);
    ASSERT(len >= 0);
    w->len += len;
}

static void write_text_f64(Writer *w, double n)
{
    int len;
    if (w->len < w->cap)
        len = snprintf(w->dst + w->len, w->cap - w->len, "%2.2f", n);
    else
        len = snprintf(NULL, 0, "%2.2f", n);
    ASSERT(len >= 0);
    w->len += len;
}

static void patch_mem(Writer *w, void *src, int off, int len)
{
    ASSERT(off + len <= w->len);
    if (off < w->cap) {
        int cpy = MIN(w->cap - off, len);
        memcpy(w->dst + off, src, cpy);
    }
}

/////////////////////////////////////////////////////////////////////////
// PARSER
/////////////////////////////////////////////////////////////////////////

typedef struct {
    char *src;
    int   len;
    int   cur;
} Scanner;

typedef enum {
    TOKEN_END,
    TOKEN_ERROR,
    TOKEN_IDENT,
    TOKEN_KWORD_IF,
    TOKEN_KWORD_ELSE,
    TOKEN_KWORD_WHILE,
    TOKEN_KWORD_FOR,
    TOKEN_KWORD_IN,
    TOKEN_KWORD_PROCEDURE,
    TOKEN_KWORD_LET,
    TOKEN_KWORD_NONE,
    TOKEN_KWORD_TRUE,
    TOKEN_KWORD_FALSE,
    TOKEN_KWORD_INCLUDE,
    TOKEN_KWORD_LEN,
    TOKEN_KWORD_ESCAPE,
    TOKEN_VALUE_FLOAT,
    TOKEN_VALUE_INT,
    TOKEN_VALUE_STR,
    TOKEN_OPER_EQL,
    TOKEN_OPER_NQL,
    TOKEN_OPER_LSS,
    TOKEN_OPER_GRT,
    TOKEN_OPER_ADD,
    TOKEN_OPER_SUB,
    TOKEN_OPER_MUL,
    TOKEN_OPER_DIV,
    TOKEN_OPER_MOD,
    TOKEN_OPER_ASS,
    TOKEN_OPER_SHOVEL,
    TOKEN_PAREN_OPEN,
    TOKEN_PAREN_CLOSE,
    TOKEN_BRACKET_OPEN,
    TOKEN_BRACKET_CLOSE,
    TOKEN_CURLY_OPEN,
    TOKEN_CURLY_CLOSE,
    TOKEN_DOT,
    TOKEN_COMMA,
    TOKEN_COLON,
    TOKEN_DOLLAR,
    TOKEN_NEWLINE,
} TokType;

typedef struct {
    TokType type;
    int64_t ival;
    double  fval;
    String  sval;
} Token;

typedef enum {
    NODE_PROCEDURE_DECL,
    NODE_PROCEDURE_ARG,
    NODE_PROCEDURE_CALL,
    NODE_VAR_DECL,
    NODE_COMPOUND,
    NODE_GLOBAL,
    NODE_IFELSE,
    NODE_FOR,
    NODE_WHILE,
    NODE_INCLUDE,
    NODE_SELECT,
    NODE_NESTED,
    NODE_OPER_ESCAPE,
    NODE_OPER_LEN,
    NODE_OPER_POS,
    NODE_OPER_NEG,
    NODE_OPER_ASS,
    NODE_OPER_EQL,
    NODE_OPER_NQL,
    NODE_OPER_LSS,
    NODE_OPER_GRT,
    NODE_OPER_ADD,
    NODE_OPER_SUB,
    NODE_OPER_MUL,
    NODE_OPER_DIV,
    NODE_OPER_MOD,
    NODE_OPER_SHOVEL,
    NODE_VALUE_INT,
    NODE_VALUE_FLOAT,
    NODE_VALUE_STR,
    NODE_VALUE_NONE,
    NODE_VALUE_TRUE,
    NODE_VALUE_FALSE,
    NODE_VALUE_VAR,
    NODE_VALUE_SYSVAR,
    NODE_VALUE_HTML,
    NODE_VALUE_ARRAY,
    NODE_VALUE_MAP,
} NodeType;

typedef struct Node Node;
struct Node {
    NodeType type;
    Node *next;

    Node *key;

    Node *left;
    Node *right;

    Node *child;

    uint64_t ival;
    double   fval;
    String   sval;

    String html_tag;
    Node*  html_attr;
    Node*  html_child;
    bool   html_body;

    Node *if_cond;
    Node *if_branch1;
    Node *if_branch2;

    Node *while_cond;
    Node *while_body;

    String for_var1;
    String for_var2;
    Node*  for_set;

    String proc_name;
    Node*  proc_args;
    Node*  proc_body;

    String var_name;
    Node*  var_value;

    String include_path;
    Node*  include_next;
    Node*  include_root;
};

typedef struct {
    Node *node;
    Node *includes;
    int   errlen;
} ParseResult;

typedef struct {
    Scanner   s;
    WL_Arena*    arena;
    char*     errbuf;
    int       errmax;
    int       errlen;
    Node*     include_head;
    Node**    include_tail;
} Parser;

static bool consume_str(Scanner *s, String x)
{
    if (x.len == 0)
        return false;

    if (x.len > s->len - s->cur)
        return false;

    for (int i = 0; i < x.len; i++)
        if (s->src[s->cur+i] != x.ptr[i])
            return false;

    s->cur += x.len;
    return true;
}

#if 0
static void write_token(Writer *w, Token token)
{
    switch (token.type) {

        default                 : write_text(w, S("???"));       break;
        case TOKEN_END          : write_text(w, S("<EOF>"));     break;
        case TOKEN_ERROR        : write_text(w, S("<ERROR>"));   break;
        case TOKEN_IDENT        : write_text(w, token.sval);     break;
        case TOKEN_KWORD_IF     : write_text(w, S("if"));        break;
        case TOKEN_KWORD_ELSE   : write_text(w, S("else"));      break;
        case TOKEN_KWORD_WHILE  : write_text(w, S("while"));     break;
        case TOKEN_KWORD_FOR    : write_text(w, S("for"));       break;
        case TOKEN_KWORD_IN     : write_text(w, S("in"));        break;
        case TOKEN_KWORD_PROCEDURE: write_text(w, S("procedure")); break;
        case TOKEN_KWORD_LET    : write_text(w, S("let"));       break;
        case TOKEN_KWORD_NONE   : write_text(w, S("none"));      break;
        case TOKEN_KWORD_TRUE   : write_text(w, S("true"));      break;
        case TOKEN_KWORD_FALSE  : write_text(w, S("false"));     break;
        case TOKEN_KWORD_INCLUDE: write_text(w, S("include"));   break;
        case TOKEN_KWORD_LEN    : write_text(w, S("len"));       break;
        case TOKEN_KWORD_ESCAPE: write_text(w, S("escape")); break;
        case TOKEN_VALUE_FLOAT  : write_text_f64(w, token.fval); break;
        case TOKEN_VALUE_INT    : write_text_s64(w, token.ival); break;
        case TOKEN_OPER_ASS     : write_text(w, S("="));         break;
        case TOKEN_OPER_EQL     : write_text(w, S("=="));        break;
        case TOKEN_OPER_NQL     : write_text(w, S("!="));        break;
        case TOKEN_OPER_LSS     : write_text(w, S("<"));         break;
        case TOKEN_OPER_GRT     : write_text(w, S(">"));         break;
        case TOKEN_OPER_ADD     : write_text(w, S("+"));         break;
        case TOKEN_OPER_SUB     : write_text(w, S("-"));         break;
        case TOKEN_OPER_MUL     : write_text(w, S("*"));         break;
        case TOKEN_OPER_DIV     : write_text(w, S("/"));         break;
        case TOKEN_OPER_MOD     : write_text(w, S("%"));         break;
        case TOKEN_OPER_SHOVEL  : write_text(w, S("<<"));        break;
        case TOKEN_PAREN_OPEN   : write_text(w, S("("));         break;
        case TOKEN_PAREN_CLOSE  : write_text(w, S(")"));         break;
        case TOKEN_BRACKET_OPEN : write_text(w, S("["));         break;
        case TOKEN_BRACKET_CLOSE: write_text(w, S("]"));         break;
        case TOKEN_CURLY_OPEN   : write_text(w, S("{"));         break;
        case TOKEN_CURLY_CLOSE  : write_text(w, S("}"));         break;
        case TOKEN_DOT          : write_text(w, S("."));         break;
        case TOKEN_COMMA        : write_text(w, S(","));         break;
        case TOKEN_COLON        : write_text(w, S(":"));         break;
        case TOKEN_DOLLAR       : write_text(w, S("$"));         break;
        case TOKEN_NEWLINE      : write_text(w, S("\\n"));       break;

        case TOKEN_VALUE_STR:
        write_text(w, S("\""));
        write_text(w, token.sval); // TODO: Escape
        write_text(w, S("\""));
        break;

    }
}
#endif

static void parser_report(Parser *p, char *fmt, ...)
{
    if (p->errmax == 0 || p->errlen > 0)
        return;

    int line = 1;
    int cur = 0;
    while (cur < p->s.cur) {
        if (p->s.src[cur] == '\n')
            line++;
        cur++;
    }

    int len = snprintf(p->errbuf, p->errmax, "Error (line %d): ", line);
    ASSERT(len >= 0);

    va_list args;
    va_start(args, fmt);
    int ret = vsnprintf(p->errbuf + len, p->errmax - len, fmt, args);
    va_end(args);
    ASSERT(ret >= 0);
    len += ret;

    p->errlen = len;
}

static Node *alloc_node(Parser *p)
{
    Node *n = alloc(p->arena, sizeof(Node), _Alignof(Node));
    if (n == NULL) {
        parser_report(p, "Out of memory");
        return NULL;
    }

    return n;
}

static Token next_token(Parser *p)
{
    for (;;) {
        while (p->s.cur < p->s.len && is_space(p->s.src[p->s.cur]))
            p->s.cur++;

        if (!consume_str(&p->s, S("<!--")))
            break;

        while (p->s.cur < p->s.len) {
            if (consume_str(&p->s, S("-->")))
                break;
            p->s.cur++;
        }
    }

    if (p->s.cur == p->s.len)
        return (Token) { .type=TOKEN_END };
    char c = p->s.src[p->s.cur];

    if (is_alpha(c) || c == '_') {

        int start = p->s.cur;
        do
            p->s.cur++;
        while (p->s.cur < p->s.len && (is_alpha(p->s.src[p->s.cur]) || is_digit(p->s.src[p->s.cur]) || p->s.src[p->s.cur] == '_'));

        String kword = {
            p->s.src + start,
            p->s.cur - start
        };

        if (streq(kword, S("if")))      return (Token) { .type=TOKEN_KWORD_IF      };
        if (streq(kword, S("else")))    return (Token) { .type=TOKEN_KWORD_ELSE    };
        if (streq(kword, S("while")))   return (Token) { .type=TOKEN_KWORD_WHILE   };
        if (streq(kword, S("for")))     return (Token) { .type=TOKEN_KWORD_FOR     };
        if (streq(kword, S("in")))      return (Token) { .type=TOKEN_KWORD_IN      };
        if (streq(kword, S("procedure"))) return (Token) { .type=TOKEN_KWORD_PROCEDURE };
        if (streq(kword, S("let")))     return (Token) { .type=TOKEN_KWORD_LET     };
        if (streq(kword, S("none")))    return (Token) { .type=TOKEN_KWORD_NONE    };
        if (streq(kword, S("true")))    return (Token) { .type=TOKEN_KWORD_TRUE    };
        if (streq(kword, S("false")))   return (Token) { .type=TOKEN_KWORD_FALSE   };
        if (streq(kword, S("include"))) return (Token) { .type=TOKEN_KWORD_INCLUDE };
        if (streq(kword, S("len")))     return (Token) { .type=TOKEN_KWORD_LEN     };
        if (streq(kword, S("escape"))) return (Token) { .type=TOKEN_KWORD_ESCAPE };

        return (Token) { .type=TOKEN_IDENT, .sval=kword };
    }

    if (is_digit(c)) {

        int peek = p->s.cur;
        do
            peek++;
        while (peek < p->s.len && is_digit(p->s.src[peek]));

        if (p->s.len - peek > 1 && p->s.src[peek] == '.' && is_digit(p->s.src[peek+1])) {

            double buf = 0;
            do {
                int d = p->s.src[p->s.cur++] - '0';
                buf = buf * 10 + d;
            } while (p->s.cur < p->s.len && p->s.src[p->s.cur] != '.');

            p->s.cur++;

            double q = 1;
            do {
                int d = p->s.src[p->s.cur++] - '0';
                q /= 10;
                buf += q * d;
            } while (p->s.cur < p->s.len && is_digit(p->s.src[p->s.cur]));

            return (Token) { .type=TOKEN_VALUE_FLOAT, .fval=buf };

        } else {

            uint64_t buf = 0;
            do {
                int d = p->s.src[p->s.cur++] - '0';
                if (buf > (UINT64_MAX - d) / 10) {
                    parser_report(p, "Integer literal overflow");
                    return (Token) { .type=TOKEN_ERROR };
                }
                buf = buf * 10 + d;
            } while (p->s.cur < p->s.len && is_digit(p->s.src[p->s.cur]));

            return (Token) { .type=TOKEN_VALUE_INT, .ival=buf };
        }
    }

    if (c == '\'' || c == '"') {

        char f = c;
        p->s.cur++;

        char *buf = NULL;
        int   len = 0;

        for (;;) {

            int substr_off = p->s.cur;

            while (p->s.cur < p->s.len && is_printable(p->s.src[p->s.cur]) && p->s.src[p->s.cur] != f && p->s.src[p->s.cur] != '\\')
                p->s.cur++;

            int substr_len = p->s.cur - substr_off;

            if (buf == NULL)
                buf = alloc(p->arena, substr_len+1, 1);
            else
                if (!grow_alloc(p->arena, buf, len + substr_len+1))
                    buf = NULL;

            if (buf == NULL) {
                parser_report(p, "Out of memory");
                return (Token) { .type=TOKEN_ERROR };
            }

            if (substr_len > 0) {
                memcpy(
                    buf + len,
                    p->s.src + substr_off,
                    p->s.cur - substr_off
                );
                len += substr_len;
            }

            if (p->s.cur == p->s.len) {
                parser_report(p, "String literal wasn't closed");
                return (Token) { .type=TOKEN_ERROR };
            }

            if (!is_printable(p->s.src[p->s.cur])) {
                parser_report(p, "Invalid byte in string literal");
                return (Token) { .type=TOKEN_ERROR };
            }

            if (p->s.src[p->s.cur] == f)
                break;

            p->s.cur++;
            if (p->s.cur == p->s.len) {
                parser_report(p, "Missing special character after escape character \\");
                return (Token) { .type=TOKEN_ERROR };
            }

            switch (p->s.src[p->s.cur]) {
                case 'n':  buf[len++] = '\n'; break;
                case 't':  buf[len++] = '\t'; break;
                case 'r':  buf[len++] = '\r'; break;
                case '"':  buf[len++] = '"';  break;
                case '\'': buf[len++] = '\''; break;
                case '\\': buf[len++] = '\\'; break;

                case 'x':
                {
                    if (p->s.len - p->s.cur < 3
                        || !is_hex_digit(p->s.src[p->s.cur+1])
                        || !is_hex_digit(p->s.src[p->s.cur+2]))
                        return (Token) { .type=TOKEN_ERROR };
                    buf[len++]
                        = (hex_digit_to_int(p->s.src[p->s.cur+1]) << 4)
                        | (hex_digit_to_int(p->s.src[p->s.cur+2]) << 0);
                    p->s.cur += 2;
                }
                break;

                default:
                parser_report(p, "Invalid character after escape character \\");
                return (Token) { .type=TOKEN_ERROR };
            }

            p->s.cur++;
        }

        p->s.cur++;
        return (Token) { .type=TOKEN_VALUE_STR, .sval=(String) { .ptr=buf, .len=len } };
    }

    if (consume_str(&p->s, S("<<"))) return (Token) { .type=TOKEN_OPER_SHOVEL };
    if (consume_str(&p->s, S("=="))) return (Token) { .type=TOKEN_OPER_EQL };
    if (consume_str(&p->s, S("!="))) return (Token) { .type=TOKEN_OPER_NQL };
    if (consume_str(&p->s, S("<")))  return (Token) { .type=TOKEN_OPER_LSS };
    if (consume_str(&p->s, S(">")))  return (Token) { .type=TOKEN_OPER_GRT };
    if (consume_str(&p->s, S("+")))  return (Token) { .type=TOKEN_OPER_ADD };
    if (consume_str(&p->s, S("-")))  return (Token) { .type=TOKEN_OPER_SUB };
    if (consume_str(&p->s, S("*")))  return (Token) { .type=TOKEN_OPER_MUL };
    if (consume_str(&p->s, S("/")))  return (Token) { .type=TOKEN_OPER_DIV };
    if (consume_str(&p->s, S("%")))  return (Token) { .type=TOKEN_OPER_MOD };
    if (consume_str(&p->s, S("=")))  return (Token) { .type=TOKEN_OPER_ASS };

    if (consume_str(&p->s, S("(")))  return (Token) { .type=TOKEN_PAREN_OPEN };
    if (consume_str(&p->s, S(")")))  return (Token) { .type=TOKEN_PAREN_CLOSE };
    if (consume_str(&p->s, S("[")))  return (Token) { .type=TOKEN_BRACKET_OPEN };
    if (consume_str(&p->s, S("]")))  return (Token) { .type=TOKEN_BRACKET_CLOSE };
    if (consume_str(&p->s, S("{")))  return (Token) { .type=TOKEN_CURLY_OPEN };
    if (consume_str(&p->s, S("}")))  return (Token) { .type=TOKEN_CURLY_CLOSE };
    if (consume_str(&p->s, S(".")))  return (Token) { .type=TOKEN_DOT };
    if (consume_str(&p->s, S(",")))  return (Token) { .type=TOKEN_COMMA };
    if (consume_str(&p->s, S(":")))  return (Token) { .type=TOKEN_COLON };
    if (consume_str(&p->s, S("$")))  return (Token) { .type=TOKEN_DOLLAR };

    parser_report(p, "Invalid character '%c'", c);
    return (Token) { .type=TOKEN_ERROR };
}

static Token next_token_or_newline(Parser *p)
{
    int peek = p->s.cur;
    while (peek < p->s.len && is_space(p->s.src[peek]) && p->s.src[peek] != '\n')
        peek++;

    if (peek < p->s.len && p->s.src[peek] == '\n') {
        p->s.cur = peek+1;
        return (Token) { .type=TOKEN_NEWLINE };
    }

    return next_token(p);
}

enum {
    IGNORE_GRT = 1 << 0,
    IGNORE_LSS = 1 << 1,
    IGNORE_DIV = 1 << 2,
};

static Node *parse_stmt(Parser *p, int opflags);
static Node *parse_expr(Parser *p, int opflags);

static Node *parse_html(Parser *p)
{
    // NOTE: The first < was already consumed

    Token t = next_token(p);
    if (t.type != TOKEN_IDENT) {
        parser_report(p, "HTML tag doesn't start with a name");
        return NULL;
    }
    String tagname = t.sval;

    Node *attr_head;
    Node **attr_tail = &attr_head;

    bool no_body = false;
    Scanner *s = &p->s;
    for (;;) {

        int off = s->cur;

        bool quotes = false;
        while (s->cur < s->len && s->src[s->cur] != '\\' && (quotes || (s->src[s->cur] != '/' && s->src[s->cur] != '>'))) {
            if (s->src[s->cur] == '"')
                quotes = !quotes;
            s->cur++;
        }

        if (s->cur > off) {

            Node *child = alloc_node(p);
            if (child == NULL)
                return NULL;

            child->type = NODE_VALUE_STR;
            child->sval = (String) { p->s.src + off, p->s.cur - off };

            *attr_tail = child;
            attr_tail = &child->next;
        }

        if (s->cur == s->len) {
            ASSERT(0); // TODO
        }
        s->cur++;

        if (s->src[s->cur-1] == '>')
            break;

        if (s->src[s->cur-1] == '/') {
            while (s->cur < s->len && is_space(s->src[s->cur]))
                s->cur++;
            if (s->cur == s->len || s->src[s->cur] != '>') {
                ASSERT(0); // TODO
            }
            s->cur++;
            no_body = true;
            break;
        }

        ASSERT(s->src[s->cur-1] == '\\');

        Node *child = parse_stmt(p, IGNORE_GRT | IGNORE_DIV);
        if (child == NULL)
            return NULL;

        *attr_tail = child;
        attr_tail = &child->next;
    }

    *attr_tail = NULL;

    Node *child_head;
    Node **child_tail = &child_head;

    if (no_body == false)
        for (;;) {

            int off = s->cur;

            while (s->cur < s->len && s->src[s->cur] != '\\' && s->src[s->cur] != '<')
                s->cur++;

            if (s->cur > off) {

                Node *child = alloc_node(p);
                if (child == NULL)
                    return NULL;

                child->type = NODE_VALUE_STR;
                child->sval = (String) { p->s.src + off, p->s.cur - off };

                *child_tail = child;
                child_tail = &child->next;
            }

            if (s->cur == s->len) {
                ASSERT(0); // TODO
            }
            s->cur++;

            if (s->src[s->cur-1] == '<') {

                Scanner saved = *s;
                t = next_token(p);
                if (t.type == TOKEN_OPER_DIV) {

                    t = next_token(p);
                    if (t.type != TOKEN_IDENT) {
                        ASSERT(0); // TODO
                    }
                    String closing_tagname = t.sval;

                    if (!streq(closing_tagname, tagname)) {
                        ASSERT(0); // TODO
                    }

                    t = next_token(p);
                    if (t.type != TOKEN_OPER_GRT) {
                        ASSERT(0);
                    }

                    break;
                }

                *s = saved;

                Node *child = parse_html(p);
                if (child == NULL)
                    return NULL;

                *child_tail = child;
                child_tail = &child->next;

            } else {

                Node *child = parse_stmt(p, IGNORE_LSS);
                if (child == NULL)
                    return NULL;

                *child_tail = child;
                child_tail = &child->next;
            }
        }

    *child_tail = NULL;

    Node *parent = alloc_node(p);
    if (parent == NULL)
        return NULL;

    parent->type = NODE_VALUE_HTML;
    parent->html_tag   = tagname;
    parent->html_attr  = attr_head;
    parent->html_child = child_head;
    parent->html_body  = !no_body;

    return parent;
}

static Node *parse_array(Parser *p)
{
    // Left bracket already consumed

    Node *head;
    Node **tail = &head;

    Scanner saved = p->s;
    Token t = next_token(p);
    if (t.type != TOKEN_BRACKET_CLOSE) {

        p->s = saved;

        for (;;) {

            Node *child = parse_expr(p, 0);
            if (child == NULL)
                return NULL;

            *tail = child;
            tail = &child->next;

            saved = p->s;
            t = next_token(p);
            if (t.type == TOKEN_COMMA) {
                saved = p->s;
                t = next_token(p);
            }

            if (t.type == TOKEN_BRACKET_CLOSE)
                break;

            p->s = saved;
        }
    }

    *tail = NULL;

    Node *parent = alloc_node(p);
    if (parent == NULL)
        return NULL;

    parent->type = NODE_VALUE_ARRAY;
    parent->child  = head;

    return parent;
}

static Node *parse_map(Parser *p)
{
    // Left bracket already consumed

    Node *head;
    Node **tail = &head;

    Scanner saved = p->s;
    Token t = next_token(p);
    if (t.type != TOKEN_CURLY_CLOSE) {

        p->s = saved;

        for (;;) {

            Node *key;

            saved = p->s;
            t = next_token(p);
            if (t.type == TOKEN_IDENT) {
   
                key = alloc_node(p);
                if (key == NULL)
                    return NULL;

                key->type = NODE_VALUE_STR;
                key->sval = t.sval;

            } else {

                p->s = saved;
                key = parse_expr(p, 0);
                if (key == NULL)
                    return NULL;
            }

            t = next_token(p);
            if (t.type != TOKEN_COLON) {
                parser_report(p, "Missing ':' after key inside map literal");
                return NULL;
            }

            Node *child = parse_expr(p, 0);
            if (child == NULL)
                return NULL;
            child->key = key;

            *tail = child;
            tail = &child->next;

            saved = p->s;
            t = next_token(p);
            if (t.type == TOKEN_COMMA) {
                saved = p->s;
                t = next_token(p);
            }

            if (t.type == TOKEN_CURLY_CLOSE)
                break;

            p->s = saved;
        }
    }

    *tail = NULL;

    Node *parent = alloc_node(p);
    if (parent == NULL)
        return NULL;

    parent->type = NODE_VALUE_MAP;
    parent->child  = head;

    return parent;
}

static int precedence(Token t, int flags)
{
    switch (t.type) {

        case TOKEN_OPER_ASS:
        return 1;

        case TOKEN_OPER_SHOVEL:
        if (flags & IGNORE_LSS)
            return -1;
        return 1;

        case TOKEN_OPER_EQL:
        case TOKEN_OPER_NQL:
        return 2;

        case TOKEN_OPER_LSS:
        if (flags & IGNORE_LSS)
            return -1;
        return 2;

        case TOKEN_OPER_GRT:
        if (flags & IGNORE_GRT)
            return -1;
        return 2;

        case TOKEN_OPER_ADD:
        case TOKEN_OPER_SUB:
        return 3;

        case TOKEN_OPER_MUL:
        case TOKEN_OPER_MOD:
        return 4;

        case TOKEN_OPER_DIV:
        if (flags & IGNORE_DIV)
            return -1;
        return 4;

        default:
        break;
    }

    return -1;
}

static bool right_associative(Token t)
{
    return t.type == TOKEN_OPER_ASS;
}

static Node *parse_atom(Parser *p)
{
    Token t = next_token(p);

    Node *ret;
    switch (t.type) {
        case TOKEN_OPER_ADD:
        {
            Node *child = parse_atom(p);
            if (child == NULL)
                return NULL;

            Node *parent = alloc_node(p);
            if (parent == NULL)
                return NULL;

            parent->type = NODE_OPER_POS;
            parent->left = child;

            ret = parent;
        }
        break;

        case TOKEN_OPER_SUB:
        {
            Node *child = parse_atom(p);
            if (child == NULL)
                return NULL;

            Node *parent = alloc_node(p);
            if (parent == NULL)
                return NULL;

            parent->type = NODE_OPER_NEG;
            parent->left = child;

            ret = parent;
        }
        break;

        case TOKEN_KWORD_LEN:
        {
            Node *child = parse_atom(p);
            if (child == NULL)
                return NULL;

            Node *parent = alloc_node(p);
            if (parent == NULL)
                return NULL;

            parent->type = NODE_OPER_LEN;
            parent->left = child;

            ret = parent;
        }
        break;

        case TOKEN_KWORD_ESCAPE:
        {
            Node *child = parse_atom(p);
            if (child == NULL)
                return NULL;

            Node *parent = alloc_node(p);
            if (parent == NULL)
                return NULL;

            parent->type = NODE_OPER_ESCAPE;
            parent->left = child;

            ret = parent;
        }
        break;

        case TOKEN_IDENT:
        {
            Node *node = alloc_node(p);
            if (node == NULL)
                return NULL;

            node->type = NODE_VALUE_VAR;
            node->sval = t.sval;

            ret = node;
        }
        break;

        case TOKEN_VALUE_INT:
        {
            Node *node = alloc_node(p);
            if (node == NULL)
                return NULL;

            node->type = NODE_VALUE_INT;
            node->ival = t.ival;

            ret = node;
        }
        break;

        case TOKEN_VALUE_FLOAT:
        {
            Node *node = alloc_node(p);
            if (node == NULL)
                return NULL;

            node->type = NODE_VALUE_FLOAT;
            node->fval = t.fval;

            ret = node;
        }
        break;

        case TOKEN_VALUE_STR:
        {
            Node *node = alloc_node(p);
            if (node == NULL)
                return NULL;

            node->type = NODE_VALUE_STR;
            node->sval = t.sval;

            ret = node;
        }
        break;

        case TOKEN_KWORD_NONE:
        {
            Node *node = alloc_node(p);
            if (node == NULL)
                return NULL;

            node->type = NODE_VALUE_NONE;
            node->sval = t.sval;

            ret = node;
        }
        break;

        case TOKEN_KWORD_TRUE:
        {
            Node *node = alloc_node(p);
            if (node == NULL)
                return NULL;

            node->type = NODE_VALUE_TRUE;
            node->sval = t.sval;

            ret = node;
        }
        break;
        case TOKEN_KWORD_FALSE:
        {
            Node *node = alloc_node(p);
            if (node == NULL)
                return NULL;

            node->type = NODE_VALUE_FALSE;
            node->sval = t.sval;

            ret = node;
        }
        break;

        case TOKEN_OPER_LSS:
        {
            Node *node = parse_html(p);
            if (node == NULL)
                return NULL;

            ret = node;
        }
        break;

        case TOKEN_PAREN_OPEN:
        {
            Node *node = parse_expr(p, 0);
            if (node == NULL)
                return NULL;

            Token t = next_token(p);
            if (t.type != TOKEN_PAREN_CLOSE) {
                parser_report(p, "Missing ')' after expression");
                return NULL;
            }

            Node *parent = alloc_node(p);
            if (parent == NULL)
                return NULL;

            parent->type = NODE_NESTED;
            parent->left = node;

            ret = parent;
        }
        break;

        case TOKEN_BRACKET_OPEN:
        {
            Node *node = parse_array(p);
            if (node == NULL)
                return NULL;

            ret = node;
        }
        break;

        case TOKEN_CURLY_OPEN:
        {
            Node *node = parse_map(p);
            if (node == NULL)
                return NULL;

            ret = node;
        }
        break;

        case TOKEN_DOLLAR:
        {
            t = next_token(p);
            if (t.type != TOKEN_IDENT) {
                parser_report(p, "Missing identifier after '$'");
                return NULL;
            }

            Node *node = alloc_node(p);
            if (node == NULL)
                return NULL;

            node->type = NODE_VALUE_SYSVAR;
            node->sval = t.sval;

            ret = node;
        }
        break;

        default:
        {
            parser_report(p, "Invalid token inside expression");
        }
        return NULL;
    }

    for (;;) {
        Scanner saved = p->s;
        t = next_token(p);
        if (t.type == TOKEN_DOT) {

            t = next_token(p);
            if (t.type != TOKEN_IDENT) {
                parser_report(p, "Invalid token after '.' where an identifier was expected");
                return NULL;
            }

            Node *child = alloc_node(p);
            if (child == NULL)
                return NULL;

            child->type = NODE_VALUE_STR;
            child->sval = t.sval;

            Node *parent = alloc_node(p);
            if (parent == NULL)
                return NULL;

            parent->type = NODE_SELECT;
            parent->left = ret;
            parent->right = child;

            ret = parent;

        } else if (t.type == TOKEN_BRACKET_OPEN) {

            Node *child = parse_expr(p, 0);
            if (child == NULL)
                return NULL;

            t = next_token(p);
            if (t.type != TOKEN_BRACKET_CLOSE) {
                parser_report(p, "Missing token ']'");
                return NULL;
            }

            Node *parent = alloc_node(p);
            if (parent == NULL)
                return NULL;

            parent->type = NODE_SELECT;
            parent->left = ret;
            parent->right = child;

            ret = parent;

        } else if (t.type == TOKEN_PAREN_OPEN && (ret->type == NODE_VALUE_VAR || ret->type == NODE_VALUE_SYSVAR)) {

            Node *arg_head;
            Node **arg_tail = &arg_head;

            Scanner saved = p->s;
            t = next_token(p);
            if (t.type != TOKEN_PAREN_CLOSE) {

                p->s = saved;

                for (;;) {

                    Node *argval = parse_expr(p, 0);
                    if (argval == NULL)
                        return NULL;

                    *arg_tail = argval;
                    arg_tail = &argval->next;

                    t = next_token(p);
                    if (t.type == TOKEN_PAREN_CLOSE)
                        break;

                    if (t.type != TOKEN_COMMA) {
                        parser_report(p, "Expected ',' after argument in procedure call");
                        return NULL;
                    }
                }
            }

            *arg_tail = NULL;

            Node *parent = alloc_node(p);
            if (parent == NULL)
                return NULL;

            parent->type = NODE_PROCEDURE_CALL;
            parent->left = ret;
            parent->right = arg_head;

            ret = parent;

        } else {
            p->s = saved;
            break;
        }
    }

    return ret;
}

static Node *parse_expr_inner(Parser *p, Node *left, int min_prec, int flags)
{
    for (;;) {

        Scanner saved = p->s;
        Token t1 = next_token_or_newline(p);
        if (precedence(t1, flags) < min_prec) {
            p->s = saved;
           break;
        }

        Node *right = parse_atom(p);
        if (right == NULL)
            return NULL;

        for (;;) {

            saved = p->s;
            Token t2 = next_token_or_newline(p);
            int p1 = precedence(t1, flags);
            int p2 = precedence(t2, flags);
            p->s = saved;

            if (p2 < 0)
                break;

            if (p2 <= p1 && (p1 != p2 || !right_associative(t2)))
                break;

            right = parse_expr_inner(p, right, p1 + (p2 > p1), flags);
            if (right == NULL)
                return NULL;
        }

        Node *parent = alloc_node(p);
        if (parent == NULL)
            return NULL;

        parent->left = left;
        parent->right = right;

        switch (t1.type) {
            case TOKEN_OPER_ASS: parent->type = NODE_OPER_ASS; break;
            case TOKEN_OPER_EQL: parent->type = NODE_OPER_EQL; break;
            case TOKEN_OPER_NQL: parent->type = NODE_OPER_NQL; break;
            case TOKEN_OPER_LSS: parent->type = NODE_OPER_LSS; break;
            case TOKEN_OPER_GRT: parent->type = NODE_OPER_GRT; break;
            case TOKEN_OPER_ADD: parent->type = NODE_OPER_ADD; break;
            case TOKEN_OPER_SUB: parent->type = NODE_OPER_SUB; break;
            case TOKEN_OPER_MUL: parent->type = NODE_OPER_MUL; break;
            case TOKEN_OPER_DIV: parent->type = NODE_OPER_DIV; break;
            case TOKEN_OPER_MOD: parent->type = NODE_OPER_MOD; break;
            case TOKEN_OPER_SHOVEL: parent->type = NODE_OPER_SHOVEL; break;
            default:
            parser_report(p, "Operator not implemented");
            return NULL;
        }

        left = parent;
    }

    return left;
}

static Node *parse_expr(Parser *p, int flags)
{
    Node *left = parse_atom(p);
    if (left == NULL)
        return NULL;

    return parse_expr_inner(p, left, 0, flags);
}

static Node *parse_expr_stmt(Parser *p, int opflags)
{
    Node *e = parse_expr(p, opflags);
    if (e == NULL)
        return NULL;

    return e;
}

static Node *parse_ifelse_stmt(Parser *p, int opflags)
{
    Token t = next_token(p);
    if (t.type != TOKEN_KWORD_IF) {
        parser_report(p, "Missing 'if' keyword before if statement");
        return NULL;
    }

    Node *cond = parse_expr(p, 0);
    if (cond == NULL)
        return NULL;

    t = next_token(p);
    if (t.type != TOKEN_COLON) {
        parser_report(p, "Missing ':' after if condition");
        return NULL;
    }

    Node *if_stmt = parse_stmt(p, opflags);
    if (if_stmt == NULL)
        return NULL;

    Scanner saved = p->s;
    t = next_token(p);

    Node *else_stmt = NULL;
    if (t.type == TOKEN_KWORD_ELSE) {

        else_stmt = parse_stmt(p, opflags);
        if (else_stmt == NULL)
            return NULL;

    } else {
        p->s = saved;
    }

    Node *parent = alloc_node(p);
    if (parent == NULL)
        return NULL;

    parent->type = NODE_IFELSE;
    parent->if_cond = cond;
    parent->if_branch1 = if_stmt;
    parent->if_branch2 = else_stmt;

    return parent;
}

static Node *parse_for_stmt(Parser *p, int opflags)
{
    Token t = next_token(p);
    if (t.type != TOKEN_KWORD_FOR) {
        parser_report(p, "Missing 'for' keyword at the start of a for statement");
        return NULL;
    }

    t = next_token(p);
    if (t.type != TOKEN_IDENT) {
        parser_report(p, "Missing iteraion variable name in for statement");
        return NULL;
    }
    String var1 = t.sval;

    t = next_token(p);

    String var2 = S("");
    if (t.type == TOKEN_COMMA) {

        t = next_token(p);
        if (t.type != TOKEN_IDENT) {
            parser_report(p, "Missing iteration variable name after ',' in for statement");
            return NULL;
        }
        var2 = t.sval;

        t = next_token(p);
    }

    if (t.type != TOKEN_KWORD_IN) {
        parser_report(p, "Missing 'in' keyword after iteration variable name in for statement");
        return NULL;
    }

    Node *set = parse_expr(p, 0);
    if (set == NULL)
        return NULL;

    t = next_token(p);
    if (t.type != TOKEN_COLON) {
        parser_report(p, "Missing ':' after for statement set expression");
        return NULL;
    }

    Node *body = parse_stmt(p, opflags);
    if (body == NULL)
        return NULL;

    Node *parent = alloc_node(p);
    if (parent == NULL)
        return NULL;

    parent->type = NODE_FOR;
    parent->left = body;
    parent->for_var1 = var1;
    parent->for_var2 = var2;
    parent->for_set  = set;

    return parent;
}

static Node *parse_while_stmt(Parser *p, int opflags)
{
    Token t = next_token(p);
    if (t.type != TOKEN_KWORD_WHILE) {
        parser_report(p, "Missing keyword 'while' at the start of a while statement");
        return NULL;
    }

    Node *cond = parse_expr(p, 0);
    if (cond == NULL)
        return NULL;

    t = next_token(p);
    if (t.type != TOKEN_COLON) {
        parser_report(p, "Missing token ':' after while statement condition");
        return NULL;
    }

    Node *stmt = parse_stmt(p, opflags);
    if (stmt == NULL)
        return NULL;

    Node *parent = alloc_node(p);
    if (parent == NULL)
        return NULL;

    parent->type = NODE_WHILE;
    parent->left = stmt;
    parent->while_cond = cond;
    parent->while_body = stmt;

    return parent;
}

static Node *parse_compound_stmt(Parser *p, bool global)
{
    if (!global) {
        Token t = next_token(p);
        if (t.type != TOKEN_CURLY_OPEN) {
            parser_report(p, "Missing '{' at the start of a compound statement");
            return NULL;
        }
    }

    Node *head;
    Node **tail = &head;

    for (;;) {

        Scanner saved = p->s;
        Token t = next_token(p);
        if (!global) {
            if (t.type == TOKEN_CURLY_CLOSE)
                break;
        } else {
            if (t.type == TOKEN_END)
                break;
        }
        p->s = saved;

        Node *node = parse_stmt(p, 0);
        if (node == NULL)
            return NULL;

        *tail = node;
        tail = &node->next;
    }

    *tail = NULL;

    Node *parent = alloc_node(p);
    if (parent == NULL)
        return NULL;

    parent->type = global ? NODE_GLOBAL : NODE_COMPOUND;
    parent->left = head;

    return parent;
}

static Node *parse_proc_decl(Parser *p, int opflags)
{
    Token t = next_token(p);
    if (t.type != TOKEN_KWORD_PROCEDURE) {
        parser_report(p, "Missing keyword 'procedure' at the start of a procedure declaration");
        return NULL;
    }

    t = next_token(p);
    if (t.type != TOKEN_IDENT) {
        parser_report(p, "Missing procedure name after 'procedure' keyword");
        return NULL;
    }
    String name = t.sval;

    t = next_token(p);
    if (t.type != TOKEN_PAREN_OPEN) {
        parser_report(p, "Missing '(' after procedure name in declaration");
        return NULL;
    }

    Node *arg_head;
    Node **arg_tail = &arg_head;

    Scanner saved = p->s;
    t = next_token(p);
    if (t.type != TOKEN_PAREN_CLOSE) {
        p->s = saved;

        for (;;) {

            t = next_token(p);
            if (t.type != TOKEN_IDENT) {
                parser_report(p, "Missing argument name in procedure declaration");
                return NULL;
            }
            String argname = t.sval;

            Node *node = alloc_node(p);
            if (node == NULL)
                return NULL;

            node->type = NODE_PROCEDURE_ARG;
            node->sval = argname;

            *arg_tail = node;
            arg_tail = &node->next;

            Scanner saved = p->s;
            t = next_token(p);
            if (t.type == TOKEN_COMMA) {
                saved = p->s;
                t = next_token(p);
            }

            if (t.type == TOKEN_PAREN_CLOSE)
                break;
            p->s = saved;
        }
    }

    *arg_tail = NULL;

    Node *body = parse_stmt(p, opflags);
    if (body == NULL)
        return NULL;

    Node *parent = alloc_node(p);
    if (parent == NULL)
        return NULL;

    parent->type = NODE_PROCEDURE_DECL;
    parent->proc_name = name;
    parent->proc_args = arg_head;
    parent->proc_body = body;

    return parent;
}

static Node *parse_var_decl(Parser *p, int opflags)
{
    Token t = next_token(p);
    if (t.type != TOKEN_KWORD_LET) {
        parser_report(p, "Missing keyword 'let' at the start of a variable declaration");
        return NULL;
    }

    t = next_token(p);
    if (t.type != TOKEN_IDENT) {
        parser_report(p, "Missing variable name after 'let' keyword");
        return NULL;
    }
    String name = t.sval;

    Scanner saved = p->s;
    t = next_token(p);

    Node *value;
    if (t.type == TOKEN_OPER_ASS) {

        value = parse_expr(p, opflags);
        if (value == NULL)
            return NULL;

    } else {
        p->s = saved;
        value = NULL;
    }

    Node *parent = alloc_node(p);
    if (parent == NULL)
        return NULL;

    parent->type = NODE_VAR_DECL;
    parent->var_name = name;
    parent->var_value = value;

    return parent;
}

static Node *parse_include_stmt(Parser *p)
{
    Token t = next_token(p);
    if (t.type != TOKEN_KWORD_INCLUDE) {
        parser_report(p, "Missing keyword 'include' at the start of an include statement");
        return NULL;
    }

    t = next_token(p);
    if (t.type != TOKEN_VALUE_STR) {
        parser_report(p, "Missing file path string after 'include' keyword");
        return NULL;
    }
    String path = t.sval;

    Node *parent = alloc_node(p);
    if (parent == NULL)
        return NULL;

    parent->type = NODE_INCLUDE;
    parent->include_path = path;
    parent->include_root = NULL;

    *p->include_tail = parent;
    p->include_tail = &parent->include_next;

    return parent;
}

static Node *parse_stmt(Parser *p, int opflags)
{
    Scanner saved = p->s;
    Token t = next_token(p);
    p->s = saved;

    switch (t.type) {

        case TOKEN_KWORD_INCLUDE:
        return parse_include_stmt(p);

        case TOKEN_KWORD_PROCEDURE:
        return parse_proc_decl(p, opflags);

        case TOKEN_KWORD_LET:
        return parse_var_decl(p, opflags);

        case TOKEN_KWORD_IF:
        return parse_ifelse_stmt(p, opflags);

        case TOKEN_KWORD_WHILE:
        return parse_while_stmt(p, opflags);

        case TOKEN_KWORD_FOR:
        return parse_for_stmt(p, opflags);

        case TOKEN_CURLY_OPEN:
        return parse_compound_stmt(p, false);

        default:
        break;
    }

    return parse_expr_stmt(p, opflags);
}

static void write_node(Writer *w, Node *node)
{
    switch (node->type) {

        case NODE_VALUE_NONE : write_text(w, S("none")); break;
        case NODE_VALUE_TRUE : write_text(w, S("true")); break;
        case NODE_VALUE_FALSE: write_text(w, S("false")); break;

        case NODE_NESTED:
        write_text(w, S("(nested "));
        write_node(w, node->left);
        write_text(w, S(")"));
        break;

        case NODE_COMPOUND:
        {
            write_text(w, S("(compound "));
            Node *cur = node->left;
            while (cur) {
                write_node(w, cur);
                cur = cur->next;
                if (cur)
                    write_text(w, S(" "));
            }
            write_text(w, S(")"));
        }
        break;

        case NODE_GLOBAL:
        {
            write_text(w, S("(global "));
            Node *cur = node->left;
            while (cur) {
                write_node(w, cur);
                cur = cur->next;
                if (cur)
                    write_text(w, S(" "));
            }
            write_text(w, S(")"));
        }
        break;

        case NODE_OPER_LEN:
        write_text(w, S("(len "));
        write_node(w, node->left);
        write_text(w, S(")"));
        break;

        case NODE_OPER_ESCAPE:
        write_text(w, S("(escape "));
        write_node(w, node->left);
        write_text(w, S(")"));
        break;

        case NODE_OPER_POS:
        write_text(w, S("(+"));
        write_node(w, node->left);
        write_text(w, S(")"));
        break;

        case NODE_OPER_NEG:
        write_text(w, S("("));
        write_text(w, S("-"));
        write_node(w, node->left);
        write_text(w, S(")"));
        break;

        case NODE_OPER_ASS:
        write_text(w, S("("));
        write_node(w, node->left);
        write_text(w, S("="));
        write_node(w, node->right);
        write_text(w, S(")"));
        break;

        case NODE_OPER_EQL:
        write_text(w, S("("));
        write_node(w, node->left);
        write_text(w, S("=="));
        write_node(w, node->right);
        write_text(w, S(")"));
        break;

        case NODE_OPER_NQL:
        write_text(w, S("("));
        write_node(w, node->left);
        write_text(w, S("!="));
        write_node(w, node->right);
        write_text(w, S(")"));
        break;

        case NODE_OPER_LSS:
        write_text(w, S("("));
        write_node(w, node->left);
        write_text(w, S("<"));
        write_node(w, node->right);
        write_text(w, S(")"));
        break;

        case NODE_OPER_GRT:
        write_text(w, S("("));
        write_node(w, node->left);
        write_text(w, S(">"));
        write_node(w, node->right);
        write_text(w, S(")"));
        break;

        case NODE_OPER_ADD:
        write_text(w, S("("));
        write_node(w, node->left);
        write_text(w, S("+"));
        write_node(w, node->right);
        write_text(w, S(")"));
        break;

        case NODE_OPER_SUB:
        write_text(w, S("("));
        write_node(w, node->left);
        write_text(w, S("-"));
        write_node(w, node->right);
        write_text(w, S(")"));
        break;

        case NODE_OPER_MUL:
        write_text(w, S("("));
        write_node(w, node->left);
        write_text(w, S("*"));
        write_node(w, node->right);
        write_text(w, S(")"));
        break;

        case NODE_OPER_DIV:
        write_text(w, S("("));
        write_node(w, node->left);
        write_text(w, S("/"));
        write_node(w, node->right);
        write_text(w, S(")"));
        break;

        case NODE_OPER_MOD:
        write_text(w, S("("));
        write_node(w, node->left);
        write_text(w, S("%%"));
        write_node(w, node->right);
        write_text(w, S(")"));
        break;

        case NODE_OPER_SHOVEL:
        write_text(w, S("("));
        write_node(w, node->left);
        write_text(w, S("<<"));
        write_node(w, node->right);
        write_text(w, S(")"));
        break;

        case NODE_VALUE_INT:
        write_text_s64(w, node->ival);
        break;

        case NODE_VALUE_FLOAT:
        write_text_f64(w, node->fval);
        break;

        case NODE_VALUE_STR:
        write_text(w, S("\""));
        write_text(w, node->sval);
        write_text(w, S("\""));
        break;

        case NODE_VALUE_VAR:
        write_text(w, node->sval);
        break;

        case NODE_VALUE_SYSVAR:
        write_text(w, S("$"));
        write_text(w, node->sval);
        break;

        case NODE_IFELSE:
        write_text(w, S("(if "));
        write_node(w, node->if_cond);
        write_text(w, S(" "));
        write_node(w, node->if_branch1);
        if (node->if_branch2) {
            write_text(w, S(" else "));
            write_node(w, node->if_branch2);
        }
        write_text(w, S(")"));
        break;

        case NODE_WHILE:
        write_text(w, S("(while "));
        write_node(w, node->while_cond);
        write_text(w, S(" "));
        write_node(w, node->while_body);
        write_text(w, S(")"));
        break;

        case NODE_VALUE_HTML:
        {
            write_text(w, S("(html "));
            write_text(w, node->html_tag);

            Node *child = node->html_child;
            while (child) {
                write_text(w, S(" "));
                write_node(w, child);
                child = child->next;
            }

            write_text(w, S(")"));
        }
        break;

        case NODE_FOR:
        write_text(w, S("(for "));
        write_text(w, node->for_var1);
        if (node->for_var2.len > 0) {
            write_text(w, S(", "));
            write_text(w, node->for_var2);
        }
        write_text(w, S(" in "));
        write_node(w, node->for_set);
        write_text(w, S(": "));
        write_node(w, node->left);
        break;

        case NODE_SELECT:
        write_node(w, node->left);
        write_text(w, S("["));
        write_node(w, node->right);
        write_text(w, S("]"));
        break;

        case NODE_VALUE_ARRAY:
        {
            write_text(w, S("["));
            Node *child = node->child;
            while (child) {
                write_node(w, child);
                write_text(w, S(", "));
                child = child->next;
            }
            write_text(w, S("]"));
        }
        break;

        case NODE_VALUE_MAP:
        {
            write_text(w, S("{"));
            Node *child = node->child;
            while (child) {
                write_node(w, child->key);
                write_text(w, S(": "));
                write_node(w, child);
                write_text(w, S(", "));
                child = child->next;
            }
            write_text(w, S("}"));
        }
        break;

        case NODE_PROCEDURE_DECL:
        {
            write_text(w, S("(proc "));
            write_text(w, node->proc_name);
            write_text(w, S("("));
            Node *arg = node->proc_args;
            while (arg) {
                write_node(w, arg);
                arg = arg->next;
                if (arg)
                    write_text(w, S(", "));
            }
            write_text(w, S(")"));
            write_node(w, node->proc_body);
        }
        break;

        case NODE_PROCEDURE_ARG:
        write_text(w, node->sval);
        break;

        case NODE_PROCEDURE_CALL:
        {
            write_node(w, node->left);
            write_text(w, S("("));
            Node *arg = node->right;
            while (arg) {
                write_node(w, arg);
                arg = arg->next;
                if (arg)
                    write_text(w, S(", "));
            }
            write_text(w, S(")"));
        }
        break;

        case NODE_VAR_DECL:
        write_text(w, S("(let "));
        write_text(w, node->var_name);
        if (node->var_value) {
            write_text(w, S(" = "));
            write_node(w, node->var_value);
        }
        write_text(w, S(")"));
        break;

        case NODE_INCLUDE:
        write_text(w, S("include \""));
        write_text(w, node->include_path);
        write_text(w, S("\""));
        break;
    }
}

static ParseResult parse(String src, WL_Arena *arena, char *errbuf, int errmax)
{
    Parser p = {
        .s={ src.ptr, src.len, 0 },
        .arena=arena,
        .errbuf=errbuf,
        .errmax=errmax,
        .errlen=0,
    };

    p.include_tail = &p.include_head;

    Node *node = parse_compound_stmt(&p, true);
    if (node == NULL)
        return (ParseResult) { .node=NULL, .includes=NULL, .errlen=p.errlen };

    *p.include_tail = NULL;
    return (ParseResult) { .node=node, .includes=p.include_head, .errlen=-1 };
}

/////////////////////////////////////////////////////////////////////////
// CODEGEN
/////////////////////////////////////////////////////////////////////////

enum {
    OPCODE_NOPE,
    OPCODE_JUMP,
    OPCODE_JIFP,
    OPCODE_OUTPUT,
    OPCODE_SYSVAR,
    OPCODE_SYSCALL,
    OPCODE_CALL,
    OPCODE_RET,
    OPCODE_GROUP,
    OPCODE_ESCAPE,
    OPCODE_PACK,
    OPCODE_GPOP,
    OPCODE_FOR,
    OPCODE_EXIT,
    OPCODE_VARS,
    OPCODE_POP,
    OPCODE_SETV,
    OPCODE_PUSHV,
    OPCODE_PUSHI,
    OPCODE_PUSHF,
    OPCODE_PUSHS,
    OPCODE_PUSHA,
    OPCODE_PUSHM,
    OPCODE_PUSHN,
    OPCODE_PUSHT,
    OPCODE_PUSHFL,
    OPCODE_LEN,
    OPCODE_NEG,
    OPCODE_EQL,
    OPCODE_NQL,
    OPCODE_LSS,
    OPCODE_GRT,
    OPCODE_ADD,
    OPCODE_SUB,
    OPCODE_MUL,
    OPCODE_DIV,
    OPCODE_MOD,
    OPCODE_APPEND,
    OPCODE_INSERT1,
    OPCODE_INSERT2,
    OPCODE_SELECT,
};

typedef struct UnpatchedCall UnpatchedCall;
struct UnpatchedCall {
    UnpatchedCall *next;
    String         name;
    int            off;
};

typedef enum {
    SYMBOL_VARIABLE,
    SYMBOL_PROCEDURE,
} SymbolType;

typedef struct {
    SymbolType type;
    String     name;
    bool       cnst;
    int        off;
} Symbol;

typedef enum {
    SCOPE_IF,
    SCOPE_ELSE,
    SCOPE_FOR,
    SCOPE_WHILE,
    SCOPE_PROC,
    SCOPE_COMPOUND,
    SCOPE_GLOBAL,
    SCOPE_ASSIGNMENT,
} ScopeType;

typedef struct {
    ScopeType type;
    int idx_syms;
    int max_vars;
    UnpatchedCall *calls;
} Scope;

#define MAX_SYMBOLS 1024
#define MAX_SCOPES 128
#define MAX_UNPATCHED_CALLS 32

typedef struct {

    Writer code;
    Writer data;

    int num_scopes;
    Scope scopes[MAX_SCOPES];

    int num_syms;
    Symbol syms[MAX_SYMBOLS];

    UnpatchedCall *free_list_calls;
    UnpatchedCall calls[MAX_UNPATCHED_CALLS];

    bool  err;
    char *errmsg;
    int   errcap;

    int data_off;

} Codegen;

static void cg_report(Codegen *cg, char *fmt, ...)
{
    if (cg->err) return;

    va_list args;
    va_start(args, fmt);
    int len = vsnprintf(cg->errmsg, cg->errcap, fmt, args);
    va_end(args);

    if (len > cg->errcap)
        len = cg->errcap-1;

    cg->errmsg[len] = '\0';
    cg->err = true;
}

static int cg_write_u8(Codegen *cg, uint8_t x)
{
    if (cg->err) return -1;

    int off = cg->code.len;
    write_raw_u8(&cg->code, x);
    return off;
}

static int cg_write_u32(Codegen *cg, uint32_t x)
{
    if (cg->err) return -1;

    int off = cg->code.len;
    write_raw_u32(&cg->code, x);
    return off;
}

static int cg_write_s64(Codegen *cg, int64_t x)
{
    if (cg->err) return -1;

    int off = cg->code.len;
    write_raw_s64(&cg->code, x);
    return off;
}

static int cg_write_f64(Codegen *cg, double x)
{
    if (cg->err) return -1;

    int off = cg->code.len;
    write_raw_f64(&cg->code, x);
    return off;
}

static void cg_write_str(Codegen *cg, String x)
{
    if (cg->err) return;

    int off = cg->data.len;
    write_text(&cg->data, x);
    write_raw_u32(&cg->code, off);
    write_raw_u32(&cg->code, x.len);
}

static void cg_patch_u8(Codegen *cg, int off, uint8_t x)
{
    if (cg->err) return;

    patch_mem(&cg->code, &x, off, SIZEOF(x));
}

static void cg_patch_u32(Codegen *cg, int off, uint32_t x)
{
    if (cg->err) return;

    patch_mem(&cg->code, &x, off, SIZEOF(x));
}

static uint32_t cg_current_offset(Codegen *cg)
{
    return cg->code.len;
}

int count_nodes(Node *head)
{
    int n = 0;
    Node *node = head;
    while (node) {
        n++;
        node = node->next;
    }
    return n;
}

static Scope *parent_scope(Codegen *cg)
{
    ASSERT(cg->num_scopes > 0);

    int parent = cg->num_scopes-1;
    while (cg->scopes[parent].type != SCOPE_PROC && cg->scopes[parent].type != SCOPE_GLOBAL)
        parent--;

    return &cg->scopes[parent];
}

static bool inside_assignment(Codegen *cg)
{
    ASSERT(cg->num_scopes > 0);

    int parent = cg->num_scopes-1;
    while (cg->scopes[parent].type != SCOPE_PROC
        && cg->scopes[parent].type != SCOPE_GLOBAL
        && cg->scopes[parent].type != SCOPE_ASSIGNMENT)
        parent--;

    return cg->scopes[parent].type == SCOPE_ASSIGNMENT;
}

static int count_function_vars(Codegen *cg)
{
    int n = 0;
    Scope *scope = parent_scope(cg);
    for (int i = scope->idx_syms; i < cg->num_syms; i++)
        if (cg->syms[i].type == SYMBOL_VARIABLE)
            n++;
    return n;
}

static Symbol *cg_find_symbol(Codegen *cg, String name, bool local)
{
    if (cg->err) return NULL;

    if (name.len == 0) return NULL;
    ASSERT(cg->num_scopes > 0);
    Scope *scope = local ? &cg->scopes[cg->num_scopes-1] : parent_scope(cg);
    for (int i = cg->num_syms-1; i >= scope->idx_syms; i--)
        if (streq(cg->syms[i].name, name))
            return &cg->syms[i];
    return NULL;
}

static int cg_declare_variable(Codegen *cg, String name, bool cnst)
{
    if (cg->err) return -1;

    Symbol *sym = cg_find_symbol(cg, name, true);
    if (sym) {
        cg_report(cg, "Variable declared twice");
        return -1;
    }

    if (cg->num_syms == MAX_SYMBOLS) {
        cg_report(cg, "Symbol count limit reached");
        return -1;
    }

    int off = count_function_vars(cg);

    Scope *parent = parent_scope(cg);
    parent->max_vars = MAX(parent->max_vars, off+1);

    cg->syms[cg->num_syms++] = (Symbol) {
        .type = SYMBOL_VARIABLE,
        .name = name,
        .cnst = cnst,
        .off  = off,
    };
    return off;
}

static void cg_declare_procedure(Codegen *cg, String name, int off)
{
    if (cg->err) return;

    Symbol *sym = cg_find_symbol(cg, name, true);
    if (sym) {
        cg_report(cg, "Procedure declared twice");
        return;
    }

    if (cg->num_syms == MAX_SYMBOLS) {
        cg_report(cg, "Symbol count limit reached");
        return;
    }

    cg->syms[cg->num_syms++] = (Symbol) {
        .type = SYMBOL_PROCEDURE,
        .name = name,
        .cnst = true,
        .off  = off,
    };
}

static void cg_push_scope(Codegen *cg, ScopeType type)
{
    if (cg->err) return;

    if (cg->num_scopes == MAX_SCOPES) {
        cg_report(cg, "Scope limit reached");
        return;
    }

    Scope *scope = &cg->scopes[cg->num_scopes++];
    scope->type     = type;
    scope->idx_syms = cg->num_syms;
    scope->max_vars = 0;
    scope->calls    = NULL;
}

static void cg_pop_scope(Codegen *cg)
{
    if (cg->err) return;

    ASSERT(cg->num_scopes > 0);
    Scope *scope = &cg->scopes[cg->num_scopes-1];

    Scope *parent_scope = NULL;
    if (cg->num_scopes > 1)
        parent_scope = &cg->scopes[cg->num_scopes-2];

    while (scope->calls) {

        UnpatchedCall *call = scope->calls;
        scope->calls = call->next;

        ASSERT(call - cg->calls >= 0 && call - cg->calls < MAX_UNPATCHED_CALLS);

        Symbol *sym = cg_find_symbol(cg, call->name, true);

        if (sym == NULL) {
            if (parent_scope == NULL) {
                cg_report(cg, "Undefined function '%.*s'",
                    scope->calls->name.len,
                    scope->calls->name.ptr);
                    return;
                }
            call->next = parent_scope->calls;
            parent_scope->calls = call; 
            continue;
        }

        if (sym->type != SYMBOL_PROCEDURE) {
            cg_report(cg, "Symbol '%.*s' is not a procedure", call->name.len, call->name.ptr);
            return;
        }

        cg_patch_u32(cg, call->off, sym->off);

        call->next = cg->free_list_calls;
        cg->free_list_calls = call;

        // TODO: remove
        ASSERT(cg->scopes[cg->num_scopes-1].calls == NULL || (cg->scopes[cg->num_scopes-1].calls - cg->calls >= 0 && cg->scopes[cg->num_scopes-1].calls - cg->calls < MAX_UNPATCHED_CALLS));
    }

    cg->num_syms = scope->idx_syms;
    cg->num_scopes--;
}

static void cg_append_unpatched_call(Codegen *cg, String name, int p)
{
    if (cg->err) return;

    if (cg->free_list_calls == NULL) {
        cg_report(cg, "Out of memory");
        return;
    }
    UnpatchedCall *call = cg->free_list_calls;
    cg->free_list_calls = call->next;

    ASSERT(call - cg->calls >= 0 && call - cg->calls < MAX_UNPATCHED_CALLS);

    call->name = name;
    call->off  = p;
    call->next = NULL;

    ASSERT(cg->num_scopes > 0);
    Scope *scope = &cg->scopes[cg->num_scopes-1];

    call->next = scope->calls;
    scope->calls = call;
}

static bool cg_global_scope(Codegen *cg)
{
    Scope *scope = parent_scope(cg);
    return scope->type == SCOPE_GLOBAL;
}

static void cg_flush_pushs(Codegen *cg)
{
    if (cg->data_off != -1) {
        if (cg->data_off < cg->data.len) {
            cg_write_u8(cg, OPCODE_PUSHS);
            cg_write_u32(cg, cg->data_off);
            cg_write_u32(cg, cg->data.len - cg->data_off);
        }
        cg->data_off = -1;
    }
}

static int cg_write_opcode(Codegen *cg, uint8_t opcode)
{
    ASSERT(opcode != OPCODE_PUSHS);
    cg_flush_pushs(cg);
    return cg_write_u8(cg, opcode);
}

static void cg_write_pushs(Codegen *cg, String str, bool dont_group)
{
    if (dont_group) {
        cg_flush_pushs(cg);
        cg_write_u8(cg, OPCODE_PUSHS);
        cg_write_str(cg, str);
    } else {
        if (cg->data_off == -1)
            cg->data_off = cg->data.len;
        write_raw_mem(&cg->data, str.ptr, str.len);
    }
}

static void walk_node(Codegen *cg, Node *node, bool inside_html);

static void walk_expr_node(Codegen *cg, Node *node, bool one)
{
    // TODO: remove
    ASSERT(cg->scopes[cg->num_scopes-1].calls == NULL || (cg->scopes[cg->num_scopes-1].calls - cg->calls >= 0 && cg->scopes[cg->num_scopes-1].calls - cg->calls < MAX_UNPATCHED_CALLS));

    switch (node->type) {

        case NODE_NESTED:
        walk_expr_node(cg, node->left, one);
        break;

        case NODE_OPER_LEN:
        walk_expr_node(cg, node->left, true);
        cg_write_opcode(cg, OPCODE_LEN);
        break;

        case NODE_OPER_ESCAPE:
        cg_write_opcode(cg, OPCODE_GROUP);
        walk_expr_node(cg, node->left, false);
        cg_write_opcode(cg, OPCODE_ESCAPE);
        break;

        case NODE_OPER_POS:
        walk_expr_node(cg, node->left, one);
        break;

        case NODE_OPER_NEG:
        walk_expr_node(cg, node->left, true);
        cg_write_opcode(cg, OPCODE_NEG);
        break;

        case NODE_OPER_ASS:
        {
            Node *dst = node->left;
            Node *src = node->right;

            if (dst->type == NODE_VALUE_VAR) {

                String name = dst->sval;
                Symbol *sym = cg_find_symbol(cg, name, false);
                if (sym == NULL) {
                    cg_report(cg, "Write to undeclared variable");
                    return;
                }
                if (sym->type == SYMBOL_PROCEDURE) {
                    cg_report(cg, "Symbol is not a variable");
                    return;
                }
                if (sym->cnst) {
                    cg_report(cg, "Variable is constant");
                    return;
                }

                cg_push_scope(cg, SCOPE_ASSIGNMENT);
                walk_expr_node(cg, src, true);
                cg_pop_scope(cg);

                cg_write_opcode(cg, OPCODE_SETV);
                cg_write_u8(cg, sym->off);

                if (!one)
                    cg_write_opcode(cg, OPCODE_POP);

            } else if (dst->type == NODE_SELECT) {

                cg_push_scope(cg, SCOPE_ASSIGNMENT);
                walk_expr_node(cg, src, true);
                cg_pop_scope(cg);

                walk_expr_node(cg, dst->left,  true);
                walk_expr_node(cg, dst->right, true);
                cg_write_opcode(cg, OPCODE_INSERT2);

                if (!one)
                    cg_write_opcode(cg, OPCODE_POP);

            } else {

                cg_report(cg, "Assignment left side can't be assigned to");
                return;
            }
        }
        break;

        case NODE_OPER_SHOVEL:
        {
            walk_expr_node(cg, node->left, true);

            cg_push_scope(cg, SCOPE_ASSIGNMENT);
            walk_expr_node(cg, node->right, true);
            cg_pop_scope(cg);

            cg_write_opcode(cg, OPCODE_APPEND);
            if (!one)
                cg_write_opcode(cg, OPCODE_POP);
        }
        break;

        case NODE_OPER_EQL:
        walk_expr_node(cg, node->left, true);
        walk_expr_node(cg, node->right, true);
        cg_write_opcode(cg, OPCODE_EQL);
        break;

        case NODE_OPER_NQL:
        walk_expr_node(cg, node->left, true);
        walk_expr_node(cg, node->right, true);
        cg_write_opcode(cg, OPCODE_NQL);
        break;

        case NODE_OPER_LSS:
        walk_expr_node(cg, node->left, true);
        walk_expr_node(cg, node->right, true);
        cg_write_opcode(cg, OPCODE_LSS);
        break;

        case NODE_OPER_GRT:
        walk_expr_node(cg, node->left, true);
        walk_expr_node(cg, node->right, true);
        cg_write_opcode(cg, OPCODE_GRT);
        break;

        case NODE_OPER_ADD:
        walk_expr_node(cg, node->left, true);
        walk_expr_node(cg, node->right, true);
        cg_write_opcode(cg, OPCODE_ADD);
        break;

        case NODE_OPER_SUB:
        walk_expr_node(cg, node->left, true);
        walk_expr_node(cg, node->right, true);
        cg_write_opcode(cg, OPCODE_SUB);
        break;

        case NODE_OPER_MUL:
        walk_expr_node(cg, node->left, true);
        walk_expr_node(cg, node->right, true);
        cg_write_opcode(cg, OPCODE_MUL);
        break;

        case NODE_OPER_DIV:
        walk_expr_node(cg, node->left, true);
        walk_expr_node(cg, node->right, true);
        cg_write_opcode(cg, OPCODE_DIV);
        break;

        case NODE_OPER_MOD:
        walk_expr_node(cg, node->left, true);
        walk_expr_node(cg, node->right, true);
        cg_write_opcode(cg, OPCODE_MOD);
        break;

        case NODE_VALUE_INT:
        cg_write_opcode(cg, OPCODE_PUSHI);
        cg_write_s64(cg, node->ival);
        break;

        case NODE_VALUE_FLOAT:
        cg_write_opcode(cg, OPCODE_PUSHF);
        cg_write_f64(cg, node->fval);
        break;

        case NODE_VALUE_STR:
        cg_write_pushs(cg, node->sval, one);
        break;

        case NODE_VALUE_NONE:
        cg_write_opcode(cg, OPCODE_PUSHN);
        break;

        case NODE_VALUE_TRUE:
        cg_write_opcode(cg, OPCODE_PUSHT);
        break;

        case NODE_VALUE_FALSE:
        cg_write_opcode(cg, OPCODE_PUSHFL);
        break;

        case NODE_VALUE_VAR:
        {
            String name = node->sval;
            Symbol *sym = cg_find_symbol(cg, name, false);
            if (sym == NULL) {
                cg_report(cg, "Access to undeclared variable '%.*s'", name.len, name.ptr);
                return;
            }
            if (sym->type == SYMBOL_PROCEDURE) {
                cg_report(cg, "Symbol is not a variable");
                return;
            }

            cg_write_opcode(cg, OPCODE_PUSHV);
            cg_write_u8(cg, sym->off);
        }
        break;

        case NODE_VALUE_SYSVAR:
        cg_write_opcode(cg, OPCODE_SYSVAR);
        cg_write_str(cg, node->sval);
        break;

        case NODE_VALUE_HTML:
        {
            if (one)
                cg_write_opcode(cg, OPCODE_GROUP);

            cg_write_pushs(cg, S("<"), false);
            cg_write_pushs(cg, node->html_tag, false);

            Node *child = node->html_attr;
            while (child) {
                walk_node(cg, child, true);
                child = child->next;
            }

            if (!node->html_body) {
                cg_write_pushs(cg, S("/>"), false);
            } else {
                cg_write_pushs(cg, S(">"), false);
                Node *child = node->html_child;
                while (child) {
                    walk_node(cg, child, true);
                    child = child->next;
                }
                cg_write_pushs(cg, S("</"), false);
                cg_write_pushs(cg, node->html_tag, false);
                cg_write_pushs(cg, S(">"), false);
            }

            if (one)
                cg_write_opcode(cg, OPCODE_PACK);
        }
        break;

        case NODE_VALUE_ARRAY:
        {
            cg_write_opcode(cg, OPCODE_PUSHA);
            cg_write_u32(cg, count_nodes(node->child));

            Node *child = node->child;
            while (child) {
                walk_expr_node(cg, child, true);
                cg_write_opcode(cg, OPCODE_APPEND);
                child = child->next;
            }
        }
        break;

        case NODE_VALUE_MAP:
        {
            cg_write_opcode(cg, OPCODE_PUSHM);
            cg_write_u32(cg, count_nodes(node->child));

            Node *child = node->child;
            while (child) {
                walk_expr_node(cg, child, true);
                walk_expr_node(cg, child->key, true);
                cg_write_opcode(cg, OPCODE_INSERT1);
                child = child->next;
            }
        }
        break;

        case NODE_SELECT:
        {
            Node *set = node->left;
            Node *key = node->right;
            walk_expr_node(cg, set, true);
            walk_expr_node(cg, key, true);
            cg_write_opcode(cg, OPCODE_SELECT);
        }
        break;

        case NODE_PROCEDURE_CALL:
        {
            if (one)
                cg_write_opcode(cg, OPCODE_GROUP);

            int count = 0;
            Node *arg = node->right;
            while (arg) {
                walk_expr_node(cg, arg, true);
                count++;
                arg = arg->next;
            }

            Node *proc = node->left;
            if (proc->type == NODE_VALUE_VAR) {
                
                cg_write_opcode(cg, OPCODE_CALL);
                cg_write_u8(cg, count);
                int p = cg_write_u32(cg, 0);
                cg_append_unpatched_call(cg, proc->sval, p);

            } else {

                ASSERT(proc->type == NODE_VALUE_SYSVAR);
                cg_write_opcode(cg, OPCODE_SYSCALL);
                cg_write_u8(cg, count);
                cg_write_str(cg, proc->sval);
            }

            if (one)
                cg_write_opcode(cg, OPCODE_PACK);
        }
        break;

        default:
        UNREACHABLE;
    }
}

static void walk_node(Codegen *cg, Node *node, bool inside_html)
{
    // TODO: remove
    ASSERT(cg->scopes[cg->num_scopes-1].calls == NULL || (cg->scopes[cg->num_scopes-1].calls - cg->calls >= 0 && cg->scopes[cg->num_scopes-1].calls - cg->calls < MAX_UNPATCHED_CALLS));

    switch (node->type) {

        case NODE_GLOBAL:
        for (Node *child = node->left;
            child; child = child->next) {
            walk_node(cg, child, false);
        }
        break;

        case NODE_COMPOUND:
        cg_push_scope(cg, SCOPE_COMPOUND);
        for (Node *child = node->left;
            child; child = child->next)
            walk_node(cg, child, inside_html);
        cg_pop_scope(cg);
        break;

        case NODE_PROCEDURE_DECL:
        {
            cg_push_scope(cg, SCOPE_PROC);

            cg_write_opcode(cg, OPCODE_JUMP);
            int off0 = cg_write_u32(cg, 0);

            #define MAX_ARGS 128

            int num_args = 0;
            Node *args[MAX_ARGS];

            Node *arg = node->proc_args;
            while (arg) {
                if (num_args == MAX_ARGS) {
                    cg_report(cg, "Procedure argument limit reached");
                    return;
                }
                args[num_args++] = arg;
                arg = arg->next;
            }

            for (int i = num_args-1; i >= 0; i--)
                cg_declare_variable(cg, args[i]->sval, false);

            int off1 = cg_write_opcode(cg, OPCODE_VARS);
            int off2 = cg_write_u8(cg, 0);

            walk_node(cg, node->proc_body, false);
            cg_write_opcode(cg, OPCODE_RET);

            cg_patch_u8 (cg, off2, count_function_vars(cg));
            cg_patch_u32(cg, off0, cg_current_offset(cg));

            cg_pop_scope(cg);

            cg_declare_procedure(cg, node->proc_name, off1);
        }
        break;

        case NODE_VAR_DECL:
        {
            int off = cg_declare_variable(cg, node->var_name, false);
            if (node->var_value) {
                cg_push_scope(cg, SCOPE_ASSIGNMENT);
                walk_expr_node(cg, node->var_value, true);
                cg_pop_scope(cg);
            } else
                cg_write_opcode(cg, OPCODE_PUSHN);
            cg_write_opcode(cg, OPCODE_SETV);
            cg_write_u8(cg, off);
            cg_write_opcode(cg, OPCODE_POP);
        }
        break;

        case NODE_IFELSE:
        {
            // If there is no else branch:
            //
            //   <cond>
            //   JIFP end
            //   <left>
            // end:
            //   ...
            //
            // If there is:
            //
            //   <cond>
            //   JIFP else
            //   <left>
            //   JUMP end
            // else:
            //   <right>
            // end:
            //   ...

            if (node->if_branch2) {

                walk_expr_node(cg, node->if_cond, true);

                cg_write_opcode(cg, OPCODE_JIFP);
                int p1 = cg_write_u32(cg, 0);

                cg_push_scope(cg, SCOPE_IF);
                walk_node(cg, node->if_branch1, inside_html);
                cg_pop_scope(cg);

                cg_write_opcode(cg, OPCODE_JUMP);
                int p2 = cg_write_u32(cg, 0);

                cg_flush_pushs(cg);
                cg_patch_u32(cg, p1, cg_current_offset(cg));

                cg_push_scope(cg, SCOPE_ELSE);
                walk_node(cg, node->if_branch2, inside_html);
                cg_pop_scope(cg);

                cg_flush_pushs(cg);
                cg_patch_u32(cg, p2, cg_current_offset(cg));

            } else {

                walk_expr_node(cg, node->if_cond, true);

                cg_write_opcode(cg, OPCODE_JIFP);
                int p1 = cg_write_u32(cg, 0);

                cg_push_scope(cg, SCOPE_IF);
                walk_node(cg, node->if_branch1, inside_html);
                cg_pop_scope(cg);

                cg_flush_pushs(cg);
                cg_patch_u32(cg, p1, cg_current_offset(cg));
            }
        }
        break;

        case NODE_FOR:
        {
            cg_push_scope(cg, SCOPE_FOR);

            int var_1 = cg_declare_variable(cg, node->for_var1, false);
            int var_2 = cg_declare_variable(cg, node->for_var2, true);
            int var_3 = cg_declare_variable(cg, (String) { NULL, 0 }, true);

            walk_expr_node(cg, node->for_set, true);
            cg_write_opcode(cg, OPCODE_SETV);
            cg_write_u8(cg, var_3);
            cg_write_opcode(cg, OPCODE_POP);

            cg_write_opcode(cg, OPCODE_PUSHI);
            cg_write_s64(cg, -1);
            cg_write_opcode(cg, OPCODE_SETV);
            cg_write_u8(cg, var_2);
            cg_write_opcode(cg, OPCODE_POP);

            int start = cg_write_opcode(cg, OPCODE_FOR);
            cg_write_u8(cg, var_3);
            cg_write_u8(cg, var_1);
            cg_write_u8(cg, var_2);
            int p = cg_write_u32(cg, 0);

            walk_node(cg, node->left, inside_html);

            cg_write_opcode(cg, OPCODE_JUMP);
            cg_write_u32(cg, start);

            cg_patch_u32(cg, p, cg_current_offset(cg));

            cg_pop_scope(cg);
        }
        break;

        case NODE_WHILE:
        {
            // start:
            //   <cond>
            //   JIFP end
            //   <body>
            //   JUMP start
            // end:
            //   ...

            int start = cg_current_offset(cg);

            walk_expr_node(cg, node->while_cond, true);

            cg_write_opcode(cg, OPCODE_JIFP);
            int p = cg_write_u32(cg, 0);

            cg_push_scope(cg, SCOPE_WHILE);
            walk_node(cg, node->left, inside_html);
            cg_pop_scope(cg);

            cg_write_opcode(cg, OPCODE_JUMP);
            cg_write_u32(cg, start);

            cg_patch_u32(cg, p, cg_current_offset(cg));
        }
        break;

        case NODE_INCLUDE:
        walk_node(cg, node->include_root, false);
        break;

        default:
        walk_expr_node(cg, node, false);
        if (cg_global_scope(cg) && !inside_assignment(cg) && !inside_html)
            cg_write_opcode(cg, OPCODE_OUTPUT);
        break;
    }
}

#define WL_MAGIC 0xFEEDBEEF

static int codegen(Node *node, char *dst, int cap, char *errmsg, int errcap)
{
    char *hdr;
    if (cap < SIZEOF(uint32_t) * 3)
        hdr = NULL;
    else {
        hdr = dst;
        dst += SIZEOF(uint32_t) * 3;
        cap -= SIZEOF(uint32_t) * 3;
    }

    Codegen cg = {
        .code = { dst,         cap/2, 0 },
        .data = { dst + cap/2, cap/2, 0 },
        .num_scopes = 0,
        .err = false,
        .errmsg = errmsg,
        .errcap = errcap,
        .data_off = -1,
    };

    cg.free_list_calls = cg.calls;
    for (int i = 0; i < MAX_UNPATCHED_CALLS-1; i++)
        cg.calls[i].next = &cg.calls[i+1];
    cg.calls[MAX_UNPATCHED_CALLS-1].next = NULL;

    cg_push_scope(&cg, SCOPE_GLOBAL);
    cg_write_opcode(&cg, OPCODE_VARS);
    int off = cg_write_u8(&cg, 0);
    walk_node(&cg, node, false);
    cg_write_opcode(&cg, OPCODE_EXIT);
    cg_patch_u8(&cg, off, cg.scopes[0].max_vars);
    cg_pop_scope(&cg);

    if (cg.err)
        return -1;

    if (hdr) {

        uint32_t magic = WL_MAGIC;
        uint32_t code_len = cg.code.len;
        uint32_t data_len = cg.data.len;
        memcpy(hdr + 0, &magic   , sizeof(uint32_t));
        memcpy(hdr + 4, &code_len, sizeof(uint32_t));
        memcpy(hdr + 8, &data_len, sizeof(uint32_t));

        if (cg.code.len + cg.data.len <= cap)
            memmove(dst + cg.code.len, dst + cap/2, cg.data.len);
    }

    return cg.code.len + cg.data.len + SIZEOF(uint32_t) * 3;
}

static int write_instr(Writer *w, char *src, int len, String data)
{
    if (len == 0)
        return -1;

    switch (src[0]) {

        uint8_t b0;
        uint8_t b1;
        uint8_t b2;
        uint32_t w0;
        uint32_t w1;
        int64_t i;
        double  d;

        case OPCODE_NOPE:
        write_text(w, S("NOPE\n"));
        return 1;

        case OPCODE_JUMP:
        if (len < 5) return -1;
        memcpy(&w0, src + 1, sizeof(uint32_t));
        write_text(w, S("JUMP "));
        write_text_s64(w, w0);
        write_text(w, S("\n"));
        return 5;

        case OPCODE_JIFP:
        if (len < 5) return -1;
        memcpy(&w0, src + 1, sizeof(uint32_t));
        write_text(w, S("JIFP "));
        write_text_s64(w, w0);
        write_text(w, S("\n"));
        return 5;

        case OPCODE_OUTPUT:
        write_text(w, S("OUTPUT\n"));
        return 1;

        case OPCODE_SYSVAR:
        if (len < 9) return -1;
        memcpy(&w0, src + 1, sizeof(uint32_t));
        memcpy(&w1, src + 5, sizeof(uint32_t));
        write_text(w, S("SYSVAR \""));
        write_text(w, (String) { data.ptr + w0, w1 });
        write_text(w, S("\"\n"));
        return 9;

        case OPCODE_SYSCALL:
        if (len < 10) return -1;
        memcpy(&b0, src + 1, sizeof(uint8_t));
        memcpy(&w0, src + 2, sizeof(uint32_t));
        memcpy(&w1, src + 6, sizeof(uint32_t));
        write_text(w, S("SYSCALL "));
        write_text_s64(w, b0);
        write_text(w, S(" \""));
        write_text(w, (String) { data.ptr + w0, w1 });
        write_text(w, S("\"\n"));
        return 10;

        case OPCODE_CALL:
        if (len < 6) return -1;
        memcpy(&b0, src + 1, sizeof(uint8_t));
        memcpy(&w0, src + 2, sizeof(uint32_t));
        write_text(w, S("CALL "));
        write_text_s64(w, b0);
        write_text(w, S(" "));
        write_text_s64(w, w0);
        write_text(w, S("\n"));
        return 6;

        case OPCODE_RET:
        write_text(w, S("RET\n"));
        return 1;

        case OPCODE_GROUP:
        write_text(w, S("GROUP\n"));
        return 1;

        case OPCODE_ESCAPE:
        write_text(w, S("ESCAPE\n"));
        return 1;

        case OPCODE_PACK:
        write_text(w, S("PACK\n"));
        return 1;

        case OPCODE_GPOP:
        write_text(w, S("GPOP\n"));
        return 1;

        case OPCODE_FOR:
        if (len < 8) return -1;
        memcpy(&b0, src + 1, sizeof(b0));
        memcpy(&b1, src + 2, sizeof(b1));
        memcpy(&b2, src + 3, sizeof(b2));
        memcpy(&w0, src + 4, sizeof(w0));
        write_text(w, S("FOR "));
        write_text_s64(w, b0);
        write_text(w, S(" "));
        write_text_s64(w, b1);
        write_text(w, S(" "));
        write_text_s64(w, b2);
        write_text(w, S(" "));
        write_text_s64(w, w0);
        write_text(w, S("\n"));
        return 8;

        case OPCODE_EXIT:
        write_text(w, S("EXIT\n"));
        return 1;

        case OPCODE_VARS:
        if (len < 2) return -1;
        memcpy(&b0, src + 1, sizeof(b0));
        write_text(w, S("VARS "));
        write_text_s64(w, b0);
        write_text(w, S("\n"));
        return 2;

        case OPCODE_POP:
        write_text(w, S("POP\n"));
        return 1;

        case OPCODE_SETV:
        if (len < 2) return -1;
        memcpy(&b0, src + 1, sizeof(uint8_t));
        write_text(w, S("SETV "));
        write_text_s64(w, b0);
        write_text(w, S("\n"));
        return 2;

        case OPCODE_PUSHV:
        if (len < 2) return -1;
        memcpy(&b0, src + 1, sizeof(uint8_t));
        write_text(w, S("PUSHV "));
        write_text_s64(w, b0);
        write_text(w, S("\n"));
        return 2;

        case OPCODE_PUSHI:
        if (len < 9) return -1;
        memcpy(&i, src + 1, sizeof(int64_t));
        write_text(w, S("PUSHI "));
        write_text_s64(w, i);
        write_text(w, S("\n"));
        return 9;

        case OPCODE_PUSHF:
        if (len < 9) return -1;
        memcpy(&d, src + 1, sizeof(double));
        write_text(w, S("PUSHF "));
        write_text_f64(w, d);
        write_text(w, S("\n"));
        return 9;

        case OPCODE_PUSHS:
        if (len < 9) return -1;
        memcpy(&w0, src + 1, sizeof(uint32_t));
        memcpy(&w1, src + 5, sizeof(uint32_t));
        write_text(w, S("PUSHS \""));
        write_text(w, (String) { data.ptr + w0, w1 });
        write_text(w, S("\"\n"));
        return 9;

        case OPCODE_PUSHA:
        if (len < 5) return -1;
        memcpy(&w0, src + 1, sizeof(w0));
        write_text(w, S("PUSHA "));
        write_text_s64(w, w0);
        write_text(w, S("\n"));
        return 5;

        case OPCODE_PUSHM:
        if (len < 5) return -1;
        memcpy(&w0, src + 1, sizeof(w0));
        write_text(w, S("PUSHM "));
        write_text_s64(w, w0);
        write_text(w, S("\n"));
        return 5;

        case OPCODE_PUSHN:
        write_text(w, S("PUSHN\n"));
        return 1;

        case OPCODE_PUSHT:
        write_text(w, S("PUSHT\n"));
        return 1;

        case OPCODE_PUSHFL:
        write_text(w, S("PUSHFL\n"));
        return 1;

        case OPCODE_LEN:
        write_text(w, S("LEN\n"));
        return 1;

        case OPCODE_NEG:
        write_text(w, S("NEG\n"));
        return 1;

        case OPCODE_EQL:
        write_text(w, S("EQL\n"));
        return 1;

        case OPCODE_NQL:
        write_text(w, S("NQL\n"));
        return 1;

        case OPCODE_LSS:
        write_text(w, S("LSS\n"));
        return 1;

        case OPCODE_GRT:
        write_text(w, S("GRT\n"));
        return 1;

        case OPCODE_ADD:
        write_text(w, S("ADD\n"));
        return 1;

        case OPCODE_SUB:
        write_text(w, S("SUB\n"));
        return 1;

        case OPCODE_MUL:
        write_text(w, S("MUL\n"));
        return 1;

        case OPCODE_DIV:
        write_text(w, S("DIV\n"));
        return 1;

        case OPCODE_MOD:
        write_text(w, S("MOD\n"));
        return 1;

        case OPCODE_APPEND:
        write_text(w, S("APPEND\n"));
        return 1;

        case OPCODE_INSERT1:
        write_text(w, S("INSERT1\n"));
        return 1;

        case OPCODE_INSERT2:
        write_text(w, S("INSERT2\n"));
        return 1;

        case OPCODE_SELECT:
        write_text(w, S("SELECT\n"));
        return 1;

        default:
        write_text(w, S("byte "));
        write_text_s64(w, src[0]);
        return 1;
    }

    return -1;
}

static int write_program(WL_Program program, char *dst, int cap)
{
    if (program.len < 3 * sizeof(uint32_t))
        return -1;

    uint32_t magic;
    uint32_t code_len;
    uint32_t data_len;

    memcpy(&magic   , program.ptr + 0, sizeof(uint32_t));
    memcpy(&code_len, program.ptr + 4, sizeof(uint32_t));
    memcpy(&data_len, program.ptr + 8, sizeof(uint32_t));

    if (magic != WL_MAGIC)
        return -1;

    if (code_len + data_len + 3 * sizeof(uint32_t) != program.len)
        return -1;

    String code = { program.ptr + 3 * sizeof(uint32_t)           , code_len };
    String data = { program.ptr + 3 * sizeof(uint32_t) + code_len, data_len };

    Writer w = { dst, cap, 0 };

    int cur = 0;
    while (cur < code.len) {
        write_text_s64(&w, cur);
        write_text(&w, S(": "));
        int ret = write_instr(&w, code.ptr + cur, code.len - cur, data);
        if (ret < 0) return -1;
        cur += ret;
    }

    return w.len;
}

void wl_dump_program(WL_Program program)
{
    char buf[1<<10];
    int len = write_program(program, buf, SIZEOF(buf));

    if (len < 0) {
        printf("Invalid program\n");
        return;
    }

    if (len > SIZEOF(buf)) {
        char *p = malloc(len+1);
        if (p == NULL) {
            printf("Out of memory\n");
            return;
        }
        write_program(program, p, len);
        p[len] = '\0';
        fwrite(p, 1, len, stdout);
    } else {
        fwrite(buf, 1, len, stdout);
    }
}

/////////////////////////////////////////////////////////////////////////
// COMPILER
/////////////////////////////////////////////////////////////////////////

#define FILE_LIMIT 128

typedef struct {
    String file;
    Node*  root;
    Node*  includes;
} CompiledFile;

struct WL_Compiler {

    WL_Arena*    arena;
    CompiledFile files[FILE_LIMIT];
    int          num_files;
    String       waiting_file;

    bool err;
    char msg[1<<8];
};

WL_Compiler *wl_compiler_init(WL_Arena *arena)
{
    WL_Compiler *compiler = alloc(arena, SIZEOF(WL_Compiler), _Alignof(WL_Compiler));
    if (compiler == NULL)
        return NULL;
    compiler->arena = arena;
    compiler->num_files = 0;
    compiler->waiting_file = (String) { NULL, 0 };
    compiler->err = false;
    return compiler;
}

WL_AddResult wl_compiler_add(WL_Compiler *compiler, WL_String path, WL_String content)
{
    if (compiler->err)
        return (WL_AddResult) { .type=WL_ADD_ERROR };

    ParseResult pres = parse((String) { content.ptr, content.len }, compiler->arena, compiler->msg, SIZEOF(compiler->msg));
    if (pres.node == NULL) {
        compiler->err = true;
        return (WL_AddResult) { .type=WL_ADD_ERROR };
    }

    // Make include paths relative to the parent file
    if (path.len > 0) {

        String parent = { path.ptr, path.len };

        char sep = '/';
        while (parent.len > 0 && parent.ptr[parent.len-1] != sep)
            parent.len--;

        if (parent.len > 0) {
            Node *include = pres.includes;
            while (include) {

                char *dst = alloc(compiler->arena, parent.len + include->include_path.len + 1, 1);
                if (dst == NULL) {
                    // TODO
                }

                memcpy(dst,
                    parent.ptr,
                    parent.len);
                memcpy(dst + parent.len,
                    include->include_path.ptr,
                    include->include_path.len);

                include->include_path = (String) { dst, parent.len + include->include_path.len };

                include = include->include_next;
            }
        }
    }

    CompiledFile compiled_file = {
        .file = compiler->waiting_file,
        .root = pres.node,
        .includes = pres.includes,
    };
    compiler->files[compiler->num_files++] = compiled_file;
    compiler->waiting_file = (String) { NULL, 0 };

    for (int i = 0; i < compiler->num_files; i++) {

        Node *include = compiler->files[i].includes;
        while (include) {

            ASSERT(include->type == NODE_INCLUDE);

            if (include->include_root == NULL) {
                for (int j = 0; j < compiler->num_files; j++) {
                    if (streq(include->include_path, compiler->files[j].file)) {
                        include->include_root = compiler->files[j].root;
                        break;
                    }
                }
            }

            if (include->include_root == NULL) {

                if (compiler->num_files == FILE_LIMIT) {
                    ASSERT(0); // TODO
                }

                // TODO: Make the path relative to the compiled file

                compiler->waiting_file = include->include_path;
                return (WL_AddResult) { .type=WL_ADD_AGAIN, .path={ include->include_path.ptr, include->include_path.len } };
            }

            include = include->include_next;
        }
    }

    return (WL_AddResult) { .type=WL_ADD_LINK };
}

int wl_compiler_link(WL_Compiler *compiler, WL_Program *program)
{
    if (compiler->err) return -1;

    if (compiler->num_files == 0 || compiler->waiting_file.len > 0) {
        int len = snprintf(compiler->msg, SIZEOF(compiler->msg), "Missing files in compilation unit");
        if (len > SIZEOF(compiler->msg))
            len = SIZEOF(compiler->msg)-1;
        compiler->msg[len] = '\0';
        compiler->err = true;
        return -1;
    }

    char *dst = compiler->arena->ptr + compiler->arena->cur;
    int   cap = compiler->arena->len - compiler->arena->cur;

    int len = codegen(compiler->files[0].root, dst, cap, compiler->msg, SIZEOF(compiler->msg));
    if (len < 0) {
        compiler->err = true;
        return -1;
    }
    if (len > cap) {
        int len = snprintf(compiler->msg, SIZEOF(compiler->msg), "Out of memory");
        if (len > SIZEOF(compiler->msg))
            len = SIZEOF(compiler->msg)-1;
        compiler->msg[len] = '\0';
        compiler->err = true;
        return -1;
    }

    *program = (WL_Program) { dst, len };

    compiler->arena->cur += len;
    return 0;
}

WL_String wl_compiler_error(WL_Compiler *compiler)
{
    return compiler->err
        ? (WL_String) { compiler->msg, strlen(compiler->msg) }
        : (WL_String) { NULL, 0 };
}

int wl_dump_ast(WL_Compiler *compiler, char *dst, int cap)
{
    Writer w = { dst, cap, 0 };
    for (int i = 0; i < compiler->num_files; i++) {
        write_text(&w, S("(file \""));
        write_text(&w, compiler->files[i].file);
        write_text(&w, S("\" "));
        write_node(&w, compiler->files[i].root);
        write_text(&w, S(")"));
    }
    return w.len;
}

/////////////////////////////////////////////////////////////////////////
// OBJECT MODEL
/////////////////////////////////////////////////////////////////////////

typedef enum {
    TYPE_NONE,
    TYPE_BOOL,
    TYPE_INT,
    TYPE_FLOAT,
    TYPE_STRING,
    TYPE_ARRAY,
    TYPE_MAP,
    TYPE_ERROR,
} Type;

#define TAG_ERROR 0
#define TAG_POSITIVE_INT 1
#define TAG_NEGATIVE_INT 2
#define TAG_BOOL 3
#define TAG_NONE 4
#define TAG_PTR  5

#define VALUE_NONE  ((0 << 3) | TAG_NONE)
#define VALUE_TRUE  ((0 << 3) | TAG_BOOL)
#define VALUE_FALSE ((1 << 3) | TAG_BOOL)
#define VALUE_ERROR ((0 << 3) | TAG_ERROR)

typedef uint64_t Value;

typedef struct Extension Extension;
struct Extension {
    Extension *next;
    int count;
    int capacity;
    Value vals[];
};

typedef struct {
    Type  type;
    int   count;
    int   capacity;
    Extension *ext;
    Value vals[];
} AggregateValue;

typedef struct {
    Type   type;
    double raw;
} FloatValue;

typedef struct {
    Type    type;
    int64_t raw;
} IntValue;

typedef struct {
    Type type;
    int  len;
    char data[];
} StringValue;

static int value_convert_to_str(Value v, char *dst, int cap);

static Type value_type(Value v)
{
    switch (v & 7) {
        case TAG_ERROR: return TYPE_ERROR;
        case TAG_POSITIVE_INT: return TYPE_INT;
        case TAG_NEGATIVE_INT: return TYPE_INT;
        case TAG_BOOL : return TYPE_BOOL;
        case TAG_NONE : return TYPE_NONE;
        case TAG_PTR  : return *(Type*) (v & ~(Value) 7); break;
    }
    return TAG_ERROR;
}

static int64_t value_to_s64(Value v)
{
    ASSERT(value_type(v) == TYPE_INT);

    if ((v & 7) == TAG_POSITIVE_INT)
        return (int64_t) (v >> 3);

    if ((v & 7) == TAG_NEGATIVE_INT)
        return (int64_t) ((v >> 3) | ((Value) 7 << 61));

    IntValue *p = (IntValue*) (v & ~(Value) 7);
    return p->raw;
}

static double value_to_f64(Value v)
{
    ASSERT(value_type(v) == TYPE_FLOAT);

    FloatValue *p = (FloatValue*) (v & ~(Value) 7);
    return p->raw;
}

static String value_to_str(Value v)
{
    ASSERT(value_type(v) == TYPE_STRING);

    StringValue *p = (StringValue*) (v & ~(Value) 7);
    return (String) { p->data, p->len };
}

/*

2 bits -> 2^2 = 4

00000   0    .
00001   1    .
00010   2    .
00011   3    .
00100   4    .
00101   5    .
00110   6    .
00111   7    .
01000   8
01001   9
01010   10
01011   11
01100   12
01101   13
01110   14
01111   15
10000  -16
10001  -15
10010  -14
10011  -13
10100  -12
10101  -11
10110  -10
10111  -9
11000  -8    .
11001  -7    .
11010  -6    .
11011  -5    .
11100  -4    .
11101  -3    .
11110  -2    .
11111  -1    .

*/

static Value value_from_s64(int64_t x, WL_Arena *arena, Error *err)
{
    Value v = (Value) x;
    Value upper3bits = v >> 61;

    if (upper3bits == 0)
        return (v << 3) | TAG_POSITIVE_INT;

    if (upper3bits == 7)
        return (v << 3) | TAG_NEGATIVE_INT;

    IntValue *p = alloc(arena, SIZEOF(IntValue), _Alignof(IntValue));
    if (p == NULL) {
        REPORT(err, "Out of memory");
        return VALUE_ERROR;
    }

    p->type = TYPE_INT;
    p->raw  = x;

    ASSERT(((Value) p & 7) == 0);
    return ((Value) p) | TAG_PTR;
}

static Value value_from_f64(double x, WL_Arena *arena, Error *err)
{
    FloatValue *v = alloc(arena, SIZEOF(FloatValue), _Alignof(FloatValue));
    if (v == NULL) {
        REPORT(err, "Out of memory");
        return VALUE_ERROR;
    }

    v->type = TYPE_FLOAT;
    v->raw  = x;

    ASSERT(((uintptr_t) v & 7) == 0);
    return ((Value) v) | TAG_PTR;
}

static Value value_from_str(String x, WL_Arena *arena, Error *err)
{
    StringValue *v = alloc(arena, SIZEOF(StringValue) + x.len, 8);
    if (v == NULL) {
        REPORT(err, "Out of memory");
        return VALUE_ERROR;
    }

    v->type = TYPE_STRING;
    v->len = x.len;
    memcpy(v->data, x.ptr, x.len);

    ASSERT(((uintptr_t) v & 7) == 0);
    return ((Value) v) | TAG_PTR;
}

static Value aggregate_empty(bool map, uint32_t cap, WL_Arena *arena, Error *err)
{
    AggregateValue *v = alloc(arena, SIZEOF(AggregateValue) + 2 * cap * SIZEOF(Value), MAX(_Alignof(AggregateValue), 8));
    if (v == NULL) {
        REPORT(err, "Out of memory");
        return VALUE_ERROR;
    }

    v->type = map ? TYPE_MAP : TYPE_ARRAY;
    v->count = 0;
    v->capacity = cap;
    v->ext = NULL;

    ASSERT(((uintptr_t) v & 7) == 0);
    return ((Value) v) | TAG_PTR;
}

static int64_t aggregate_length(AggregateValue *agg)
{
    int64_t n = agg->count;

    Extension *ext = agg->ext;
    while (ext) {
        n += ext->count;
        ext = ext->next;
    }

    return n;
}

static Value *aggregate_select_by_raw_index(AggregateValue *agg, int64_t idx)
{
    ASSERT(agg->type == TYPE_ARRAY || agg->type == TYPE_MAP);

    if (idx < 0 || idx >= aggregate_length(agg))
        return NULL;

    if (idx < agg->count)
        return &agg->vals[idx];

    idx -= agg->count;
    Extension *ext = agg->ext;
    while (ext) {
        if (idx < ext->count)
            return &ext->vals[idx];
        idx -= ext->count;
        ext = ext->next;
    }

    UNREACHABLE;
    return NULL;
}

static bool value_eql(Value a, Value b);

static Value *aggregate_select(AggregateValue *agg, Value key)
{
    if (agg->type == TYPE_MAP) {

        for (int i = 0; i < agg->count; i += 2)
            if (value_eql(agg->vals[i], key))
                return &agg->vals[i+1];

        Extension *ext = agg->ext;
        while (ext) {
            for (int i = 0; i < ext->count; i += 2)
                if (value_eql(ext->vals[i], key)) {
                    return &ext->vals[i+1];
                }
            ext = ext->next;
        }

        return NULL;
    
    } else {

        ASSERT(agg->type == TYPE_ARRAY);

        if (value_type(key) != TYPE_INT)
            return NULL;
        int64_t idx = value_to_s64(key);

        return aggregate_select_by_raw_index(agg, idx);
    }
}

static bool aggregate_append(AggregateValue *agg, Value v1, Value v2, WL_Arena *arena)
{
    if (agg->count < agg->capacity) {
        agg->vals[agg->count++] = v1;
        if (v2 != VALUE_ERROR)
            agg->vals[agg->count++] = v2;
        return true;
    }

    Extension *tail = agg->ext;
    if (tail)
        while (tail->next)
            tail = tail->next;

    Extension *ext;
    if (tail == NULL || tail->count == tail->capacity) {

        int cap = 8;
        ext = alloc(arena, SIZEOF(Extension) + cap * sizeof(Value), ALIGNOF(Extension));
        if (ext == NULL)
            return false;

        ext->count = 0;
        ext->capacity = cap;
        ext->next = NULL;

        if (tail)
            tail->next = ext;
        else
            agg->ext = ext;

    } else
        ext = tail;

    ext->vals[ext->count++] = v1;
    if (v2 != VALUE_ERROR)
        ext->vals[ext->count++] = v2;
    return true;
}

static Value value_empty_map(uint32_t cap, WL_Arena *arena, Error *err)
{
    return aggregate_empty(true, 2 * cap, arena, err);
}

static Value value_empty_array(uint32_t cap, WL_Arena *arena, Error *err)
{
    return aggregate_empty(false, cap, arena, err);
}

static int64_t value_length(Value set)
{
    ASSERT(value_type(set) == TYPE_MAP || value_type(set) == TYPE_ARRAY);
    AggregateValue *agg = (void*) (set & ~(Value) 7);
    int64_t len = aggregate_length(agg);
    if (agg->type == TYPE_MAP)
        len /= 2;
    return len;
}

static bool value_insert(Value set, Value key, Value val, WL_Arena *arena, Error *err)
{
    Type t = value_type(set);
    if (t != TYPE_MAP && t != TYPE_ARRAY) {
        REPORT(err, "Invalid insertion on non-map and non-array value");
        return false;
    }
    AggregateValue *agg = (void*) (set & ~(Value) 7);

    Value *dst = aggregate_select(agg, key);
    if (dst != NULL) {
        *dst = val;
        return true;
    }

    if (agg->type == TYPE_ARRAY && value_type(key) != TYPE_INT) {
        REPORT(err, "Invalid index used in array access");
        return false;
    }

    if (!aggregate_append(agg, key, val, arena)) {
        REPORT(err, "Out of memory");
        return false;
    }

    return true;
}

static Value value_select(Value set, Value key, Error *err)
{
    Type t = value_type(set);
    if (t != TYPE_MAP && t != TYPE_ARRAY) {
        REPORT(err, "Invalid selection from non-map and non-array value");
        return VALUE_ERROR;
    }
    AggregateValue *agg = (void*) (set & ~(Value) 7);

    Value *dst = aggregate_select(agg, key);
    if (dst) return *dst;

    if (agg->type == TYPE_ARRAY && value_type(key) != TYPE_INT) {
        REPORT(err, "Invalid index used in array access");
        return VALUE_ERROR;
    }

    char key_buf[1<<8];
    int key_len = value_convert_to_str(key, key_buf, SIZEOF(key_buf));
    if (key_len > SIZEOF(key_buf)-1)
        key_len = SIZEOF(key_buf)-1;
    key_buf[key_len] = '\0';

    char set_buf[1<<8];
    int set_len = value_convert_to_str(set, set_buf, SIZEOF(set_buf));
    if (set_len > SIZEOF(set_buf)-1)
        set_len = SIZEOF(set_buf)-1;
    set_buf[set_len] = '\0';

    REPORT(err, "Invalid key '%s' used in access to map '%s'", key_buf, set_buf);
    return VALUE_ERROR;
}

static Value value_select_by_index(Value set, int64_t idx, Error *err)
{
    Type t = value_type(set);
    if (t != TYPE_MAP && t != TYPE_ARRAY) {
        REPORT(err, "Invalid selection from non-map and non-array value");
        return VALUE_ERROR;
    }
    AggregateValue *agg = (void*) (set & ~(Value) 7);

    if (agg->type == TYPE_MAP)
        idx *= 2;

    Value *src = aggregate_select_by_raw_index(agg, idx);
    if (src == NULL) {
        REPORT(err, "Invalid selection from non-map and non-array value");
        return VALUE_ERROR;
    }

    return *src;
}

static bool value_append(Value set, Value val, WL_Arena *arena, Error *err)
{
    Type t = value_type(set);
    if (t != TYPE_ARRAY) {
        REPORT(err, "Invalid append on non-array value");
        return false;
    }
    AggregateValue *agg = (void*) (set & ~(Value) 7);

    if (!aggregate_append(agg, val, VALUE_ERROR, arena)) {
        REPORT(err, "Out of memory");
        return false;
    }

    return true;
}

static bool value_eql(Value a, Value b)
{
    Type t1 = value_type(a);
    Type t2 = value_type(b);

    if (t1 != t2)
        return false;

    switch (t1) {

        case TYPE_NONE:
        return true;

        case TYPE_BOOL:
        return a == b;

        case TYPE_INT:
        return value_to_s64(a) == value_to_s64(b);

        case TYPE_FLOAT:
        return value_to_f64(a) == value_to_f64(b);

        case TYPE_MAP:
        return false; // TODO

        case TYPE_ARRAY:
        return false; // TODO

        case TYPE_STRING:
        return streq(value_to_str(a), value_to_str(b));

        case TYPE_ERROR:
        return true;
    }

    return false;
}

static bool value_nql(Value a, Value b)
{
    return !value_eql(a, b);
}

#define TYPE_PAIR(X, Y) (((uint16_t) (X) << 16) | (uint16_t) (Y))

bool value_greater(Value a, Value b, Error *err)
{
    Type t1 = value_type(a);
    Type t2 = value_type(b);
    switch (TYPE_PAIR(t1, t2)) {
        case TYPE_PAIR(TYPE_INT  , TYPE_INT  ): return value_to_s64(a) > value_to_s64(b);
        case TYPE_PAIR(TYPE_INT  , TYPE_FLOAT): return value_to_s64(a) > value_to_f64(b);
        case TYPE_PAIR(TYPE_FLOAT, TYPE_INT  ): return value_to_f64(a) > value_to_s64(b);
        case TYPE_PAIR(TYPE_FLOAT, TYPE_FLOAT): return value_to_f64(a) > value_to_f64(b);
        default:break;
    }
    REPORT(err, "Invalid '>' operation on non-numeric type");
    return false;
}

bool value_lower(Value a, Value b, Error *err)
{
    Type t1 = value_type(a);
    Type t2 = value_type(b);
    switch (TYPE_PAIR(t1, t2)) {
        case TYPE_PAIR(TYPE_INT  , TYPE_INT  ): return value_to_s64(a) < value_to_s64(b);
        case TYPE_PAIR(TYPE_INT  , TYPE_FLOAT): return value_to_s64(a) < value_to_f64(b);
        case TYPE_PAIR(TYPE_FLOAT, TYPE_INT  ): return value_to_f64(a) < value_to_s64(b);
        case TYPE_PAIR(TYPE_FLOAT, TYPE_FLOAT): return value_to_f64(a) < value_to_f64(b);
        default:break;
    }
    REPORT(err, "Invalid '<' operation on non-numeric type");
    return false;
}

static Value value_neg(Value v, WL_Arena *arena, Error *err)
{
    Type t = value_type(v);
    if (t == TYPE_INT)
        return value_from_s64(-value_to_s64(v), arena, err); // TODO: overflow
    
    if (t == TYPE_FLOAT)
        return value_from_f64(-value_to_f64(v), arena, err);

    REPORT(err, "Invalid '-' operation on non-numeric type");
    return VALUE_ERROR;
}

static Value value_add(Value v1, Value v2, WL_Arena *arena, Error *err)
{
    Type t1 = value_type(v1);
    Type t2 = value_type(v2);

    Value r;
    switch (TYPE_PAIR(t1, t2)) {

        case TYPE_PAIR(TYPE_INT, TYPE_INT):
        {
            int64_t u = value_to_s64(v1);
            int64_t v = value_to_s64(v2);
            // TODO: check overflow and underflow
            r = value_from_s64(u + v, arena, err);
        }
        break;

        case TYPE_PAIR(TYPE_INT, TYPE_FLOAT):
        {
            double u = (double) value_to_s64(v1);
            double v = value_to_f64(v2);
            r = value_from_f64(u + v, arena, err);
        }
        break;

        case TYPE_PAIR(TYPE_FLOAT, TYPE_INT):
        {
            double u = value_to_f64(v1);
            double v = (double) value_to_s64(v2);
            r = value_from_f64(u + v, arena, err);
        }
        break;

        case TYPE_PAIR(TYPE_FLOAT, TYPE_FLOAT):
        {
            double u = value_to_f64(v1);
            double v = value_to_f64(v2);
            // TODO: check overflow and underflow
            r = value_from_f64(u + v, arena, err);
        }
        break;

        default:
        REPORT(err, "Invalid operation '+' on non-numeric value");
        return VALUE_ERROR;
    }

    return r;
}

static Value value_sub(Value v1, Value v2, WL_Arena *arena, Error *err)
{
    Type t1 = value_type(v1);
    Type t2 = value_type(v2);

    Value r;
    switch (TYPE_PAIR(t1, t2)) {

        case TYPE_PAIR(TYPE_INT, TYPE_INT):
        {
            int64_t u = value_to_s64(v1);
            int64_t v = value_to_s64(v2);
            // TODO: check overflow and underflow
            r = value_from_s64(u - v, arena, err);
        }
        break;

        case TYPE_PAIR(TYPE_INT, TYPE_FLOAT):
        {
            double u = (double) value_to_s64(v1);
            double v = value_to_f64(v2);
            r = value_from_f64(u - v, arena, err);
        }
        break;

        case TYPE_PAIR(TYPE_FLOAT, TYPE_INT):
        {
            double u = value_to_f64(v1);
            double v = (double) value_to_s64(v2);
            r = value_from_f64(u - v, arena, err);
        }
        break;

        case TYPE_PAIR(TYPE_FLOAT, TYPE_FLOAT):
        {
            double u = value_to_f64(v1);
            double v = value_to_f64(v2);
            // TODO: check overflow and underflow
            r = value_from_f64(u - v, arena, err);
        }
        break;

        default:
        REPORT(err, "Invalid operation '-' on non-numeric value");
        return VALUE_ERROR;
    }

    return r;
}

static Value value_mul(Value v1, Value v2, WL_Arena *arena, Error *err)
{
    Type t1 = value_type(v1);
    Type t2 = value_type(v2);

    Value r;
    switch (TYPE_PAIR(t1, t2)) {

        case TYPE_PAIR(TYPE_INT, TYPE_INT):
        {
            int64_t u = value_to_s64(v1);
            int64_t v = value_to_s64(v2);
            // TODO: check overflow and underflow
            r = value_from_s64(u * v, arena, err);
        }
        break;

        case TYPE_PAIR(TYPE_INT, TYPE_FLOAT):
        {
            double u = (double) value_to_s64(v1);
            double v = value_to_f64(v2);
            r = value_from_f64(u * v, arena, err);
        }
        break;

        case TYPE_PAIR(TYPE_FLOAT, TYPE_INT):
        {
            double u = value_to_f64(v1);
            double v = (double) value_to_s64(v2);
            r = value_from_f64(u * v, arena, err);
        }
        break;

        case TYPE_PAIR(TYPE_FLOAT, TYPE_FLOAT):
        {
            double u = value_to_f64(v1);
            double v = value_to_f64(v2);
            // TODO: check overflow and underflow
            r = value_from_f64(u * v, arena, err);
        }
        break;

        default:
        REPORT(err, "Invalid operation '*' on non-numeric value");
        return VALUE_ERROR;
    }

    return r;
}

static Value value_div(Value v1, Value v2, WL_Arena *arena, Error *err)
{
    Type t1 = value_type(v1);
    Type t2 = value_type(v2);

    Value r;
    switch (TYPE_PAIR(t1, t2)) {

        case TYPE_PAIR(TYPE_INT, TYPE_INT):
        {
            // TODO: check division by 0

            int64_t u = value_to_s64(v1);
            int64_t v = value_to_s64(v2);
            r = value_from_s64(u / v, arena, err);
        }
        break;

        case TYPE_PAIR(TYPE_INT, TYPE_FLOAT):
        {
            // TODO: check division by 0

            double u = (double) value_to_s64(v1);
            double v = value_to_f64(v2);
            r = value_from_f64(u / v, arena, err);
        }
        break;

        case TYPE_PAIR(TYPE_FLOAT, TYPE_INT):
        {
            // TODO: check division by 0

            double u = value_to_f64(v1);
            double v = (double) value_to_s64(v2);
            r = value_from_f64(u / v, arena, err);
        }
        break;

        case TYPE_PAIR(TYPE_FLOAT, TYPE_FLOAT):
        {
            double u = value_to_f64(v1);
            double v = value_to_f64(v2);
            r = value_from_f64(u / v, arena, err);
        }
        break;

        default:
        REPORT(err, "Invalid operation '/' on non-numeric value");
        return VALUE_ERROR;
    }

    return r;
}

static Value value_mod(Value v1, Value v2, WL_Arena *arena, Error *err)
{
    Type t1 = value_type(v1);
    Type t2 = value_type(v2);

    if (t1 != TYPE_INT || t2 != TYPE_INT) {
        REPORT(err, "Invalid operation '%%' on non-integer value");
        return VALUE_ERROR;
    }

    int64_t u = value_to_s64(v1);
    int64_t v = value_to_s64(v2);
    Value r = value_from_s64(u % v, arena, err);
    return r;
}

static void value_convert_to_str_inner(Writer *w, Value v)
{
    Type t = value_type(v);
    switch (t) {

        case TYPE_NONE:
        break;

        case TYPE_BOOL:
        write_text(w, v == VALUE_TRUE ? S("true") : S("false"));
        break;

        case TYPE_INT:
        write_text_s64(w, value_to_s64(v));
        break;

        case TYPE_FLOAT:
        write_text_f64(w, value_to_f64(v));
        break;

        case TYPE_STRING:
        write_text(w, value_to_str(v));
        break;

        case TYPE_ARRAY:
        {
            AggregateValue *agg = (void*) (v & ~(Value) 7);
            for (int i = 0; i < agg->count; i++)
                value_convert_to_str_inner(w, agg->vals[i]);
            Extension *ext = agg->ext;
            while (ext) {
                for (int i = 0; i < ext->count; i++)
                    value_convert_to_str_inner(w, ext->vals[i]);
                ext = ext->next;
            }
        }
        break;

        case TYPE_MAP:
        write_text(w, S("<map>"));
        break;

        case TYPE_ERROR:
        break;
    }
}

static int value_convert_to_str(Value v, char *dst, int cap)
{
    Writer w = { dst, cap, 0};
    value_convert_to_str_inner(&w, v);
    return w.len;
}

static Value value_escape_packed(Value v, WL_Arena *arena, Error *err);

static int array_escape(Value v, Value *out, int max, WL_Arena *arena, Error *err)
{
    Value v2 = value_empty_array(value_length(v), arena, err);
    if (v2 == VALUE_ERROR) return -1;

    AggregateValue *src = (void*) (v  & ~(Value) 7);

    for (int i = 0; i < src->count; i++) {

        Value child = src->vals[i];

        Value escaped_child = value_escape_packed(child, arena, err);
        if (escaped_child == VALUE_ERROR)
            return -1;

        if (!value_append(v2, escaped_child, arena, err))
            return -1;
    }
    Extension *ext = src->ext;
    while (ext) {
        for (int i = 0; i < ext->count; i++) {

            Value child = src->vals[i];

            Value escaped_child = value_escape_packed(child, arena, err);
            if (escaped_child == VALUE_ERROR)
                return -1;

            if (!value_append(v2, escaped_child, arena, err))
                return -1;
        }
        ext = ext->next;
    }

    if (max == 0)
        return -1;
    out[0] = v2;
    return 1;
}

static int string_escape(Value v, Value *out, int max, WL_Arena *arena, Error *err)
{
    String s = value_to_str(v);

    int i = 0;
    int num = 0;
    for (;;) {

        int off = i;
        while (i < s.len
            && s.ptr[i] != '<'
            && s.ptr[i] != '>'
            && s.ptr[i] != '&'
            && s.ptr[i] != '"'
            && s.ptr[i] != '\'')
            i++;
        String substr = { s.ptr + off, i - off };

        Value escaped_v = value_from_str(substr, arena, err); // TODO: don't copy the string
        if (escaped_v == VALUE_ERROR) return -1;

        if (num == max) {
            REPORT(err, "Escape buffer limit reached");
            return -1;
        }
        out[num++] = escaped_v;

        if (i == s.len) break;

        switch (s.ptr[i++]) {
            case '<' : escaped_v = value_from_str(S("&lt;"),   arena, err); break; // TODO: don't come these strings
            case '>' : escaped_v = value_from_str(S("&gt;"),   arena, err); break;
            case '&' : escaped_v = value_from_str(S("&amp;"),  arena, err); break;
            case '"' : escaped_v = value_from_str(S("&quot;"), arena, err); break;
            case '\'': escaped_v = value_from_str(S("&#x27;"), arena, err); break;
        }
        if (escaped_v == VALUE_ERROR) return -1;

        if (num == max) {
            REPORT(err, "Escape buffer limit reached");
            return -1;
        }
        out[num++] = escaped_v;
    }

    return num;
}

static int value_escape(Value v, Value *out, int max, WL_Arena *arena, Error *err)
{
    Type t = value_type(v);

    if (t == TYPE_ARRAY)
        return array_escape(v, out, max, arena, err);

    if (t == TYPE_STRING)
        return string_escape(v, out, max, arena, err);

    if (max < 1)
        return -1;
    out[0] = v;
    return 1;
}

static Value value_escape_packed(Value v, WL_Arena *arena, Error *err)
{
    Value tmp[32];
    int num = value_escape(v, tmp, COUNT(tmp), arena, err);
    if (num < 0) return VALUE_ERROR;

    Value escaped_v;

    if (num > 1) {

        Value packed = value_empty_array(num, arena, err);
        if (packed == VALUE_ERROR)
            return VALUE_ERROR;

        for (int j = 0; j < num; j++)
            if (!value_append(packed, tmp[j], arena, err))
                return VALUE_ERROR;
        escaped_v = packed;

    } else {

        ASSERT(num == 1);
        escaped_v = tmp[0];
    }

    return escaped_v;
}

#undef TYPE_PAIR

/////////////////////////////////////////////////////////////////////////
// RUNTIME
/////////////////////////////////////////////////////////////////////////

#define MAX_STACK 1024
#define MAX_FRAMES 1024
#define MAX_GROUPS 8

typedef struct {
    int retaddr;
    int varbase;
} Frame;

typedef enum {
    RUNTIME_BEGIN,
    RUNTIME_LOOP,
    RUNTIME_DONE,
    RUNTIME_ERROR,
    RUNTIME_OUTPUT,
    RUNTIME_SYSVAR,
    RUNTIME_SYSCALL,
} RuntimeState;

struct WL_Runtime {

    RuntimeState state;

    String code;
    String data;
    int off;

    int vars;
    int stack;
    Value values[MAX_STACK];

    int num_frames;
    Frame frames[MAX_FRAMES];

    int num_groups;
    int groups[MAX_GROUPS];

    WL_Arena *arena;

    char  msg[128];
    Error err;

    int stack_before_user;
    String str_for_user;
    int num_output;
    int cur_output;
    char buf[128];
};

WL_Runtime *wl_runtime_init(WL_Arena *arena, WL_Program program)
{
    if (program.len < 3 * sizeof(uint32_t))
        return NULL;

    uint32_t magic;
    uint32_t code_len;
    uint32_t data_len;

    memcpy(&magic   , program.ptr + 0, sizeof(uint32_t));
    memcpy(&code_len, program.ptr + 4, sizeof(uint32_t));
    memcpy(&data_len, program.ptr + 8, sizeof(uint32_t));

    if (magic != WL_MAGIC)
        return NULL;

    String code = { program.ptr + sizeof(uint32_t) * 3           , code_len };
    String data = { program.ptr + sizeof(uint32_t) * 3 + code_len, data_len };

    WL_Runtime *rt = alloc(arena, SIZEOF(WL_Runtime), ALIGNOF(WL_Runtime));
    if (rt == NULL)
        return NULL;

    *rt = (WL_Runtime) {
        .state      = RUNTIME_BEGIN,
        .code       = code,
        .data       = data,
        .off        = 0,
        .stack      = 0,
        .vars       = MAX_STACK-1,
        .num_frames = 0,
        .arena      = arena,
        .err        = { NULL, 0, false },
    };
    rt->err.buf = rt->msg;
    rt->err.cap = SIZEOF(rt->msg);

    rt->frames[rt->num_frames++] = (Frame) {
        .retaddr = 0,
        .varbase = rt->vars,
    };

    return rt;
}

WL_String wl_runtime_error(WL_Runtime *rt)
{
    return rt->err.yes
        ? (WL_String) { rt->msg, strlen(rt->msg) }
        : (WL_String) { NULL, 0 };
}

static void rt_read_mem(WL_Runtime *r, void *dst, int len)
{
    ASSERT(r->off + len <= r->code.len);
    memcpy(dst, r->code.ptr + r->off, len);
    r->off += len;
}

static uint8_t rt_read_u8(WL_Runtime *rt)
{
    ASSERT(rt->state == RUNTIME_LOOP);

    uint8_t x;
    rt_read_mem(rt, &x, SIZEOF(x));

    return x;
}

static uint32_t rt_read_u32(WL_Runtime *rt)
{
    ASSERT(rt->state == RUNTIME_LOOP);

    uint32_t x;
    rt_read_mem(rt, &x, SIZEOF(x));

    return x;
}

static int64_t rt_read_s64(WL_Runtime *rt)
{
    ASSERT(rt->state == RUNTIME_LOOP);

    int64_t x;
    rt_read_mem(rt, &x, SIZEOF(x));

    return x;
}

static double rt_read_f64(WL_Runtime *rt)
{
    ASSERT(rt->state == RUNTIME_LOOP);

    double x;
    rt_read_mem(rt, &x, SIZEOF(x));

    return x;
}

static String rt_read_str(WL_Runtime *rt)
{
    ASSERT(rt->state == RUNTIME_LOOP);
    uint32_t off = rt_read_u32(rt);
    uint32_t len = rt_read_u32(rt);
    ASSERT(off + len <= (uint32_t) rt->data.len);
    return (String) { rt->data.ptr + off, len };
}

static Value *rt_variable(WL_Runtime *rt, uint8_t x)
{
    ASSERT(rt->num_frames > 0);

    Frame *frame = &rt->frames[rt->num_frames-1];

    ASSERT(frame->varbase - x >= 0
        && frame->varbase - x < MAX_STACK);

    return &rt->values[frame->varbase - x];
}

static int values_usage(WL_Runtime *rt)
{
    int num_vars = (MAX_STACK - rt->vars - 1);
    return rt->stack + num_vars;
}

static bool rt_check_stack(WL_Runtime *rt, int min)
{
    if (MAX_STACK - values_usage(rt) < min) {
        REPORT(&rt->err, "Out of stack");
        rt->state = RUNTIME_ERROR;
        return false;
    }
    return true;
}

static bool rt_push_frame(WL_Runtime *rt, uint8_t args)
{
    if (rt->num_frames == MAX_FRAMES) {
        REPORT(&rt->err, "Call stack limit reached");
        rt->state = RUNTIME_ERROR;
        return false;
    }

    if (MAX_STACK - values_usage(rt) < args) {
        REPORT(&rt->err, "Stack limit reached");
        rt->state = RUNTIME_ERROR;
        return false;
    }

    Frame *frame = &rt->frames[rt->num_frames++];
    frame->retaddr = rt->off;
    frame->varbase = rt->vars;

    for (int i = 0; i < args; i++)
        rt->values[rt->vars--] = rt->values[--rt->stack];

    return true;
}

static void rt_pop_frame(WL_Runtime *rt)
{
    ASSERT(rt->num_frames > 0);
    Frame *frame = &rt->frames[rt->num_frames-1];
    rt->off  = frame->retaddr;
    rt->vars = frame->varbase;
    rt->num_frames--;
}

static void rt_set_frame_vars(WL_Runtime *rt, uint8_t num)
{
    ASSERT(rt->num_frames > 0);
    Frame *frame = &rt->frames[rt->num_frames-1];
    int num_vars = frame->varbase - rt->vars;
    if (num_vars < num)
        for (int i = 0; i < num - num_vars; i++)
            rt->values[rt->vars - i] = VALUE_NONE;
    rt->vars = frame->varbase - num;
}

static void rt_push_group(WL_Runtime *rt)
{
    if (rt->num_groups == MAX_GROUPS) {
        REPORT(&rt->err, "Out of memory");
        rt->state = RUNTIME_ERROR;
        return;
    }
    rt->groups[rt->num_groups++] = rt->stack;
}

static void rt_pack_group(WL_Runtime *rt)
{
    if (!rt_check_stack(rt, 1))
        return;

    ASSERT(rt->num_groups > 0);
    int start = rt->groups[--rt->num_groups];
    int end = rt->stack;

    if (end - start > 1) {

        Value set = value_empty_array(end - start, rt->arena, &rt->err);
        if (set == VALUE_ERROR)
            return;

        for (int i = start; i < end; i++)
            if (!value_append(set, rt->values[i], rt->arena, &rt->err))
                return;

        rt->stack = start;
        rt->values[rt->stack++] = set;
    }
}

static void rt_pop_group(WL_Runtime *rt)
{
    ASSERT(rt->num_groups > 0);
    rt->stack = rt->groups[--rt->num_groups];
}

static void value_print(Value v)
{
    char buf[1<<8];
    int len = value_convert_to_str(v, buf, SIZEOF(buf));
    if (len < SIZEOF(buf))
        fwrite(buf, 1, len, stdout);
    else {
        len = SIZEOF(buf)-1;
        fwrite(buf, 1, len, stdout);
        fprintf(stdout, " [...]");
    }
    putc('\n', stdout);
    fflush(stdout);
}

static void step(WL_Runtime *rt)
{
    switch (rt_read_u8(rt)) {

        Type t;
        Value v1;
        Value v2;
        Value v3;
        uint32_t o;
        uint8_t  b1;
        uint8_t  b2;
        uint8_t  b3;
        int64_t  i;
        double   f;
        String   s;

        case OPCODE_NOPE:
        break;

        case OPCODE_JUMP:
        rt->off = rt_read_u32(rt);
        break;

        case OPCODE_JIFP:
        ASSERT(rt->stack > 0);
        o = rt_read_u32(rt);
        v1 = rt->values[--rt->stack];
        if (v1 == VALUE_FALSE)
            rt->off = o;
        else if (value_type(v1) != TYPE_BOOL) {
            REPORT(&rt->err, "Invalid non-boolean condition");
            rt->state = RUNTIME_ERROR;
            break;
        }
        break;

        case OPCODE_VARS:
        b1 = rt_read_u8(rt);
        rt_set_frame_vars(rt, b1);
        break;

        case OPCODE_OUTPUT:
        if (rt->stack > 0) {
            rt->cur_output = 0;
            rt->num_output = rt->stack;
            rt->state = RUNTIME_OUTPUT;
        }
        break;

        case OPCODE_SYSVAR:
        s = rt_read_str(rt);
        rt_push_frame(rt, 0);
        rt->stack_before_user = rt->stack;
        rt->str_for_user = s;
        rt->state = RUNTIME_SYSVAR;
        break;

        case OPCODE_SYSCALL:
        b1 = rt_read_u8(rt);
        s = rt_read_str(rt);
        rt_push_frame(rt, b1);
        rt->stack_before_user = rt->stack;
        rt->str_for_user = s;
        rt->state = RUNTIME_SYSCALL;
        break;

        case OPCODE_CALL:
        b1 = rt_read_u8(rt);
        o = rt_read_u32(rt);
        rt_push_frame(rt, b1);
        rt->off = o;
        break;

        case OPCODE_RET:
        rt_pop_frame(rt);
        break;

        case OPCODE_GROUP:
        rt_push_group(rt);
        break;

        case OPCODE_ESCAPE:
        {
            ASSERT(rt->num_groups > 0);
            int start = rt->groups[--rt->num_groups];
            int end = rt->stack;

            Value escaped[256];
            int num_escaped = 0;

            for (int i = start; i < end; i++) {
                Value v = rt->values[i];
                int num = value_escape(v, escaped + num_escaped, COUNT(escaped) - num_escaped, rt->arena, &rt->err);
                if (num < 0) break;
                num_escaped += num;
            }

            if (num_escaped > COUNT(escaped)) {
                REPORT(&rt->err, "Escape buffer limit reached");
                rt->state = RUNTIME_ERROR;
                break;
            }

            rt->stack = start;
            if (!rt_check_stack(rt, num_escaped)) break;

            for (int i = 0; i < num_escaped; i++)
                rt->values[rt->stack + i] = escaped[i];
            rt->stack += num_escaped;
        }
        break;

        case OPCODE_PACK:
        rt_pack_group(rt);
        break;

        case OPCODE_GPOP:
        rt_pop_group(rt);
        break;

        case OPCODE_FOR:
        b1 = rt_read_u8(rt);
        b2 = rt_read_u8(rt);
        b3 = rt_read_u8(rt);
        o  = rt_read_u32(rt);

        v1 = *rt_variable(rt, b3);
        ASSERT(value_type(v1) == TYPE_INT);
        i = value_to_s64(v1);

        v2 = *rt_variable(rt, b1);

        if (value_length(v2)-1 == i) {
            rt->off = o;
            break;
        }
        i++;

        v1 = value_select_by_index(v2, i, &rt->err);
        if (v1 == VALUE_ERROR) break;

        *rt_variable(rt, b2) = v1;

        v1 = value_from_s64(i, rt->arena, &rt->err); // TODO: this could be in-place
        *rt_variable(rt, b3) = v1;
        break;

        case OPCODE_EXIT:
        rt->state = RUNTIME_DONE;
        break;

        case OPCODE_POP:
        ASSERT(rt->stack > 0);
        rt->stack--;
        break;

        case OPCODE_SETV:
        ASSERT(rt->stack > 0);
        b1 = rt_read_u8(rt);
        *rt_variable(rt, b1) =  rt->values[rt->stack-1];
        break;

        case OPCODE_PUSHV:
        if (!rt_check_stack(rt, 1)) break;
        b1 = rt_read_u8(rt);
        rt->values[rt->stack++] = *rt_variable(rt, b1);
        break;

        case OPCODE_PUSHI:
        if (!rt_check_stack(rt, 1)) break;
        i = rt_read_s64(rt);
        v1 = value_from_s64(i, rt->arena, &rt->err);
        rt->values[rt->stack++] = v1;
        break;

        case OPCODE_PUSHF:
        if (!rt_check_stack(rt, 1)) break;
        f = rt_read_f64(rt);
        v1 = value_from_f64(f, rt->arena, &rt->err);
        rt->values[rt->stack++] = v1;
        break;

        case OPCODE_PUSHS:
        if (!rt_check_stack(rt, 1)) break;
        s = rt_read_str(rt);
        v1 = value_from_str(s, rt->arena, &rt->err);
        rt->values[rt->stack++] = v1;
        break;

        case OPCODE_PUSHA:
        if (!rt_check_stack(rt, 1)) break;
        o = rt_read_u32(rt);
        v1 = value_empty_array(o, rt->arena, &rt->err);
        rt->values[rt->stack++] = v1;
        break;

        case OPCODE_PUSHM:
        if (!rt_check_stack(rt, 1)) break;
        o = rt_read_u32(rt);
        v1 = value_empty_map(o, rt->arena, &rt->err);
        rt->values[rt->stack++] = v1;
        break;

        case OPCODE_PUSHN:
        if (!rt_check_stack(rt, 1)) break;
        rt->values[rt->stack++] = VALUE_NONE;
        break;

        case OPCODE_PUSHT:
        if (!rt_check_stack(rt, 1)) break;
        rt->values[rt->stack++] = VALUE_TRUE;
        break;

        case OPCODE_PUSHFL:
        if (!rt_check_stack(rt, 1)) break;
        rt->values[rt->stack++] = VALUE_FALSE;
        break;

        case OPCODE_LEN:
        ASSERT(rt->stack > 0);
        v1 = rt->values[rt->stack-1];
        t = value_type(v1);
        if (t != TYPE_ARRAY && t != TYPE_MAP) {
            REPORT(&rt->err, "Invalid operation 'len' on non-aggregate value");
            rt->state = RUNTIME_ERROR;
            break;
        }
        v2 = value_from_s64(value_length(v1), rt->arena, &rt->err);
        rt->values[rt->stack-1] = v2;
        break;

        case OPCODE_NEG:
        ASSERT(rt->stack > 0);
        v1 = rt->values[rt->stack-1];
        v2 = value_neg(v1, rt->arena, &rt->err);
        rt->values[rt->stack-1] = v2;
        break;

        case OPCODE_EQL:
        ASSERT(rt->stack > 1);
        v1 = rt->values[--rt->stack];
        v2 = rt->values[--rt->stack];
        v3 = value_eql(v2, v1) ? VALUE_TRUE : VALUE_FALSE;
        rt->values[rt->stack++] = v3;
        break;

        case OPCODE_NQL:
        ASSERT(rt->stack > 1);
        v1 = rt->values[--rt->stack];
        v2 = rt->values[--rt->stack];
        v3 = value_nql(v2, v1) ? VALUE_TRUE : VALUE_FALSE;
        rt->values[rt->stack++] = v3;
        break;

        case OPCODE_LSS:
        ASSERT(rt->stack > 1);
        v1 = rt->values[--rt->stack];
        v2 = rt->values[--rt->stack];
        v3 = value_lower(v2, v1, &rt->err) ? VALUE_TRUE : VALUE_FALSE;
        rt->values[rt->stack++] = v3;
        break;

        case OPCODE_GRT:
        ASSERT(rt->stack > 1);
        v1 = rt->values[--rt->stack];
        v2 = rt->values[--rt->stack];
        v3 = value_greater(v2, v1, &rt->err) ? VALUE_TRUE : VALUE_FALSE;
        rt->values[rt->stack++] = v3;
        break;

        case OPCODE_ADD:
        ASSERT(rt->stack > 1);
        v1 = rt->values[--rt->stack];
        v2 = rt->values[--rt->stack];
        v3 = value_add(v2, v1, rt->arena, &rt->err);
        rt->values[rt->stack++] = v3;
        break;

        case OPCODE_SUB:
        ASSERT(rt->stack > 1);
        v1 = rt->values[--rt->stack];
        v2 = rt->values[--rt->stack];
        v3 = value_sub(v2, v1, rt->arena, &rt->err);
        rt->values[rt->stack++] = v3;
        break;

        case OPCODE_MUL:
        ASSERT(rt->stack > 1);
        v1 = rt->values[--rt->stack];
        v2 = rt->values[--rt->stack];
        v3 = value_mul(v2, v1, rt->arena, &rt->err);
        rt->values[rt->stack++] = v3;
        break;

        case OPCODE_DIV:
        ASSERT(rt->stack > 1);
        v1 = rt->values[--rt->stack];
        v2 = rt->values[--rt->stack];
        v3 = value_div(v2, v1, rt->arena, &rt->err);
        rt->values[rt->stack++] = v3;
        break;

        case OPCODE_MOD:
        ASSERT(rt->stack > 1);
        v1 = rt->values[--rt->stack];
        v2 = rt->values[--rt->stack];
        v3 = value_mod(v2, v1, rt->arena, &rt->err);
        rt->values[rt->stack++] = v3;
        break;

        case OPCODE_APPEND:
        ASSERT(rt->stack > 1);
        v2 = rt->values[--rt->stack];
        v1 = rt->values[rt->stack-1];
        value_append(v1, v2, rt->arena, &rt->err);
        break;

        case OPCODE_INSERT1:
        ASSERT(rt->stack > 2);
        v1 = rt->values[--rt->stack];
        v2 = rt->values[--rt->stack];
        v3 = rt->values[rt->stack-1];
        value_insert(v3, v1, v2, rt->arena, &rt->err);
        break;

        case OPCODE_INSERT2:
        ASSERT(rt->stack > 2);
        v1 = rt->values[--rt->stack];
        v2 = rt->values[--rt->stack];
        v3 = rt->values[rt->stack-1];
        value_insert(v2, v1, v3, rt->arena, &rt->err);
        break;

        case OPCODE_SELECT:
        ASSERT(rt->stack > 1);
        v1 = rt->values[--rt->stack];
        v2 = rt->values[--rt->stack];
        v3 = value_select(v2, v1, &rt->err);
        rt->values[rt->stack++] = v3;
        break;

        default:
        UNREACHABLE;
    }
}

WL_EvalResult wl_runtime_eval(WL_Runtime *rt)
{
    if (rt->state != RUNTIME_OUTPUT || rt->cur_output == rt->num_output) {

        switch (rt->state) {

            case RUNTIME_BEGIN:
            break;

            case RUNTIME_DONE:
            return (WL_EvalResult) { .type=WL_EVAL_DONE };

            case RUNTIME_ERROR:
            return (WL_EvalResult) { .type=WL_EVAL_ERROR };

            case RUNTIME_OUTPUT:
            rt->stack -= rt->num_output;
            break;

            case RUNTIME_SYSVAR:
            {
                ASSERT(rt->stack >= rt->stack_before_user);

                int pushed_by_user = rt->stack - rt->stack_before_user;
                if (pushed_by_user > 1) {
                    REPORT(&rt->err, "Invalid API usage");
                    rt->state = RUNTIME_ERROR;
                    return (WL_EvalResult) { .type=WL_EVAL_ERROR };
                }

                if (rt->stack == rt->stack_before_user) {
                    // User didn't push anything on the stack
                    if (!rt_check_stack(rt, 1))
                        return (WL_EvalResult) { .type=WL_EVAL_ERROR };
                    rt->values[rt->stack++] = VALUE_NONE;
                }

                rt_pop_frame(rt);
            }
            break;

            case RUNTIME_SYSCALL:
            ASSERT(rt->stack >= rt->stack_before_user);
            rt_pop_frame(rt);
            break;

            default:
            UNREACHABLE;
        }

        rt->state = RUNTIME_LOOP;

        do {

            step(rt);

            if (rt->err.yes)
                rt->state = RUNTIME_ERROR;

        } while (rt->state == RUNTIME_LOOP);

    }

    switch (rt->state) {

        case RUNTIME_BEGIN:
        case RUNTIME_LOOP:
        UNREACHABLE;

        case RUNTIME_DONE:
        break;

        case RUNTIME_ERROR:
        return (WL_EvalResult) { .type=WL_EVAL_ERROR };

        case RUNTIME_OUTPUT:
        {
            ASSERT(rt->cur_output < rt->num_output);

            Value v = rt->values[rt->stack - rt->num_output + rt->cur_output];
            Type type = value_type(v);

            String str;
            if (type == TYPE_STRING)
                str = value_to_str(v);
            else {
                int len = value_convert_to_str(v, rt->buf, SIZEOF(rt->buf));
                if (len > SIZEOF(rt->buf)) {
                    char *p = alloc(rt->arena, len, 1);
                    if (p == NULL) {
                        REPORT(&rt->err, "Out of memory");
                        rt->state = RUNTIME_ERROR;
                        return (WL_EvalResult) { .type=WL_EVAL_ERROR };
                    }
                    len = value_convert_to_str(v, p, len);
                    str = (String) { p, len };
                } else {
                    str = (String) { rt->buf, len };
                }
            }

            rt->cur_output++;
            return (WL_EvalResult) { .type=WL_EVAL_OUTPUT, .str={ str.ptr, str.len } };
        }

        case RUNTIME_SYSVAR:
        return (WL_EvalResult) { .type=WL_EVAL_SYSVAR, .str=(WL_String) { rt->str_for_user.ptr, rt->str_for_user.len } };

        case RUNTIME_SYSCALL:
        return (WL_EvalResult) { .type=WL_EVAL_SYSCALL, .str=(WL_String) { rt->str_for_user.ptr, rt->str_for_user.len } };
    }

    return (WL_EvalResult) { .type=WL_EVAL_DONE };
}

bool wl_streq(WL_String a, char *b, int blen)
{
    if (b == NULL) b = "";
    if (blen < 0) blen = strlen(b);
    return streq((String) { a.ptr, a.len }, (String) { b, blen });
}

int wl_arg_count(WL_Runtime *rt)
{
    if (rt->state != RUNTIME_SYSVAR &&
        rt->state != RUNTIME_SYSCALL)
        return -1;

    ASSERT(rt->num_frames > 0);
    return rt->frames[rt->num_frames-1].varbase - rt->vars; // TODO: is this right?
}

static Value user_arg(WL_Runtime *rt, int idx, Type type)
{
    if (rt->state != RUNTIME_SYSVAR &&
        rt->state != RUNTIME_SYSCALL)
        return -1;

    int tot = wl_arg_count(rt);
    if (idx < 0 || idx >= tot)
        return false;

    Value v = *rt_variable(rt, tot - idx - 1);
    if (value_type(v) != type)
        return VALUE_ERROR;

    return v;
}

bool wl_arg_none(WL_Runtime *rt, int idx)
{
    Value v = user_arg(rt, idx, TYPE_NONE);
    if (v == VALUE_ERROR)
        return false;
    return true;
}

bool wl_arg_bool(WL_Runtime *rt, int idx, bool *x)
{
    Value v = user_arg(rt, idx, TYPE_BOOL);
    if (v == VALUE_ERROR)
        return false;
    *x = (v == VALUE_TRUE);
    return true;
}

bool wl_arg_s64(WL_Runtime *rt, int idx, int64_t *x)
{
    Value v = user_arg(rt, idx, TYPE_INT);
    if (v == VALUE_ERROR)
        return false;
    *x = value_to_s64(v);
    return true;
}

bool wl_arg_f64(WL_Runtime *rt, int idx, double *x)
{
    Value v = user_arg(rt, idx, TYPE_FLOAT);
    if (v == VALUE_ERROR)
        return false;
    *x = value_to_f64(v);
    return true;
}

bool wl_arg_str(WL_Runtime *rt, int idx, WL_String *x)
{
    Value v = user_arg(rt, idx, TYPE_STRING);
    if (v == VALUE_ERROR)
        return false;
    String s = value_to_str(v);
    *x = (WL_String) { s.ptr, s.len };
    return true;
}

bool wl_arg_array(WL_Runtime *rt, int idx)
{
    Value v = user_arg(rt, idx, TYPE_ARRAY);
    if (v == VALUE_ERROR)
        return false;
    return true;
}

bool wl_arg_map(WL_Runtime *rt, int idx)
{
    Value v = user_arg(rt, idx, TYPE_MAP);
    if (v == VALUE_ERROR)
        return false;
    return true;
}

static Value user_peek(WL_Runtime *rt, int off, Type type)
{
    if (rt->state != RUNTIME_SYSVAR &&
        rt->state != RUNTIME_SYSCALL)
        return VALUE_ERROR;

    if (rt->stack + off < rt->stack_before_user || off >= 0)
        return VALUE_ERROR;

    Value v = rt->values[rt->stack + off];
    if (value_type(v) != type)
        return VALUE_ERROR;

    return v;
}

bool wl_peek_none(WL_Runtime *rt, int off)
{
    Value v = user_peek(rt, off, TYPE_NONE);
    if (v == VALUE_ERROR)
        return false;
    return true;
}

bool wl_peek_bool(WL_Runtime *rt, int off, bool *x)
{
    Value v = user_peek(rt, off, TYPE_BOOL);
    if (v == VALUE_ERROR)
        return false;
    *x = (v == VALUE_TRUE);
    return true;
}

bool wl_peek_s64(WL_Runtime *rt, int off, int64_t *x)
{
    Value v = user_peek(rt, off, TYPE_INT);
    if (v == VALUE_ERROR)
        return false;
    *x = value_to_s64(v);
    return true;
}

bool wl_peek_f64(WL_Runtime *rt, int off, double *x)
{
    Value v = user_peek(rt, off, TYPE_FLOAT);
    if (v == VALUE_ERROR)
        return false;
    *x = value_to_f64(v);
    return true;
}

bool wl_peek_str(WL_Runtime *rt, int off, WL_String *x)
{
    Value v = user_peek(rt, off, TYPE_STRING);
    if (v == VALUE_ERROR)
        return false;
    String s = value_to_str(v);
    *x = (WL_String) { s.ptr, s.len };
    return true;
}

bool wl_pop_any(WL_Runtime *rt)
{
    if (rt->state != RUNTIME_SYSVAR &&
        rt->state != RUNTIME_SYSCALL)
        return VALUE_ERROR;

    if (rt->stack == rt->stack_before_user)
        return false;

    ASSERT(rt->stack > 0);
    rt->stack--;
    return true;
}

static Value user_pop(WL_Runtime *rt, Type type)
{
    if (rt->state != RUNTIME_SYSVAR &&
        rt->state != RUNTIME_SYSCALL)
        return VALUE_ERROR;

    if (rt->stack == rt->stack_before_user)
        return VALUE_ERROR;

    ASSERT(rt->stack > 0);
    Value v = rt->values[rt->stack-1];
    if (value_type(v) != type)
        return VALUE_ERROR;

    rt->stack--;
    return v;
}

bool wl_pop_none(WL_Runtime *rt)
{
    Value v = user_pop(rt, TYPE_NONE);
    if (v == VALUE_ERROR)
        return false;
    return true;
}

bool wl_pop_bool(WL_Runtime *rt, bool *x)
{
    Value v = user_pop(rt, TYPE_BOOL);
    if (v == VALUE_ERROR)
        return false;
    *x = (v == VALUE_TRUE);
    return true;
}

bool wl_pop_s64(WL_Runtime *rt, int64_t *x)
{
    Value v = user_pop(rt, TYPE_INT);
    if (v == VALUE_ERROR)
        return false;
    *x = value_to_s64(v);
    return true;
}

bool wl_pop_f64(WL_Runtime *rt, double *x)
{
    Value v = user_pop(rt, TYPE_FLOAT);
    if (v == VALUE_ERROR)
        return false;
    *x = value_to_f64(v);
    return true;
}

bool wl_pop_str(WL_Runtime *rt, WL_String *x)
{
    Value v = user_pop(rt, TYPE_STRING);
    if (v == VALUE_ERROR)
        return false;
    String s = value_to_str(v);
    *x = (WL_String) { s.ptr, s.len };
    return true;
}

void wl_push_none(WL_Runtime *rt)
{
    if (rt->state != RUNTIME_SYSVAR &&
        rt->state != RUNTIME_SYSCALL)
        return;

    if (!rt_check_stack(rt, 1))
        return;

    rt->values[rt->stack++] = VALUE_NONE;
}

void wl_push_true(WL_Runtime *rt)
{
    if (rt->state != RUNTIME_SYSVAR &&
        rt->state != RUNTIME_SYSCALL)
        return;

    if (!rt_check_stack(rt, 1))
        return;

    rt->values[rt->stack++] = VALUE_TRUE;
}

void wl_push_false(WL_Runtime *rt)
{
    if (rt->state != RUNTIME_SYSVAR &&
        rt->state != RUNTIME_SYSCALL)
        return;

    if (!rt_check_stack(rt, 1))
        return;

    rt->values[rt->stack++] = VALUE_FALSE;
}

void wl_push_s64(WL_Runtime *rt, int64_t x)
{
    if (rt->state != RUNTIME_SYSVAR &&
        rt->state != RUNTIME_SYSCALL)
        return;

    if (!rt_check_stack(rt, 1))
        return;

    Value v = value_from_s64(x, rt->arena, &rt->err);
    if (v == VALUE_ERROR) {
        rt->state = RUNTIME_ERROR;
        return;
    }

    rt->values[rt->stack++] = v;
}

void wl_push_f64(WL_Runtime *rt, double x)
{
    if (rt->state != RUNTIME_SYSVAR &&
        rt->state != RUNTIME_SYSCALL)
        return;

    if (!rt_check_stack(rt, 1))
        return;

    Value v = value_from_f64(x, rt->arena, &rt->err);
    if (v == VALUE_ERROR) {
        rt->state = RUNTIME_ERROR;
        return;
    }

    rt->values[rt->stack++] = v;
}

void wl_push_str(WL_Runtime *rt, WL_String x)
{
    if (rt->state != RUNTIME_SYSVAR &&
        rt->state != RUNTIME_SYSCALL)
        return;

    if (!rt_check_stack(rt, 1))
        return;

    Value v = value_from_str((String) { x.ptr, x.len }, rt->arena, &rt->err);
    if (v == VALUE_ERROR) {
        rt->state = RUNTIME_ERROR;
        return;
    }

    rt->values[rt->stack++] = v;
}

void wl_push_array(WL_Runtime *rt, int cap)
{
    if (rt->state != RUNTIME_SYSVAR &&
        rt->state != RUNTIME_SYSCALL)
        return;

    if (!rt_check_stack(rt, 1))
        return;

    Value v = value_empty_array(cap, rt->arena, &rt->err);
    if (v == VALUE_ERROR) {
        rt->state = RUNTIME_ERROR;
        return;
    }

    rt->values[rt->stack++] = v;
}

void wl_push_map(WL_Runtime *rt, int cap)
{
    if (rt->state != RUNTIME_SYSVAR &&
        rt->state != RUNTIME_SYSCALL)
        return;

    if (!rt_check_stack(rt, 1))
        return;

    Value v = value_empty_map(cap, rt->arena, &rt->err);
    if (v == VALUE_ERROR) {
        rt->state = RUNTIME_ERROR;
        return;
    }

    rt->values[rt->stack++] = v;
}

void wl_push_arg(WL_Runtime *rt, int idx)
{
    if (rt->state != RUNTIME_SYSVAR &&
        rt->state != RUNTIME_SYSCALL)
        return;

    if (!rt_check_stack(rt, 1))
        return;

    int tot = wl_arg_count(rt);
    if (idx < 0 || idx >= tot) {
        REPORT(&rt->err, "Invalid API usagge");
        rt->state = RUNTIME_ERROR;
        return;
    }

    rt->values[rt->stack++] = *rt_variable(rt, tot - idx - 1);
}

void wl_insert(WL_Runtime *rt)
{
    if (rt->state != RUNTIME_SYSVAR &&
        rt->state != RUNTIME_SYSCALL)
        return;

    if (rt->stack - rt->stack_before_user < 3) {
        REPORT(&rt->err, "Invalid API usagge");
        rt->state = RUNTIME_ERROR;
        return;
    }

    Value key = rt->values[--rt->stack];
    Value val = rt->values[--rt->stack];
    Value set = rt->values[rt->stack-1];

    if (!value_insert(set, key, val, rt->arena, &rt->err)) {
        rt->state = RUNTIME_ERROR;
        return;
    }
}

void wl_append(WL_Runtime *rt)
{
    if (rt->state != RUNTIME_SYSVAR &&
        rt->state != RUNTIME_SYSCALL)
        return;

     if (rt->stack - rt->stack_before_user < 2) {
        REPORT(&rt->err, "Invalid API usagge");
        rt->state = RUNTIME_ERROR;
        return;
    }

    Value val = rt->values[--rt->stack];
    Value set = rt->values[rt->stack-1];

    if (!value_append(set, val, rt->arena, &rt->err)) {
        rt->state = RUNTIME_ERROR;
        return;
    }
}

void wl_runtime_dump(WL_Runtime *rt)
{
    for (int i = 0; i < rt->num_frames; i++) {
        printf("=== frame %d ===\n", i);
        
        Frame *frame = &rt->frames[i];

        int num_vars;
        if (i+1 < rt->num_frames)
            num_vars = frame->varbase - rt->frames[i+1].varbase;
        else
            num_vars = frame->varbase - rt->vars;

        for (int j = 0; j < num_vars; j++) {
            printf("  %d = ", j);
            value_print(rt->values[frame->varbase - j]);
        }
    }
    printf("===============\n");
}
#undef Scanner
#undef Token
#undef is_space
#undef is_digit
#undef is_alpha
#undef is_printable
#undef is_hex_digit
#undef hex_digit_to_int
#undef MIN
#undef MAX
#undef ASSERT
#undef SIZEOF

////////////////////////////////////////////////////////////////////////////////////////
// 3p/crypt_blowfish.h
////////////////////////////////////////////////////////////////////////////////////////

#line 1 "3p/crypt_blowfish.h"
/*
 * Written by Solar Designer <solar at openwall.com> in 2000-2011.
 * No copyright is claimed, and the software is hereby placed in the public
 * domain.  In case this attempt to disclaim copyright and place the software
 * in the public domain is deemed null and void, then the software is
 * Copyright (c) 2000-2011 Solar Designer and it is hereby released to the
 * general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 *
 * See crypt_blowfish.c for more information.
 */

#ifndef _CRYPT_BLOWFISH_H
#define _CRYPT_BLOWFISH_H

extern int _crypt_output_magic(const char *setting, char *output, int size);
extern char *_crypt_blowfish_rn(const char *key, const char *setting,
	char *output, int size);
extern char *_crypt_gensalt_blowfish_rn(const char *prefix,
	unsigned long count,
	const char *input, int size, char *output, int output_size);

#endif

////////////////////////////////////////////////////////////////////////////////////////
// 3p/crypt_blowfish.c
////////////////////////////////////////////////////////////////////////////////////////

#line 1 "3p/crypt_blowfish.c"
/*
 * The crypt_blowfish homepage is:
 *
 *	http://www.openwall.com/crypt/
 *
 * This code comes from John the Ripper password cracker, with reentrant
 * and crypt(3) interfaces added, but optimizations specific to password
 * cracking removed.
 *
 * Written by Solar Designer <solar at openwall.com> in 1998-2014.
 * No copyright is claimed, and the software is hereby placed in the public
 * domain.  In case this attempt to disclaim copyright and place the software
 * in the public domain is deemed null and void, then the software is
 * Copyright (c) 1998-2014 Solar Designer and it is hereby released to the
 * general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 *
 * It is my intent that you should be able to use this on your system,
 * as part of a software package, or anywhere else to improve security,
 * ensure compatibility, or for any other purpose.  I would appreciate
 * it if you give credit where it is due and keep your modifications in
 * the public domain as well, but I don't require that in order to let
 * you place this code and any modifications you make under a license
 * of your choice.
 *
 * This implementation is fully compatible with OpenBSD's bcrypt.c for prefix
 * "$2b$", originally by Niels Provos <provos at citi.umich.edu>, and it uses
 * some of his ideas.  The password hashing algorithm was designed by David
 * Mazieres <dm at lcs.mit.edu>.  For information on the level of
 * compatibility for bcrypt hash prefixes other than "$2b$", please refer to
 * the comments in BF_set_key() below and to the included crypt(3) man page.
 *
 * There's a paper on the algorithm that explains its design decisions:
 *
 *	http://www.usenix.org/events/usenix99/provos.html
 *
 * Some of the tricks in BF_ROUND might be inspired by Eric Young's
 * Blowfish library (I can't be sure if I would think of something if I
 * hadn't seen his code).
 */

#include <string.h>

#include <errno.h>
#ifndef __set_errno
#define __set_errno(val) errno = (val)
#endif

#ifndef CRYPT_BLOWFISH_NOINCLUDE
/* Just to make sure the prototypes match the actual definitions */
#include "crypt_blowfish.h"
#endif // CRYPT_BLOWFISH_NOINCLUDE

#ifdef __i386__
#define BF_ASM				1
#define BF_SCALE			1
#elif defined(__x86_64__) || defined(__alpha__) || defined(__hppa__)
#define BF_ASM				0
#define BF_SCALE			1
#else
#define BF_ASM				0
#define BF_SCALE			0
#endif

typedef unsigned int BF_word;
typedef signed int BF_word_signed;

/* Number of Blowfish rounds, this is also hardcoded into a few places */
#define BF_N				16

typedef BF_word BF_key[BF_N + 2];

typedef struct {
	BF_word S[4][0x100];
	BF_key P;
} BF_ctx;

/*
 * Magic IV for 64 Blowfish encryptions that we do at the end.
 * The string is "OrpheanBeholderScryDoubt" on big-endian.
 */
static BF_word BF_magic_w[6] = {
	0x4F727068, 0x65616E42, 0x65686F6C,
	0x64657253, 0x63727944, 0x6F756274
};

/*
 * P-box and S-box tables initialized with digits of Pi.
 */
static BF_ctx BF_init_state = {
	{
		{
			0xd1310ba6, 0x98dfb5ac, 0x2ffd72db, 0xd01adfb7,
			0xb8e1afed, 0x6a267e96, 0xba7c9045, 0xf12c7f99,
			0x24a19947, 0xb3916cf7, 0x0801f2e2, 0x858efc16,
			0x636920d8, 0x71574e69, 0xa458fea3, 0xf4933d7e,
			0x0d95748f, 0x728eb658, 0x718bcd58, 0x82154aee,
			0x7b54a41d, 0xc25a59b5, 0x9c30d539, 0x2af26013,
			0xc5d1b023, 0x286085f0, 0xca417918, 0xb8db38ef,
			0x8e79dcb0, 0x603a180e, 0x6c9e0e8b, 0xb01e8a3e,
			0xd71577c1, 0xbd314b27, 0x78af2fda, 0x55605c60,
			0xe65525f3, 0xaa55ab94, 0x57489862, 0x63e81440,
			0x55ca396a, 0x2aab10b6, 0xb4cc5c34, 0x1141e8ce,
			0xa15486af, 0x7c72e993, 0xb3ee1411, 0x636fbc2a,
			0x2ba9c55d, 0x741831f6, 0xce5c3e16, 0x9b87931e,
			0xafd6ba33, 0x6c24cf5c, 0x7a325381, 0x28958677,
			0x3b8f4898, 0x6b4bb9af, 0xc4bfe81b, 0x66282193,
			0x61d809cc, 0xfb21a991, 0x487cac60, 0x5dec8032,
			0xef845d5d, 0xe98575b1, 0xdc262302, 0xeb651b88,
			0x23893e81, 0xd396acc5, 0x0f6d6ff3, 0x83f44239,
			0x2e0b4482, 0xa4842004, 0x69c8f04a, 0x9e1f9b5e,
			0x21c66842, 0xf6e96c9a, 0x670c9c61, 0xabd388f0,
			0x6a51a0d2, 0xd8542f68, 0x960fa728, 0xab5133a3,
			0x6eef0b6c, 0x137a3be4, 0xba3bf050, 0x7efb2a98,
			0xa1f1651d, 0x39af0176, 0x66ca593e, 0x82430e88,
			0x8cee8619, 0x456f9fb4, 0x7d84a5c3, 0x3b8b5ebe,
			0xe06f75d8, 0x85c12073, 0x401a449f, 0x56c16aa6,
			0x4ed3aa62, 0x363f7706, 0x1bfedf72, 0x429b023d,
			0x37d0d724, 0xd00a1248, 0xdb0fead3, 0x49f1c09b,
			0x075372c9, 0x80991b7b, 0x25d479d8, 0xf6e8def7,
			0xe3fe501a, 0xb6794c3b, 0x976ce0bd, 0x04c006ba,
			0xc1a94fb6, 0x409f60c4, 0x5e5c9ec2, 0x196a2463,
			0x68fb6faf, 0x3e6c53b5, 0x1339b2eb, 0x3b52ec6f,
			0x6dfc511f, 0x9b30952c, 0xcc814544, 0xaf5ebd09,
			0xbee3d004, 0xde334afd, 0x660f2807, 0x192e4bb3,
			0xc0cba857, 0x45c8740f, 0xd20b5f39, 0xb9d3fbdb,
			0x5579c0bd, 0x1a60320a, 0xd6a100c6, 0x402c7279,
			0x679f25fe, 0xfb1fa3cc, 0x8ea5e9f8, 0xdb3222f8,
			0x3c7516df, 0xfd616b15, 0x2f501ec8, 0xad0552ab,
			0x323db5fa, 0xfd238760, 0x53317b48, 0x3e00df82,
			0x9e5c57bb, 0xca6f8ca0, 0x1a87562e, 0xdf1769db,
			0xd542a8f6, 0x287effc3, 0xac6732c6, 0x8c4f5573,
			0x695b27b0, 0xbbca58c8, 0xe1ffa35d, 0xb8f011a0,
			0x10fa3d98, 0xfd2183b8, 0x4afcb56c, 0x2dd1d35b,
			0x9a53e479, 0xb6f84565, 0xd28e49bc, 0x4bfb9790,
			0xe1ddf2da, 0xa4cb7e33, 0x62fb1341, 0xcee4c6e8,
			0xef20cada, 0x36774c01, 0xd07e9efe, 0x2bf11fb4,
			0x95dbda4d, 0xae909198, 0xeaad8e71, 0x6b93d5a0,
			0xd08ed1d0, 0xafc725e0, 0x8e3c5b2f, 0x8e7594b7,
			0x8ff6e2fb, 0xf2122b64, 0x8888b812, 0x900df01c,
			0x4fad5ea0, 0x688fc31c, 0xd1cff191, 0xb3a8c1ad,
			0x2f2f2218, 0xbe0e1777, 0xea752dfe, 0x8b021fa1,
			0xe5a0cc0f, 0xb56f74e8, 0x18acf3d6, 0xce89e299,
			0xb4a84fe0, 0xfd13e0b7, 0x7cc43b81, 0xd2ada8d9,
			0x165fa266, 0x80957705, 0x93cc7314, 0x211a1477,
			0xe6ad2065, 0x77b5fa86, 0xc75442f5, 0xfb9d35cf,
			0xebcdaf0c, 0x7b3e89a0, 0xd6411bd3, 0xae1e7e49,
			0x00250e2d, 0x2071b35e, 0x226800bb, 0x57b8e0af,
			0x2464369b, 0xf009b91e, 0x5563911d, 0x59dfa6aa,
			0x78c14389, 0xd95a537f, 0x207d5ba2, 0x02e5b9c5,
			0x83260376, 0x6295cfa9, 0x11c81968, 0x4e734a41,
			0xb3472dca, 0x7b14a94a, 0x1b510052, 0x9a532915,
			0xd60f573f, 0xbc9bc6e4, 0x2b60a476, 0x81e67400,
			0x08ba6fb5, 0x571be91f, 0xf296ec6b, 0x2a0dd915,
			0xb6636521, 0xe7b9f9b6, 0xff34052e, 0xc5855664,
			0x53b02d5d, 0xa99f8fa1, 0x08ba4799, 0x6e85076a
		}, {
			0x4b7a70e9, 0xb5b32944, 0xdb75092e, 0xc4192623,
			0xad6ea6b0, 0x49a7df7d, 0x9cee60b8, 0x8fedb266,
			0xecaa8c71, 0x699a17ff, 0x5664526c, 0xc2b19ee1,
			0x193602a5, 0x75094c29, 0xa0591340, 0xe4183a3e,
			0x3f54989a, 0x5b429d65, 0x6b8fe4d6, 0x99f73fd6,
			0xa1d29c07, 0xefe830f5, 0x4d2d38e6, 0xf0255dc1,
			0x4cdd2086, 0x8470eb26, 0x6382e9c6, 0x021ecc5e,
			0x09686b3f, 0x3ebaefc9, 0x3c971814, 0x6b6a70a1,
			0x687f3584, 0x52a0e286, 0xb79c5305, 0xaa500737,
			0x3e07841c, 0x7fdeae5c, 0x8e7d44ec, 0x5716f2b8,
			0xb03ada37, 0xf0500c0d, 0xf01c1f04, 0x0200b3ff,
			0xae0cf51a, 0x3cb574b2, 0x25837a58, 0xdc0921bd,
			0xd19113f9, 0x7ca92ff6, 0x94324773, 0x22f54701,
			0x3ae5e581, 0x37c2dadc, 0xc8b57634, 0x9af3dda7,
			0xa9446146, 0x0fd0030e, 0xecc8c73e, 0xa4751e41,
			0xe238cd99, 0x3bea0e2f, 0x3280bba1, 0x183eb331,
			0x4e548b38, 0x4f6db908, 0x6f420d03, 0xf60a04bf,
			0x2cb81290, 0x24977c79, 0x5679b072, 0xbcaf89af,
			0xde9a771f, 0xd9930810, 0xb38bae12, 0xdccf3f2e,
			0x5512721f, 0x2e6b7124, 0x501adde6, 0x9f84cd87,
			0x7a584718, 0x7408da17, 0xbc9f9abc, 0xe94b7d8c,
			0xec7aec3a, 0xdb851dfa, 0x63094366, 0xc464c3d2,
			0xef1c1847, 0x3215d908, 0xdd433b37, 0x24c2ba16,
			0x12a14d43, 0x2a65c451, 0x50940002, 0x133ae4dd,
			0x71dff89e, 0x10314e55, 0x81ac77d6, 0x5f11199b,
			0x043556f1, 0xd7a3c76b, 0x3c11183b, 0x5924a509,
			0xf28fe6ed, 0x97f1fbfa, 0x9ebabf2c, 0x1e153c6e,
			0x86e34570, 0xeae96fb1, 0x860e5e0a, 0x5a3e2ab3,
			0x771fe71c, 0x4e3d06fa, 0x2965dcb9, 0x99e71d0f,
			0x803e89d6, 0x5266c825, 0x2e4cc978, 0x9c10b36a,
			0xc6150eba, 0x94e2ea78, 0xa5fc3c53, 0x1e0a2df4,
			0xf2f74ea7, 0x361d2b3d, 0x1939260f, 0x19c27960,
			0x5223a708, 0xf71312b6, 0xebadfe6e, 0xeac31f66,
			0xe3bc4595, 0xa67bc883, 0xb17f37d1, 0x018cff28,
			0xc332ddef, 0xbe6c5aa5, 0x65582185, 0x68ab9802,
			0xeecea50f, 0xdb2f953b, 0x2aef7dad, 0x5b6e2f84,
			0x1521b628, 0x29076170, 0xecdd4775, 0x619f1510,
			0x13cca830, 0xeb61bd96, 0x0334fe1e, 0xaa0363cf,
			0xb5735c90, 0x4c70a239, 0xd59e9e0b, 0xcbaade14,
			0xeecc86bc, 0x60622ca7, 0x9cab5cab, 0xb2f3846e,
			0x648b1eaf, 0x19bdf0ca, 0xa02369b9, 0x655abb50,
			0x40685a32, 0x3c2ab4b3, 0x319ee9d5, 0xc021b8f7,
			0x9b540b19, 0x875fa099, 0x95f7997e, 0x623d7da8,
			0xf837889a, 0x97e32d77, 0x11ed935f, 0x16681281,
			0x0e358829, 0xc7e61fd6, 0x96dedfa1, 0x7858ba99,
			0x57f584a5, 0x1b227263, 0x9b83c3ff, 0x1ac24696,
			0xcdb30aeb, 0x532e3054, 0x8fd948e4, 0x6dbc3128,
			0x58ebf2ef, 0x34c6ffea, 0xfe28ed61, 0xee7c3c73,
			0x5d4a14d9, 0xe864b7e3, 0x42105d14, 0x203e13e0,
			0x45eee2b6, 0xa3aaabea, 0xdb6c4f15, 0xfacb4fd0,
			0xc742f442, 0xef6abbb5, 0x654f3b1d, 0x41cd2105,
			0xd81e799e, 0x86854dc7, 0xe44b476a, 0x3d816250,
			0xcf62a1f2, 0x5b8d2646, 0xfc8883a0, 0xc1c7b6a3,
			0x7f1524c3, 0x69cb7492, 0x47848a0b, 0x5692b285,
			0x095bbf00, 0xad19489d, 0x1462b174, 0x23820e00,
			0x58428d2a, 0x0c55f5ea, 0x1dadf43e, 0x233f7061,
			0x3372f092, 0x8d937e41, 0xd65fecf1, 0x6c223bdb,
			0x7cde3759, 0xcbee7460, 0x4085f2a7, 0xce77326e,
			0xa6078084, 0x19f8509e, 0xe8efd855, 0x61d99735,
			0xa969a7aa, 0xc50c06c2, 0x5a04abfc, 0x800bcadc,
			0x9e447a2e, 0xc3453484, 0xfdd56705, 0x0e1e9ec9,
			0xdb73dbd3, 0x105588cd, 0x675fda79, 0xe3674340,
			0xc5c43465, 0x713e38d8, 0x3d28f89e, 0xf16dff20,
			0x153e21e7, 0x8fb03d4a, 0xe6e39f2b, 0xdb83adf7
		}, {
			0xe93d5a68, 0x948140f7, 0xf64c261c, 0x94692934,
			0x411520f7, 0x7602d4f7, 0xbcf46b2e, 0xd4a20068,
			0xd4082471, 0x3320f46a, 0x43b7d4b7, 0x500061af,
			0x1e39f62e, 0x97244546, 0x14214f74, 0xbf8b8840,
			0x4d95fc1d, 0x96b591af, 0x70f4ddd3, 0x66a02f45,
			0xbfbc09ec, 0x03bd9785, 0x7fac6dd0, 0x31cb8504,
			0x96eb27b3, 0x55fd3941, 0xda2547e6, 0xabca0a9a,
			0x28507825, 0x530429f4, 0x0a2c86da, 0xe9b66dfb,
			0x68dc1462, 0xd7486900, 0x680ec0a4, 0x27a18dee,
			0x4f3ffea2, 0xe887ad8c, 0xb58ce006, 0x7af4d6b6,
			0xaace1e7c, 0xd3375fec, 0xce78a399, 0x406b2a42,
			0x20fe9e35, 0xd9f385b9, 0xee39d7ab, 0x3b124e8b,
			0x1dc9faf7, 0x4b6d1856, 0x26a36631, 0xeae397b2,
			0x3a6efa74, 0xdd5b4332, 0x6841e7f7, 0xca7820fb,
			0xfb0af54e, 0xd8feb397, 0x454056ac, 0xba489527,
			0x55533a3a, 0x20838d87, 0xfe6ba9b7, 0xd096954b,
			0x55a867bc, 0xa1159a58, 0xcca92963, 0x99e1db33,
			0xa62a4a56, 0x3f3125f9, 0x5ef47e1c, 0x9029317c,
			0xfdf8e802, 0x04272f70, 0x80bb155c, 0x05282ce3,
			0x95c11548, 0xe4c66d22, 0x48c1133f, 0xc70f86dc,
			0x07f9c9ee, 0x41041f0f, 0x404779a4, 0x5d886e17,
			0x325f51eb, 0xd59bc0d1, 0xf2bcc18f, 0x41113564,
			0x257b7834, 0x602a9c60, 0xdff8e8a3, 0x1f636c1b,
			0x0e12b4c2, 0x02e1329e, 0xaf664fd1, 0xcad18115,
			0x6b2395e0, 0x333e92e1, 0x3b240b62, 0xeebeb922,
			0x85b2a20e, 0xe6ba0d99, 0xde720c8c, 0x2da2f728,
			0xd0127845, 0x95b794fd, 0x647d0862, 0xe7ccf5f0,
			0x5449a36f, 0x877d48fa, 0xc39dfd27, 0xf33e8d1e,
			0x0a476341, 0x992eff74, 0x3a6f6eab, 0xf4f8fd37,
			0xa812dc60, 0xa1ebddf8, 0x991be14c, 0xdb6e6b0d,
			0xc67b5510, 0x6d672c37, 0x2765d43b, 0xdcd0e804,
			0xf1290dc7, 0xcc00ffa3, 0xb5390f92, 0x690fed0b,
			0x667b9ffb, 0xcedb7d9c, 0xa091cf0b, 0xd9155ea3,
			0xbb132f88, 0x515bad24, 0x7b9479bf, 0x763bd6eb,
			0x37392eb3, 0xcc115979, 0x8026e297, 0xf42e312d,
			0x6842ada7, 0xc66a2b3b, 0x12754ccc, 0x782ef11c,
			0x6a124237, 0xb79251e7, 0x06a1bbe6, 0x4bfb6350,
			0x1a6b1018, 0x11caedfa, 0x3d25bdd8, 0xe2e1c3c9,
			0x44421659, 0x0a121386, 0xd90cec6e, 0xd5abea2a,
			0x64af674e, 0xda86a85f, 0xbebfe988, 0x64e4c3fe,
			0x9dbc8057, 0xf0f7c086, 0x60787bf8, 0x6003604d,
			0xd1fd8346, 0xf6381fb0, 0x7745ae04, 0xd736fccc,
			0x83426b33, 0xf01eab71, 0xb0804187, 0x3c005e5f,
			0x77a057be, 0xbde8ae24, 0x55464299, 0xbf582e61,
			0x4e58f48f, 0xf2ddfda2, 0xf474ef38, 0x8789bdc2,
			0x5366f9c3, 0xc8b38e74, 0xb475f255, 0x46fcd9b9,
			0x7aeb2661, 0x8b1ddf84, 0x846a0e79, 0x915f95e2,
			0x466e598e, 0x20b45770, 0x8cd55591, 0xc902de4c,
			0xb90bace1, 0xbb8205d0, 0x11a86248, 0x7574a99e,
			0xb77f19b6, 0xe0a9dc09, 0x662d09a1, 0xc4324633,
			0xe85a1f02, 0x09f0be8c, 0x4a99a025, 0x1d6efe10,
			0x1ab93d1d, 0x0ba5a4df, 0xa186f20f, 0x2868f169,
			0xdcb7da83, 0x573906fe, 0xa1e2ce9b, 0x4fcd7f52,
			0x50115e01, 0xa70683fa, 0xa002b5c4, 0x0de6d027,
			0x9af88c27, 0x773f8641, 0xc3604c06, 0x61a806b5,
			0xf0177a28, 0xc0f586e0, 0x006058aa, 0x30dc7d62,
			0x11e69ed7, 0x2338ea63, 0x53c2dd94, 0xc2c21634,
			0xbbcbee56, 0x90bcb6de, 0xebfc7da1, 0xce591d76,
			0x6f05e409, 0x4b7c0188, 0x39720a3d, 0x7c927c24,
			0x86e3725f, 0x724d9db9, 0x1ac15bb4, 0xd39eb8fc,
			0xed545578, 0x08fca5b5, 0xd83d7cd3, 0x4dad0fc4,
			0x1e50ef5e, 0xb161e6f8, 0xa28514d9, 0x6c51133c,
			0x6fd5c7e7, 0x56e14ec4, 0x362abfce, 0xddc6c837,
			0xd79a3234, 0x92638212, 0x670efa8e, 0x406000e0
		}, {
			0x3a39ce37, 0xd3faf5cf, 0xabc27737, 0x5ac52d1b,
			0x5cb0679e, 0x4fa33742, 0xd3822740, 0x99bc9bbe,
			0xd5118e9d, 0xbf0f7315, 0xd62d1c7e, 0xc700c47b,
			0xb78c1b6b, 0x21a19045, 0xb26eb1be, 0x6a366eb4,
			0x5748ab2f, 0xbc946e79, 0xc6a376d2, 0x6549c2c8,
			0x530ff8ee, 0x468dde7d, 0xd5730a1d, 0x4cd04dc6,
			0x2939bbdb, 0xa9ba4650, 0xac9526e8, 0xbe5ee304,
			0xa1fad5f0, 0x6a2d519a, 0x63ef8ce2, 0x9a86ee22,
			0xc089c2b8, 0x43242ef6, 0xa51e03aa, 0x9cf2d0a4,
			0x83c061ba, 0x9be96a4d, 0x8fe51550, 0xba645bd6,
			0x2826a2f9, 0xa73a3ae1, 0x4ba99586, 0xef5562e9,
			0xc72fefd3, 0xf752f7da, 0x3f046f69, 0x77fa0a59,
			0x80e4a915, 0x87b08601, 0x9b09e6ad, 0x3b3ee593,
			0xe990fd5a, 0x9e34d797, 0x2cf0b7d9, 0x022b8b51,
			0x96d5ac3a, 0x017da67d, 0xd1cf3ed6, 0x7c7d2d28,
			0x1f9f25cf, 0xadf2b89b, 0x5ad6b472, 0x5a88f54c,
			0xe029ac71, 0xe019a5e6, 0x47b0acfd, 0xed93fa9b,
			0xe8d3c48d, 0x283b57cc, 0xf8d56629, 0x79132e28,
			0x785f0191, 0xed756055, 0xf7960e44, 0xe3d35e8c,
			0x15056dd4, 0x88f46dba, 0x03a16125, 0x0564f0bd,
			0xc3eb9e15, 0x3c9057a2, 0x97271aec, 0xa93a072a,
			0x1b3f6d9b, 0x1e6321f5, 0xf59c66fb, 0x26dcf319,
			0x7533d928, 0xb155fdf5, 0x03563482, 0x8aba3cbb,
			0x28517711, 0xc20ad9f8, 0xabcc5167, 0xccad925f,
			0x4de81751, 0x3830dc8e, 0x379d5862, 0x9320f991,
			0xea7a90c2, 0xfb3e7bce, 0x5121ce64, 0x774fbe32,
			0xa8b6e37e, 0xc3293d46, 0x48de5369, 0x6413e680,
			0xa2ae0810, 0xdd6db224, 0x69852dfd, 0x09072166,
			0xb39a460a, 0x6445c0dd, 0x586cdecf, 0x1c20c8ae,
			0x5bbef7dd, 0x1b588d40, 0xccd2017f, 0x6bb4e3bb,
			0xdda26a7e, 0x3a59ff45, 0x3e350a44, 0xbcb4cdd5,
			0x72eacea8, 0xfa6484bb, 0x8d6612ae, 0xbf3c6f47,
			0xd29be463, 0x542f5d9e, 0xaec2771b, 0xf64e6370,
			0x740e0d8d, 0xe75b1357, 0xf8721671, 0xaf537d5d,
			0x4040cb08, 0x4eb4e2cc, 0x34d2466a, 0x0115af84,
			0xe1b00428, 0x95983a1d, 0x06b89fb4, 0xce6ea048,
			0x6f3f3b82, 0x3520ab82, 0x011a1d4b, 0x277227f8,
			0x611560b1, 0xe7933fdc, 0xbb3a792b, 0x344525bd,
			0xa08839e1, 0x51ce794b, 0x2f32c9b7, 0xa01fbac9,
			0xe01cc87e, 0xbcc7d1f6, 0xcf0111c3, 0xa1e8aac7,
			0x1a908749, 0xd44fbd9a, 0xd0dadecb, 0xd50ada38,
			0x0339c32a, 0xc6913667, 0x8df9317c, 0xe0b12b4f,
			0xf79e59b7, 0x43f5bb3a, 0xf2d519ff, 0x27d9459c,
			0xbf97222c, 0x15e6fc2a, 0x0f91fc71, 0x9b941525,
			0xfae59361, 0xceb69ceb, 0xc2a86459, 0x12baa8d1,
			0xb6c1075e, 0xe3056a0c, 0x10d25065, 0xcb03a442,
			0xe0ec6e0e, 0x1698db3b, 0x4c98a0be, 0x3278e964,
			0x9f1f9532, 0xe0d392df, 0xd3a0342b, 0x8971f21e,
			0x1b0a7441, 0x4ba3348c, 0xc5be7120, 0xc37632d8,
			0xdf359f8d, 0x9b992f2e, 0xe60b6f47, 0x0fe3f11d,
			0xe54cda54, 0x1edad891, 0xce6279cf, 0xcd3e7e6f,
			0x1618b166, 0xfd2c1d05, 0x848fd2c5, 0xf6fb2299,
			0xf523f357, 0xa6327623, 0x93a83531, 0x56cccd02,
			0xacf08162, 0x5a75ebb5, 0x6e163697, 0x88d273cc,
			0xde966292, 0x81b949d0, 0x4c50901b, 0x71c65614,
			0xe6c6c7bd, 0x327a140a, 0x45e1d006, 0xc3f27b9a,
			0xc9aa53fd, 0x62a80f00, 0xbb25bfe2, 0x35bdd2f6,
			0x71126905, 0xb2040222, 0xb6cbcf7c, 0xcd769c2b,
			0x53113ec0, 0x1640e3d3, 0x38abbd60, 0x2547adf0,
			0xba38209c, 0xf746ce76, 0x77afa1c5, 0x20756060,
			0x85cbfe4e, 0x8ae88dd8, 0x7aaaf9b0, 0x4cf9aa7e,
			0x1948c25c, 0x02fb8a8c, 0x01c36ae4, 0xd6ebe1f9,
			0x90d4f869, 0xa65cdea0, 0x3f09252d, 0xc208e69f,
			0xb74e6132, 0xce77e25b, 0x578fdfe3, 0x3ac372e6
		}
	}, {
		0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344,
		0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
		0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
		0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917,
		0x9216d5d9, 0x8979fb1b
	}
};

static unsigned char BF_itoa64[64 + 1] =
	"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

static unsigned char BF_atoi64[0x60] = {
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 0, 1,
	54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 64, 64, 64, 64, 64,
	64, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
	17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 64, 64, 64, 64, 64,
	64, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
	43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 64, 64, 64, 64, 64
};

#define BF_safe_atoi64(dst, src) \
{ \
	tmp = (unsigned char)(src); \
	if ((unsigned int)(tmp -= 0x20) >= 0x60) return -1; \
	tmp = BF_atoi64[tmp]; \
	if (tmp > 63) return -1; \
	(dst) = tmp; \
}

static int BF_decode(BF_word *dst, const char *src, int size)
{
	unsigned char *dptr = (unsigned char *)dst;
	unsigned char *end = dptr + size;
	const unsigned char *sptr = (const unsigned char *)src;
	unsigned int tmp, c1, c2, c3, c4;

	do {
		BF_safe_atoi64(c1, *sptr++);
		BF_safe_atoi64(c2, *sptr++);
		*dptr++ = (c1 << 2) | ((c2 & 0x30) >> 4);
		if (dptr >= end) break;

		BF_safe_atoi64(c3, *sptr++);
		*dptr++ = ((c2 & 0x0F) << 4) | ((c3 & 0x3C) >> 2);
		if (dptr >= end) break;

		BF_safe_atoi64(c4, *sptr++);
		*dptr++ = ((c3 & 0x03) << 6) | c4;
	} while (dptr < end);

	return 0;
}

static void BF_encode(char *dst, const BF_word *src, int size)
{
	const unsigned char *sptr = (const unsigned char *)src;
	const unsigned char *end = sptr + size;
	unsigned char *dptr = (unsigned char *)dst;
	unsigned int c1, c2;

	do {
		c1 = *sptr++;
		*dptr++ = BF_itoa64[c1 >> 2];
		c1 = (c1 & 0x03) << 4;
		if (sptr >= end) {
			*dptr++ = BF_itoa64[c1];
			break;
		}

		c2 = *sptr++;
		c1 |= c2 >> 4;
		*dptr++ = BF_itoa64[c1];
		c1 = (c2 & 0x0f) << 2;
		if (sptr >= end) {
			*dptr++ = BF_itoa64[c1];
			break;
		}

		c2 = *sptr++;
		c1 |= c2 >> 6;
		*dptr++ = BF_itoa64[c1];
		*dptr++ = BF_itoa64[c2 & 0x3f];
	} while (sptr < end);
}

static void BF_swap(BF_word *x, int count)
{
	static int endianness_check = 1;
	char *is_little_endian = (char *)&endianness_check;
	BF_word tmp;

	if (*is_little_endian)
	do {
		tmp = *x;
		tmp = (tmp << 16) | (tmp >> 16);
		*x++ = ((tmp & 0x00FF00FF) << 8) | ((tmp >> 8) & 0x00FF00FF);
	} while (--count);
}

#if BF_SCALE
/* Architectures which can shift addresses left by 2 bits with no extra cost */
#define BF_ROUND(L, R, N) \
	tmp1 = L & 0xFF; \
	tmp2 = L >> 8; \
	tmp2 &= 0xFF; \
	tmp3 = L >> 16; \
	tmp3 &= 0xFF; \
	tmp4 = L >> 24; \
	tmp1 = data.ctx.S[3][tmp1]; \
	tmp2 = data.ctx.S[2][tmp2]; \
	tmp3 = data.ctx.S[1][tmp3]; \
	tmp3 += data.ctx.S[0][tmp4]; \
	tmp3 ^= tmp2; \
	R ^= data.ctx.P[N + 1]; \
	tmp3 += tmp1; \
	R ^= tmp3;
#else
/* Architectures with no complicated addressing modes supported */
#define BF_INDEX(S, i) \
	(*((BF_word *)(((unsigned char *)S) + (i))))
#define BF_ROUND(L, R, N) \
	tmp1 = L & 0xFF; \
	tmp1 <<= 2; \
	tmp2 = L >> 6; \
	tmp2 &= 0x3FC; \
	tmp3 = L >> 14; \
	tmp3 &= 0x3FC; \
	tmp4 = L >> 22; \
	tmp4 &= 0x3FC; \
	tmp1 = BF_INDEX(data.ctx.S[3], tmp1); \
	tmp2 = BF_INDEX(data.ctx.S[2], tmp2); \
	tmp3 = BF_INDEX(data.ctx.S[1], tmp3); \
	tmp3 += BF_INDEX(data.ctx.S[0], tmp4); \
	tmp3 ^= tmp2; \
	R ^= data.ctx.P[N + 1]; \
	tmp3 += tmp1; \
	R ^= tmp3;
#endif

/*
 * Encrypt one block, BF_N is hardcoded here.
 */
#define BF_ENCRYPT \
	L ^= data.ctx.P[0]; \
	BF_ROUND(L, R, 0); \
	BF_ROUND(R, L, 1); \
	BF_ROUND(L, R, 2); \
	BF_ROUND(R, L, 3); \
	BF_ROUND(L, R, 4); \
	BF_ROUND(R, L, 5); \
	BF_ROUND(L, R, 6); \
	BF_ROUND(R, L, 7); \
	BF_ROUND(L, R, 8); \
	BF_ROUND(R, L, 9); \
	BF_ROUND(L, R, 10); \
	BF_ROUND(R, L, 11); \
	BF_ROUND(L, R, 12); \
	BF_ROUND(R, L, 13); \
	BF_ROUND(L, R, 14); \
	BF_ROUND(R, L, 15); \
	tmp4 = R; \
	R = L; \
	L = tmp4 ^ data.ctx.P[BF_N + 1];

#if BF_ASM
#define BF_body() \
	_BF_body_r(&data.ctx);
#else
#define BF_body() \
	L = R = 0; \
	ptr = data.ctx.P; \
	do { \
		ptr += 2; \
		BF_ENCRYPT; \
		*(ptr - 2) = L; \
		*(ptr - 1) = R; \
	} while (ptr < &data.ctx.P[BF_N + 2]); \
\
	ptr = data.ctx.S[0]; \
	do { \
		ptr += 2; \
		BF_ENCRYPT; \
		*(ptr - 2) = L; \
		*(ptr - 1) = R; \
	} while (ptr < &data.ctx.S[3][0xFF]);
#endif

static void BF_set_key(const char *key, BF_key expanded, BF_key initial,
    unsigned char flags)
{
	const char *ptr = key;
	unsigned int bug, i, j;
	BF_word safety, sign, diff, tmp[2];

/*
 * There was a sign extension bug in older revisions of this function.  While
 * we would have liked to simply fix the bug and move on, we have to provide
 * a backwards compatibility feature (essentially the bug) for some systems and
 * a safety measure for some others.  The latter is needed because for certain
 * multiple inputs to the buggy algorithm there exist easily found inputs to
 * the correct algorithm that produce the same hash.  Thus, we optionally
 * deviate from the correct algorithm just enough to avoid such collisions.
 * While the bug itself affected the majority of passwords containing
 * characters with the 8th bit set (although only a percentage of those in a
 * collision-producing way), the anti-collision safety measure affects
 * only a subset of passwords containing the '\xff' character (not even all of
 * those passwords, just some of them).  This character is not found in valid
 * UTF-8 sequences and is rarely used in popular 8-bit character encodings.
 * Thus, the safety measure is unlikely to cause much annoyance, and is a
 * reasonable tradeoff to use when authenticating against existing hashes that
 * are not reliably known to have been computed with the correct algorithm.
 *
 * We use an approach that tries to minimize side-channel leaks of password
 * information - that is, we mostly use fixed-cost bitwise operations instead
 * of branches or table lookups.  (One conditional branch based on password
 * length remains.  It is not part of the bug aftermath, though, and is
 * difficult and possibly unreasonable to avoid given the use of C strings by
 * the caller, which results in similar timing leaks anyway.)
 *
 * For actual implementation, we set an array index in the variable "bug"
 * (0 means no bug, 1 means sign extension bug emulation) and a flag in the
 * variable "safety" (bit 16 is set when the safety measure is requested).
 * Valid combinations of settings are:
 *
 * Prefix "$2a$": bug = 0, safety = 0x10000
 * Prefix "$2b$": bug = 0, safety = 0
 * Prefix "$2x$": bug = 1, safety = 0
 * Prefix "$2y$": bug = 0, safety = 0
 */
	bug = (unsigned int)flags & 1;
	safety = ((BF_word)flags & 2) << 15;

	sign = diff = 0;

	for (i = 0; i < BF_N + 2; i++) {
		tmp[0] = tmp[1] = 0;
		for (j = 0; j < 4; j++) {
			tmp[0] <<= 8;
			tmp[0] |= (unsigned char)*ptr; /* correct */
			tmp[1] <<= 8;
			tmp[1] |= (BF_word_signed)(signed char)*ptr; /* bug */
/*
 * Sign extension in the first char has no effect - nothing to overwrite yet,
 * and those extra 24 bits will be fully shifted out of the 32-bit word.  For
 * chars 2, 3, 4 in each four-char block, we set bit 7 of "sign" if sign
 * extension in tmp[1] occurs.  Once this flag is set, it remains set.
 */
			if (j)
				sign |= tmp[1] & 0x80;
			if (!*ptr)
				ptr = key;
			else
				ptr++;
		}
		diff |= tmp[0] ^ tmp[1]; /* Non-zero on any differences */

		expanded[i] = tmp[bug];
		initial[i] = BF_init_state.P[i] ^ tmp[bug];
	}

/*
 * At this point, "diff" is zero iff the correct and buggy algorithms produced
 * exactly the same result.  If so and if "sign" is non-zero, which indicates
 * that there was a non-benign sign extension, this means that we have a
 * collision between the correctly computed hash for this password and a set of
 * passwords that could be supplied to the buggy algorithm.  Our safety measure
 * is meant to protect from such many-buggy to one-correct collisions, by
 * deviating from the correct algorithm in such cases.  Let's check for this.
 */
	diff |= diff >> 16; /* still zero iff exact match */
	diff &= 0xffff; /* ditto */
	diff += 0xffff; /* bit 16 set iff "diff" was non-zero (on non-match) */
	sign <<= 9; /* move the non-benign sign extension flag to bit 16 */
	sign &= ~diff & safety; /* action needed? */

/*
 * If we have determined that we need to deviate from the correct algorithm,
 * flip bit 16 in initial expanded key.  (The choice of 16 is arbitrary, but
 * let's stick to it now.  It came out of the approach we used above, and it's
 * not any worse than any other choice we could make.)
 *
 * It is crucial that we don't do the same to the expanded key used in the main
 * Eksblowfish loop.  By doing it to only one of these two, we deviate from a
 * state that could be directly specified by a password to the buggy algorithm
 * (and to the fully correct one as well, but that's a side-effect).
 */
	initial[0] ^= sign;
}

static const unsigned char flags_by_subtype[26] =
	{2, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 4, 0};

static char *BF_crypt(const char *key, const char *setting,
	char *output, int size,
	BF_word min)
{
#if BF_ASM
	extern void _BF_body_r(BF_ctx *ctx);
#endif
	struct {
		BF_ctx ctx;
		BF_key expanded_key;
		union {
			BF_word salt[4];
			BF_word output[6];
		} binary;
	} data;
	BF_word L, R;
	BF_word tmp1, tmp2, tmp3, tmp4;
	BF_word *ptr;
	BF_word count;
	int i;

	if (size < 7 + 22 + 31 + 1) {
		__set_errno(ERANGE);
		return NULL;
	}

	if (setting[0] != '$' ||
	    setting[1] != '2' ||
	    setting[2] < 'a' || setting[2] > 'z' ||
	    !flags_by_subtype[(unsigned int)(unsigned char)setting[2] - 'a'] ||
	    setting[3] != '$' ||
	    setting[4] < '0' || setting[4] > '3' ||
	    setting[5] < '0' || setting[5] > '9' ||
	    (setting[4] == '3' && setting[5] > '1') ||
	    setting[6] != '$') {
		__set_errno(EINVAL);
		return NULL;
	}

	count = (BF_word)1 << ((setting[4] - '0') * 10 + (setting[5] - '0'));
	if (count < min || BF_decode(data.binary.salt, &setting[7], 16)) {
		__set_errno(EINVAL);
		return NULL;
	}
	BF_swap(data.binary.salt, 4);

	BF_set_key(key, data.expanded_key, data.ctx.P,
	    flags_by_subtype[(unsigned int)(unsigned char)setting[2] - 'a']);

	memcpy(data.ctx.S, BF_init_state.S, sizeof(data.ctx.S));

	L = R = 0;
	for (i = 0; i < BF_N + 2; i += 2) {
		L ^= data.binary.salt[i & 2];
		R ^= data.binary.salt[(i & 2) + 1];
		BF_ENCRYPT;
		data.ctx.P[i] = L;
		data.ctx.P[i + 1] = R;
	}

	ptr = data.ctx.S[0];
	do {
		ptr += 4;
		L ^= data.binary.salt[(BF_N + 2) & 3];
		R ^= data.binary.salt[(BF_N + 3) & 3];
		BF_ENCRYPT;
		*(ptr - 4) = L;
		*(ptr - 3) = R;

		L ^= data.binary.salt[(BF_N + 4) & 3];
		R ^= data.binary.salt[(BF_N + 5) & 3];
		BF_ENCRYPT;
		*(ptr - 2) = L;
		*(ptr - 1) = R;
	} while (ptr < &data.ctx.S[3][0xFF]);

	do {
		int done;

		for (i = 0; i < BF_N + 2; i += 2) {
			data.ctx.P[i] ^= data.expanded_key[i];
			data.ctx.P[i + 1] ^= data.expanded_key[i + 1];
		}

		done = 0;
		do {
			BF_body();
			if (done)
				break;
			done = 1;

			tmp1 = data.binary.salt[0];
			tmp2 = data.binary.salt[1];
			tmp3 = data.binary.salt[2];
			tmp4 = data.binary.salt[3];
			for (i = 0; i < BF_N; i += 4) {
				data.ctx.P[i] ^= tmp1;
				data.ctx.P[i + 1] ^= tmp2;
				data.ctx.P[i + 2] ^= tmp3;
				data.ctx.P[i + 3] ^= tmp4;
			}
			data.ctx.P[16] ^= tmp1;
			data.ctx.P[17] ^= tmp2;
		} while (1);
	} while (--count);

	for (i = 0; i < 6; i += 2) {
		L = BF_magic_w[i];
		R = BF_magic_w[i + 1];

		count = 64;
		do {
			BF_ENCRYPT;
		} while (--count);

		data.binary.output[i] = L;
		data.binary.output[i + 1] = R;
	}

	memcpy(output, setting, 7 + 22 - 1);
	output[7 + 22 - 1] = BF_itoa64[(int)
		BF_atoi64[(int)setting[7 + 22 - 1] - 0x20] & 0x30];

/* This has to be bug-compatible with the original implementation, so
 * only encode 23 of the 24 bytes. :-) */
	BF_swap(data.binary.output, 6);
	BF_encode(&output[7 + 22], data.binary.output, 23);
	output[7 + 22 + 31] = '\0';

	return output;
}

int _crypt_output_magic(const char *setting, char *output, int size)
{
	if (size < 3)
		return -1;

	output[0] = '*';
	output[1] = '0';
	output[2] = '\0';

	if (setting[0] == '*' && setting[1] == '0')
		output[1] = '1';

	return 0;
}

/*
 * Please preserve the runtime self-test.  It serves two purposes at once:
 *
 * 1. We really can't afford the risk of producing incompatible hashes e.g.
 * when there's something like gcc bug 26587 again, whereas an application or
 * library integrating this code might not also integrate our external tests or
 * it might not run them after every build.  Even if it does, the miscompile
 * might only occur on the production build, but not on a testing build (such
 * as because of different optimization settings).  It is painful to recover
 * from incorrectly-computed hashes - merely fixing whatever broke is not
 * enough.  Thus, a proactive measure like this self-test is needed.
 *
 * 2. We don't want to leave sensitive data from our actual password hash
 * computation on the stack or in registers.  Previous revisions of the code
 * would do explicit cleanups, but simply running the self-test after hash
 * computation is more reliable.
 *
 * The performance cost of this quick self-test is around 0.6% at the "$2a$08"
 * setting.
 */
char *_crypt_blowfish_rn(const char *key, const char *setting,
	char *output, int size)
{
	const char *test_key = "8b \xd0\xc1\xd2\xcf\xcc\xd8";
	const char *test_setting = "$2a$00$abcdefghijklmnopqrstuu";
	static const char * const test_hashes[2] =
		{"i1D709vfamulimlGcq0qq3UvuUasvEa\0\x55", /* 'a', 'b', 'y' */
		"VUrPmXD6q/nVSSp7pNDhCR9071IfIRe\0\x55"}; /* 'x' */
	const char *test_hash = test_hashes[0];
	char *retval;
	const char *p;
	int save_errno, ok;
	struct {
		char s[7 + 22 + 1];
		char o[7 + 22 + 31 + 1 + 1 + 1];
	} buf;

/* Hash the supplied password */
	_crypt_output_magic(setting, output, size);
	retval = BF_crypt(key, setting, output, size, 16);
	save_errno = errno;

/*
 * Do a quick self-test.  It is important that we make both calls to BF_crypt()
 * from the same scope such that they likely use the same stack locations,
 * which makes the second call overwrite the first call's sensitive data on the
 * stack and makes it more likely that any alignment related issues would be
 * detected by the self-test.
 */
	memcpy(buf.s, test_setting, sizeof(buf.s));
	if (retval) {
		unsigned int flags = flags_by_subtype[
		    (unsigned int)(unsigned char)setting[2] - 'a'];
		test_hash = test_hashes[flags & 1];
		buf.s[2] = setting[2];
	}
	memset(buf.o, 0x55, sizeof(buf.o));
	buf.o[sizeof(buf.o) - 1] = 0;
	p = BF_crypt(test_key, buf.s, buf.o, sizeof(buf.o) - (1 + 1), 1);

	ok = (p == buf.o &&
	    !memcmp(p, buf.s, 7 + 22) &&
	    !memcmp(p + (7 + 22), test_hash, 31 + 1 + 1 + 1));

	{
		const char *k = "\xff\xa3" "34" "\xff\xff\xff\xa3" "345";
		BF_key ae, ai, ye, yi;
		BF_set_key(k, ae, ai, 2); /* $2a$ */
		BF_set_key(k, ye, yi, 4); /* $2y$ */
		ai[0] ^= 0x10000; /* undo the safety (for comparison) */
		ok = ok && ai[0] == 0xdb9c59bc && ye[17] == 0x33343500 &&
		    !memcmp(ae, ye, sizeof(ae)) &&
		    !memcmp(ai, yi, sizeof(ai));
	}

	__set_errno(save_errno);
	if (ok)
		return retval;

/* Should not happen */
	_crypt_output_magic(setting, output, size);
	__set_errno(EINVAL); /* pretend we don't support this hash type */
	return NULL;
}

char *_crypt_gensalt_blowfish_rn(const char *prefix, unsigned long count,
	const char *input, int size, char *output, int output_size)
{
	if (size < 16 || output_size < 7 + 22 + 1 ||
	    (count && (count < 4 || count > 31)) ||
	    prefix[0] != '$' || prefix[1] != '2' ||
	    (prefix[2] != 'a' && prefix[2] != 'b' && prefix[2] != 'y')) {
		if (output_size > 0) output[0] = '\0';
		__set_errno((output_size < 7 + 22 + 1) ? ERANGE : EINVAL);
		return NULL;
	}

	if (!count) count = 5;

	output[0] = '$';
	output[1] = '2';
	output[2] = prefix[2];
	output[3] = '$';
	output[4] = '0' + count / 10;
	output[5] = '0' + count % 10;
	output[6] = '$';

	BF_encode(&output[7], (const BF_word *)input, 16);
	output[7 + 22] = '\0';

	return output;
}

////////////////////////////////////////////////////////////////////////////////////////
// src/main.c
////////////////////////////////////////////////////////////////////////////////////////

#line 1 "src/main.c"
#include <stdio.h>
#include <limits.h>
#include <stdlib.h>

#ifdef __linux__
#include <errno.h>
#include <sys/random.h>
#endif

#ifdef _WIN32
#include <windows.h>
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

    // Login
    SessionStorage *session_storage;

#ifdef CWEB_ENABLE_DATABASE
    sqlite3 *db;
    SQLiteCache *dbcache;
    bool trace_sql;
#endif

#ifdef CWEB_ENABLE_TEMPLATE
    TemplateCache *tpcache;
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
    // TODO
}

static void append_to_output_s64(StaticOutputBuffer *out, int64_t n)
{
    // TODO
}

static void append_to_output_f64(StaticOutputBuffer *out, double n)
{
    // TODO
}

static void append_to_output_ptr(StaticOutputBuffer *out, void *p)
{
    // TODO
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
        case CWEB_VARG_TYPE_D    : append_to_output_u64(out, arg.d);     break;
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

/////////////////////////////////////////////////////////////////
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
    if (pass.len >= (int) sizeof(passzt))
        return -1;
    memcpy(passzt, pass.ptr, pass.len);
    passzt[pass.len] = '\0';

    CWEB_PasswordHash new_hash;
    if (_crypt_blowfish_rn(passzt, hash.data, new_hash.data, sizeof(new_hash.data)) == NULL)
        return -1;

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
        dst[i] = (hex_digit_to_int(high) << 4) | (hex_digit_to_int(low) << 0);
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

    uint64_t key;
    if (sess.len < (int) (2 * sizeof(key)))
        return NULL;
    for (int i = 0; i < (int) sizeof(key); i++) {

        int high = sess.ptr[(i << 1) | 0];
        int low  = sess.ptr[(i << 1) | 1];

        if (!is_hex_digit(sess.ptr[i+0]) ||
            !is_hex_digit(sess.ptr[i+1]))
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
        return false;
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
        int ret = sqlite3_prepare_v2(cache->db, fmt, -1, &stmt, NULL);
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
            case CWEB_VARG_TYPE_SLL : ret = sqlite3_bind_int   (stmt, i+1, arg.sll); break;
            case CWEB_VARG_TYPE_UC  : ret = sqlite3_bind_int   (stmt, i+1, arg.uc);  break;
            case CWEB_VARG_TYPE_US  : ret = sqlite3_bind_int   (stmt, i+1, arg.us);  break;
            case CWEB_VARG_TYPE_UI  : ret = sqlite3_bind_int64 (stmt, i+1, arg.ui);  break;
            case CWEB_VARG_TYPE_UL  : ret = sqlite3_bind_int64 (stmt, i+1, arg.ul);  break;
            case CWEB_VARG_TYPE_ULL : ret = sqlite3_bind_int64 (stmt, i+1, arg.ull); break;
            case CWEB_VARG_TYPE_F   : ret = sqlite3_bind_double(stmt, i+1, arg.f);   break;
            case CWEB_VARG_TYPE_D   : ret = sqlite3_bind_double(stmt, i+1, arg.d);   break;
            case CWEB_VARG_TYPE_B   : ret = sqlite3_bind_int   (stmt, i+1, arg.b);   break;
            case CWEB_VARG_TYPE_STR : ret = sqlite3_bind_text  (stmt, i+1, arg.str.ptr, arg.str.len, NULL); break;
            case CWEB_VARG_TYPE_HASH: ret = sqlite3_bind_text  (stmt, i+1, arg.hash.data, -1, NULL); break;
            default:
            ASSERT(0);  // TODO
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
    if (ret != SQLITE_OK)
        return -1;

    ret = sqlite3_step(stmt);
    if (ret != SQLITE_DONE) {
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
    if (ret != SQLITE_OK)
        return (CWEB_QueryResult) { NULL };

    return (CWEB_QueryResult) { stmt };
#else
    return (CWEB_QueryResult) { NULL };
#endif
}

int cweb_next_query_row_impl(CWEB_QueryResult *res, CWEB_VArgs args)
{
#ifdef CWEB_ENABLE_DATABASE
    if (res->handle == NULL)
        return -1;

    int ret = sqlite3_step(res->handle);

    if (ret == SQLITE_DONE)
        return 0;

    if (ret != SQLITE_ROW) {
        sqlite3_reset(res->handle);
        res->handle = NULL;
        return -1;
    }

    if (sqlite3_column_count(res->handle) != args.len) {
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
                *args.ptr[i].pll = (int) x;
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
                *args.ptr[i].pf = (float) x;
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

            default:
            sqlite3_reset(res->handle);
            res->handle = NULL;
            return -1;
        }
    }

    return 1;
#else
    (void) res;
    (void) args;
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
}

CWEB *cweb_init(CWEB_String addr, uint16_t port)
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

    cweb->server = http_server_init((HTTP_String) { addr.ptr, addr.len }, port);
    if (cweb->server == NULL) {
        session_storage_free(cweb->session_storage);
#ifdef CWEB_ENABLE_TEMPLATE
        template_cache_free(cweb->tpcache);
#endif
        free(cweb->pool);
        free(cweb);
        return NULL;
    }

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

bool cweb_match_endpoint(CWEB_Request *req, CWEB_String str)
{
    return http_streq(req->req->url.path, (HTTP_String) { str.ptr, str.len });
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

/////////////////////////////////////////////////////////////////
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

static void push_sysvar(WL_Runtime *rt, WL_String name, SQLiteCache *dbcache, CWEB_String csrf, int user_id, int resource_id)
{
    (void) dbcache;

    if (wl_streq(name, "login_user_id", -1)) {

        if (user_id < 0)
            wl_push_none(rt);
        else
            wl_push_s64(rt, user_id);

    } else if (wl_streq(name, "resource_id", -1)) {

        if (resource_id < 0)
            wl_push_none(rt);
        else
            wl_push_s64(rt, resource_id);

    } else if (wl_streq(name, "csrf", -1)) {

        if (csrf.len == 0)
            wl_push_none(rt);
        else
            wl_push_str(rt, (WL_String) { csrf.ptr, csrf.len });
    }
}

static void push_syscall(WL_Runtime *rt, WL_String name, SQLiteCache *dbcache)
{
    if (wl_streq(name, "query", -1)) {
        query_routine(rt, dbcache);
        return;
    }
}

static int get_or_create_program(TemplateCache *cache, WL_String path, WL_Arena *arena, WL_Program *program)
{
    if (cache == NULL)
        return -1;

    int i = template_cache_lookup(cache, path);
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

void cweb_respond_template(CWEB_Request *req, int status, CWEB_String template_file, int resource_id)
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
    ret = get_or_create_program(req->cweb->tpcache, (WL_String) { template_file.ptr, template_file.len }, &req->arena, &program);
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
            // wl_runtime_error(rt)
            http_response_builder_undo(req->builder);
            http_response_builder_status(req->builder, 500);
            http_response_builder_done(req->builder);
            return;

            case WL_EVAL_SYSVAR:
            push_sysvar(rt, result.str, req->cweb->dbcache, req->csrf, req->user_id, resource_id);
            break;

            case WL_EVAL_SYSCALL:
            push_syscall(rt, result.str, req->cweb->dbcache);
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
#endif // CWEB_IMPLEMENTATION
