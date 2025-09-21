#ifndef CWEB_AMALGAMATION
#define CWEB_AMALGAMATION

// This file was generated automatically. Do not modify directly!

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
// src/main.h
////////////////////////////////////////////////////////////////////////////////////////

#line 1 "src/main.h"

#define CWEB_STR(X) (CWEB_String) { (X), SIZEOF(X)-1 }

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
#endif // CWEB_AMALGAMATION
