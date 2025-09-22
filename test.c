// Helper macros
#define __CWEB_HELPER_DISPATCH_N(_0, _1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13, _14, _15, _16, N, ...) N
#define __CWEB_HELPER_CONCAT_0(A, B) A ## B
#define __CWEB_HELPER_CONCAT_1(A, B) __CWEB_HELPER_CONCAT_0(A, B)
#define __CWEB_HELPER_ARG(a) (a)
#define __CWEB_HELPER_ARGS_0()                       (CWEB_VArgs) { 0 }
#define __CWEB_HELPER_ARGS_1(a)                      (CWEB_VArgs) { 1, __CWEB_HELPER_ARG(a) }
#define __CWEB_HELPER_ARGS_2(a, b)                   (CWEB_VArgs) { 2, __CWEB_HELPER_ARG(a), __CWEB_HELPER_ARG(b) }
#define __CWEB_HELPER_ARGS_3(a, b, c)                (CWEB_VArgs) { 3, __CWEB_HELPER_ARG(a), __CWEB_HELPER_ARG(b), __CWEB_HELPER_ARG(c) }
#define __CWEB_HELPER_ARGS_4(a, b, c, d)             (CWEB_VArgs) { 4, __CWEB_HELPER_ARG(a), __CWEB_HELPER_ARG(b), __CWEB_HELPER_ARG(c), __CWEB_HELPER_ARG(d) }
#define __CWEB_HELPER_ARGS_5(a, b, c, d, e)          (CWEB_VArgs) { 5, __CWEB_HELPER_ARG(a), __CWEB_HELPER_ARG(b), __CWEB_HELPER_ARG(c), __CWEB_HELPER_ARG(d), __CWEB_HELPER_ARG(e) }
#define __CWEB_HELPER_ARGS_6(a, b, c, d, e, f)       (CWEB_VArgs) { 6, __CWEB_HELPER_ARG(a), __CWEB_HELPER_ARG(b), __CWEB_HELPER_ARG(c), __CWEB_HELPER_ARG(d), __CWEB_HELPER_ARG(e), __CWEB_HELPER_ARG(f) }
#define __CWEB_HELPER_ARGS_7(a, b, c, d, e, f, g)    (CWEB_VArgs) { 7, __CWEB_HELPER_ARG(a), __CWEB_HELPER_ARG(b), __CWEB_HELPER_ARG(c), __CWEB_HELPER_ARG(d), __CWEB_HELPER_ARG(e), __CWEB_HELPER_ARG(f), __CWEB_HELPER_ARG(g) }
#define __CWEB_HELPER_ARGS_8(a, b, c, d, e, f, g, h) (CWEB_VArgs) { 8, __CWEB_HELPER_ARG(a), __CWEB_HELPER_ARG(b), __CWEB_HELPER_ARG(c), __CWEB_HELPER_ARG(d), __CWEB_HELPER_ARG(e), __CWEB_HELPER_ARG(f), __CWEB_HELPER_ARG(g), __CWEB_HELPER_ARG(h) }
#define __CWEB_COUNT_ARGS(...) __CWEB_HELPER_DISPATCH_N(DUMMY, ##__VA_ARGS__, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)

#define CWEB_ARGS(...) __CWEB_HELPER_CONCAT_1(__CWEB_HELPER_ARGS_, __CWEB_COUNT_ARGS(__VA_ARGS__))(__VA_ARGS__)

CWEB_ARGS()
CWEB_ARGS(1)
CWEB_ARGS(1, 2)
CWEB_ARGS(1, 2, 3)
