#ifndef _DFL_H
#define _DFL_H

#define DFL_FUNC __attribute__((section("dfl_code")))
#define DFL_VAR  __attribute__((section("dfl_data")))
#define DFL_TAKEN_VAR DFL_VAR __thread volatile
#define DFL_CONSTRUCTOR __attribute__((constructor))
#define DFL_FUNC_INLINE DFL_FUNC __attribute__((always_inline))
#define DFL_FUNC_NOINLINE DFL_FUNC __attribute__((noinline))
#define DFL_UNUSED(x) (void)(x)

#define DFL_EXPAND_INTRINSCS 0
#define DFL_CT               1

#endif /* _DFL_H */
