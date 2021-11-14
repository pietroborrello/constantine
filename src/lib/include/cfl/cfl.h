#ifndef _CFL_H
#define _CFL_H

#define CFL_FUNC __attribute__((section("cfl_code")))
#define CFL_VAR  __attribute__((section("cfl_data")))
#define CFL_TAKEN_VAR CFL_VAR
#define CFL_CONSTRUCTOR __attribute__((constructor))
#define CFL_FUNC_INLINE CFL_FUNC __attribute__((always_inline))
#define CFL_FUNC_NOINLINE CFL_FUNC __attribute__((noinline))
#define CFL_UNUSED(x) (void)(x)

#define CFL_EXPAND_INTRINSCS 0
#define CFL_CT               1

#endif /* _CFL_H */
