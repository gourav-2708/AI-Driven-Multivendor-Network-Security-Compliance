/**
 * @file compiler.h
 * @brief Portable wrappers for compiler-specific annotations.
 */
#ifndef NETAUDIT_COMPILER_H
#define NETAUDIT_COMPILER_H

#if defined(__GNUC__)
   /* MinGW's printf attribute defaults to the MSVCRT dialect; ask for the
    * C99 one so %zu and friends are checked correctly everywhere. */
#  if defined(__MINGW32__)
#    define NA_PRINTF(fmt_idx, args_idx) \
         __attribute__((format(gnu_printf, fmt_idx, args_idx)))
#  else
#    define NA_PRINTF(fmt_idx, args_idx) \
         __attribute__((format(printf, fmt_idx, args_idx)))
#  endif
#else
#  define NA_PRINTF(fmt_idx, args_idx)
#endif

#define NA_ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))

#endif /* NETAUDIT_COMPILER_H */
