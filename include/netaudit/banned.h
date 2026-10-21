/**
 * @file banned.h
 * @brief Compile-time ban on unsafe libc functions and on heap allocation.
 *
 * Every standard header the project uses is included here first, so the
 * declarations are already seen; any later *use* of a poisoned identifier
 * in project code is a hard compile error under GCC and Clang.
 *
 * Rule for .c files: include system/platform headers before any netaudit
 * header (netaudit headers pull this file in via safe_str.h).
 *
 * Banned and why:
 *   strcpy strcat sprintf vsprintf gets   unbounded writes
 *   scanf sscanf fscanf                   %s without width overflows; use
 *                                         the tokenizer instead
 *   atoi atol atof                        undefined behaviour on overflow;
 *                                         use str_to_int()
 *   strtok                                hidden global state
 *   malloc calloc realloc free            fixed-size model, no heap
 */
#ifndef NETAUDIT_BANNED_H
#define NETAUDIT_BANNED_H

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__GNUC__) && !defined(NETAUDIT_NO_POISON)
#  pragma GCC poison strcpy strcat sprintf vsprintf gets
#  pragma GCC poison scanf sscanf fscanf
#  pragma GCC poison atoi atol atof strtok
#  pragma GCC poison malloc calloc realloc free
#endif

#endif /* NETAUDIT_BANNED_H */
