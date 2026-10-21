/**
 * @file platform.c
 * @brief POSIX / Win32 implementations of platform.h.
 *
 * OS headers come first: netaudit headers poison identifiers (e.g. free)
 * that system headers may mention.
 */
#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#  define _POSIX_C_SOURCE 200809L    /* fileno, isatty, stat under -std=c11 */
#endif

#ifdef _WIN32
   /* -std=c11 defines __STRICT_ANSI__, which makes MinGW hide _fileno and
    * friends. This file is the one place that needs the CRT extensions. */
#  undef __STRICT_ANSI__
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#  include <fcntl.h>
#  include <io.h>
#else
#  include <dirent.h>
#  include <sys/stat.h>
#  include <unistd.h>
#endif

#include "netaudit/platform.h"
#include "netaudit/log.h"
#include "netaudit/safe_str.h"

static bool has_config_extension(const char *name)
{
    return str_ends_with_ci(name, ".cfg") || str_ends_with_ci(name, ".conf") ||
           str_ends_with_ci(name, ".txt");
}

static int cmp_paths(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

static AuditStatus add_path(const char *dir, const char *name,
                            char paths[][NA_MAX_PATH], int *count, int max)
{
    if (*count >= max) return AUDIT_ERR_LIMIT;
#ifdef _WIN32
    const char *sep = "\\";
#else
    const char *sep = "/";
#endif
    size_t dl = strlen(dir);
    if (dl > 0 && (dir[dl - 1] == '/' || dir[dl - 1] == '\\')) sep = "";
    if (!safe_snprintf(paths[*count], NA_MAX_PATH, "%s%s%s", dir, sep, name)) {
        LOG_WRN("path too long, skipped: %s%s%s", dir, sep, name);
        return AUDIT_OK;
    }
    (*count)++;
    return AUDIT_OK;
}

AuditStatus platform_list_configs(const char *dir, char paths[][NA_MAX_PATH],
                                  int *count, int max)
{
    if (!dir || !paths || !count) return AUDIT_ERR_ARG;
    int first = *count;
    AuditStatus rc = AUDIT_OK;

#ifdef _WIN32
    char pattern[NA_MAX_PATH];
    if (!safe_snprintf(pattern, sizeof(pattern), "%s\\*", dir)) return AUDIT_ERR_ARG;
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return AUDIT_ERR_IO;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        if (!has_config_extension(fd.cFileName)) continue;
        rc = add_path(dir, fd.cFileName, paths, count, max);
    } while (rc == AUDIT_OK && FindNextFileA(h, &fd));
    FindClose(h);
#else
    DIR *dp = opendir(dir);
    if (!dp) return AUDIT_ERR_IO;
    struct dirent *de;
    while (rc == AUDIT_OK && (de = readdir(dp)) != NULL) {
        if (!has_config_extension(de->d_name)) continue;
        char full[NA_MAX_PATH];
        struct stat sb;
        if (safe_snprintf(full, sizeof(full), "%s/%s", dir, de->d_name) &&
            stat(full, &sb) == 0 && !S_ISREG(sb.st_mode))
            continue;
        rc = add_path(dir, de->d_name, paths, count, max);
    }
    closedir(dp);
#endif

    /* Directory order is filesystem-dependent; sort for reproducible runs. */
    qsort(paths[first], (size_t)(*count - first), sizeof(paths[0]), cmp_paths);
    return rc;
}

bool platform_is_tty(FILE *fp)
{
#ifdef _WIN32
    return fp && _isatty(_fileno(fp));
#else
    return fp && isatty(fileno(fp));
#endif
}

void platform_enable_ansi(FILE *fp)
{
#ifdef _WIN32
#  ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#    define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#  endif
    HANDLE h = (HANDLE)_get_osfhandle(_fileno(fp));
    DWORD mode = 0;
    if (h != INVALID_HANDLE_VALUE && GetConsoleMode(h, &mode))
        SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
#else
    (void)fp;
#endif
}

void platform_set_binary(FILE *fp)
{
#ifdef _WIN32
    if (fp) _setmode(_fileno(fp), _O_BINARY);
#else
    (void)fp;
#endif
}
