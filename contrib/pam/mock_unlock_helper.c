/*
 * mock_unlock_helper.c — Stands in for rosec-pam-unlock during tests.
 *
 * Reads the password from stdin (NUL-terminated, matching pam_exec
 * protocol) and writes it to the file specified in the MOCK_OUTPUT_FILE
 * environment variable.  Exits 0 on success, 1 on failure.
 *
 * This lets the test harness verify that:
 *   1. pam_rosec correctly forks the helper
 *   2. The password arrives on stdin intact
 *   3. The NUL terminator is present
 *
 * Build:
 *   cc -O2 -Wall -o mock_unlock_helper mock_unlock_helper.c
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void)
{
    const char *closed_fd = getenv("MOCK_CLOSED_FD");
    if (closed_fd &&
        (fcntl(atoi(closed_fd), F_GETFD) != -1 || errno != EBADF))
        return 1;

    char buf[4096];
    ssize_t total = 0;
    ssize_t n;

    /* Read all of stdin */
    while ((n = read(STDIN_FILENO, buf + total, sizeof(buf) - (size_t)total - 1)) > 0)
        total += n;

    if (total <= 0)
        return 1;

    /* Strip trailing NUL if present (pam_rosec sends NUL-terminated) */
    if (total > 0 && buf[total - 1] == '\0')
        total--;

    buf[total] = '\0';

    /* Write to the output file specified by env var */
    const char *outfile = getenv("MOCK_OUTPUT_FILE");
    if (!outfile || !outfile[0])
        return 1;

    FILE *fp = fopen(outfile, "w");
    if (!fp)
        return 1;

    fprintf(fp, "%s", buf);
    fclose(fp);

    /* Zeroize buffer */
    memset(buf, 0, sizeof(buf));

    return 0;
}
