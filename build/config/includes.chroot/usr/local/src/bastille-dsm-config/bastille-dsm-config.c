/*
 * bastille-dsm-config — setuid helper for DSM configuration.
 *
 * This binary is owned root:root and setuid. It is NOT sudo — it only
 * performs the three specific privileged operations DSM needs:
 *
 *   enable  <argon2id-hash>   write hash to /etc/thl/dsm.pin, touch dsm.enabled
 *   disable                   shred dsm.pin, remove dsm.enabled
 *   status                    print "enabled" or "disabled", exit 0
 *
 * The caller (bastille-settings GTK app) hashes the PIN in userspace
 * using libsodium before passing the hash here. This binary never sees
 * the raw PIN.
 *
 * Security:
 *   - Drops all supplementary groups immediately on entry.
 *   - Hash argument is validated: must start with "$argon2id$".
 *   - No shell, no execve of anything, no environment used.
 *   - Written to be auditable in < 100 lines.
 *
 * Build:
 *   gcc -O2 -Wall -Wextra -o bastille-dsm-config bastille-dsm-config.c
 *   chown root:root bastille-dsm-config
 *   chmod 4750 bastille-dsm-config   (setuid, group bastille-admin)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <grp.h>
#include <errno.h>

#define DSM_PIN_FILE     "/etc/thl/dsm.pin"
#define DSM_ENABLED_FILE "/etc/thl/dsm.enabled"
#define MAX_HASH_LEN     256

static void shred_file(const char *path)
{
    int fd = open(path, O_WRONLY);
    if (fd < 0) return;
    struct stat st;
    if (fstat(fd, &st) == 0) {
        char buf[512];
        memset(buf, 0, sizeof(buf));
        for (off_t i = 0; i < st.st_size; i += sizeof(buf))
            (void)write(fd, buf, sizeof(buf));
        fsync(fd);
    }
    close(fd);
    unlink(path);
}

static void drop_privileges(void)
{
    /* Drop supplementary groups; keep euid=root for file writes */
    setgroups(0, NULL);
}

static int do_enable(const char *hash)
{
    /* Validate: argon2id hashes start with $argon2id$ */
    if (strncmp(hash, "$argon2id$", 10) != 0) {
        fprintf(stderr, "bastille-dsm-config: invalid hash format\n");
        return 1;
    }
    if (strlen(hash) > MAX_HASH_LEN - 1) {
        fprintf(stderr, "bastille-dsm-config: hash too long\n");
        return 1;
    }

    /* Write hash */
    int fd = open(DSM_PIN_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) { perror(DSM_PIN_FILE); return 1; }
    dprintf(fd, "%s\n", hash);
    fsync(fd);
    close(fd);
    chown(DSM_PIN_FILE, 0, 0);

    /* Touch enabled flag */
    fd = open(DSM_ENABLED_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) { perror(DSM_ENABLED_FILE); return 1; }
    close(fd);
    chown(DSM_ENABLED_FILE, 0, 0);

    return 0;
}

static int do_disable(void)
{
    shred_file(DSM_PIN_FILE);
    unlink(DSM_ENABLED_FILE);
    return 0;
}

static int do_status(void)
{
    if (access(DSM_ENABLED_FILE, F_OK) == 0 &&
        access(DSM_PIN_FILE,     F_OK) == 0) {
        puts("enabled");
    } else {
        puts("disabled");
    }
    return 0;
}

int main(int argc, char *argv[])
{
    drop_privileges();

    if (argc < 2) {
        fprintf(stderr, "Usage: bastille-dsm-config {enable <hash>|disable|status}\n");
        return 1;
    }

    if (strcmp(argv[1], "enable") == 0) {
        if (argc < 3) {
            fprintf(stderr, "bastille-dsm-config enable: hash required\n");
            return 1;
        }
        return do_enable(argv[2]);
    } else if (strcmp(argv[1], "disable") == 0) {
        return do_disable();
    } else if (strcmp(argv[1], "status") == 0) {
        return do_status();
    }

    fprintf(stderr, "bastille-dsm-config: unknown command '%s'\n", argv[1]);
    return 1;
}
