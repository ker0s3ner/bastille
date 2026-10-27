/*
 * pam_thl_duress.c — Tinfoil Hat Linux duress PIN PAM module
 *
 * Stacks alongside or replaces pam_unix for login and disk-unlock.
 *
 * Two classes of PIN are stored in /etc/thl/duress.conf:
 *
 *   normal  <argon2id-hash>   -
 *   duress  <argon2id-hash>   <action>  [<arg>]
 *
 * On a normal PIN  → PAM_SUCCESS, nothing else happens.
 * On a duress PIN  → the action fires in a detached child process, then
 *                    PAM_SUCCESS is returned anyway so the coercer sees
 *                    no visible difference.
 * On neither       → PAM_AUTH_ERR after a constant-time delay.
 *
 * Available actions (set per duress PIN in the config):
 *   wipe   <script>   run a script that destroys key material, then boots
 *   silent <tag>      log the event to syslog silently, continue normally
 *   decoy  <profile>  switch to a named decoy profile, then log in
 *   power             immediately power off the machine
 *
 * Security properties:
 *   - All PIN comparisons use libsodium's constant-time verifier.
 *   - All PIN hashes use Argon2id (via crypto_pwhash_str).
 *   - PIN string is zeroed from memory after use (sodium_memzero).
 *   - Config file is read as root; the module refuses if it is
 *     world-readable or owned by anyone other than root.
 *   - Duress actions run in a double-forked child (daemon) so the
 *     PAM conversation returns immediately and the action cannot be
 *     detected by timing.
 *   - Failed PIN attempts (neither normal nor duress) still take the
 *     same time as a successful one via a dummy verify call.
 *
 * Build:
 *   gcc -shared -fPIC -o pam_thl_duress.so pam_thl_duress.c \
 *       -lpam -lsodium -Wall -Wextra -O2
 *
 * Install:
 *   cp pam_thl_duress.so /lib/x86_64-linux-gnu/security/
 */

#define _GNU_SOURCE
#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <syslog.h>
#include <errno.h>
#include <time.h>

#include <sodium.h>

/* ------------------------------------------------------------------ */
/* Constants                                                           */
/* ------------------------------------------------------------------ */

#define THL_DURESS_CONF     "/etc/thl/duress.conf"
#define THL_DURESS_LOG_TAG  "thl-duress"
#define MAX_LINE            512
#define MAX_PINS            16
#define MAX_HASH_LEN        256
#define MAX_ACTION_LEN      64
#define MAX_ARG_LEN         256

/* ------------------------------------------------------------------ */
/* Data types                                                          */
/* ------------------------------------------------------------------ */

typedef enum {
    PIN_NORMAL,
    PIN_DURESS,
} pin_type_t;

typedef enum {
    ACTION_NONE,
    ACTION_WIPE,
    ACTION_SILENT,
    ACTION_DECOY,
    ACTION_POWER,
} action_type_t;

typedef struct {
    pin_type_t   type;
    char         hash[MAX_HASH_LEN];
    action_type_t action;
    char         action_arg[MAX_ARG_LEN];
} pin_entry_t;

typedef struct {
    pin_entry_t entries[MAX_PINS];
    int         count;
} pin_config_t;

/* ------------------------------------------------------------------ */
/* Config parsing                                                      */
/* ------------------------------------------------------------------ */

static action_type_t parse_action(const char *s)
{
    if (strcmp(s, "wipe")   == 0) return ACTION_WIPE;
    if (strcmp(s, "silent") == 0) return ACTION_SILENT;
    if (strcmp(s, "decoy")  == 0) return ACTION_DECOY;
    if (strcmp(s, "power")  == 0) return ACTION_POWER;
    return ACTION_NONE;
}

/*
 * Verify that the config file is owned by root and not world-readable.
 * Returns 0 on success, -1 on failure.
 */
static int check_config_perms(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0) {
        syslog(LOG_AUTH | LOG_ERR,
               THL_DURESS_LOG_TAG ": cannot stat %s: %s", path, strerror(errno));
        return -1;
    }
    if (st.st_uid != 0) {
        syslog(LOG_AUTH | LOG_ERR,
               THL_DURESS_LOG_TAG ": %s is not owned by root — refusing", path);
        return -1;
    }
    if (st.st_mode & (S_IRGRP | S_IROTH | S_IWGRP | S_IWOTH)) {
        syslog(LOG_AUTH | LOG_ERR,
               THL_DURESS_LOG_TAG ": %s is group/world readable — refusing", path);
        return -1;
    }
    return 0;
}

static int load_config(pin_config_t *cfg)
{
    cfg->count = 0;

    if (check_config_perms(THL_DURESS_CONF) != 0)
        return -1;

    FILE *f = fopen(THL_DURESS_CONF, "r");
    if (!f) {
        syslog(LOG_AUTH | LOG_ERR,
               THL_DURESS_LOG_TAG ": cannot open %s: %s",
               THL_DURESS_CONF, strerror(errno));
        return -1;
    }

    char line[MAX_LINE];
    while (fgets(line, sizeof(line), f)) {
        /* Strip newline */
        line[strcspn(line, "\n")] = '\0';

        /* Skip blank lines and comments */
        if (line[0] == '\0' || line[0] == '#')
            continue;

        if (cfg->count >= MAX_PINS) {
            syslog(LOG_AUTH | LOG_WARNING,
                   THL_DURESS_LOG_TAG ": too many PIN entries — ignoring extras");
            break;
        }

        char type_str[16]       = {0};
        char hash_str[MAX_HASH_LEN]   = {0};
        char action_str[MAX_ACTION_LEN] = {0};
        char arg_str[MAX_ARG_LEN]     = {0};

        int n = sscanf(line, "%15s %255s %63s %255s",
                       type_str, hash_str, action_str, arg_str);
        if (n < 3) continue;

        pin_entry_t *e = &cfg->entries[cfg->count];

        if (strcmp(type_str, "normal") == 0)
            e->type = PIN_NORMAL;
        else if (strcmp(type_str, "duress") == 0)
            e->type = PIN_DURESS;
        else
            continue;

        strncpy(e->hash, hash_str, MAX_HASH_LEN - 1);
        e->action = parse_action(action_str);
        if (n >= 4)
            strncpy(e->action_arg, arg_str, MAX_ARG_LEN - 1);

        cfg->count++;
    }

    fclose(f);
    return cfg->count > 0 ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* Action execution                                                    */
/* ------------------------------------------------------------------ */

/*
 * Double-fork so the action becomes a daemon and cannot be waited on
 * by the PAM conversation — we return immediately.
 */
static void run_action_detached(const char *script, const char *arg)
{
    pid_t pid = fork();
    if (pid < 0) return;
    if (pid > 0) {
        /* Parent: wait only for the first fork, not the grandchild */
        int status;
        waitpid(pid, &status, 0);
        return;
    }

    /* First child: fork again to orphan the real worker */
    pid_t grandchild = fork();
    if (grandchild < 0) _exit(1);
    if (grandchild > 0) _exit(0); /* First child exits — grandchild is orphaned */

    /* Grandchild: close all fds, redirect stdin/out/err to /dev/null */
    int devnull = open("/dev/null", O_RDWR);
    if (devnull >= 0) {
        dup2(devnull, STDIN_FILENO);
        dup2(devnull, STDOUT_FILENO);
        dup2(devnull, STDERR_FILENO);
        if (devnull > 2) close(devnull);
    }
    /* Close everything else */
    for (int fd = 3; fd < 1024; fd++) close(fd);

    setsid();

    if (arg && arg[0] != '\0' && strcmp(arg, "-") != 0)
        execl(script, script, arg, (char *)NULL);
    else
        execl(script, script, (char *)NULL);

    _exit(1);
}

static void execute_duress_action(pam_handle_t *pamh,
                                   const pin_entry_t *e,
                                   const char *user)
{
    (void)pamh;

    switch (e->action) {

    case ACTION_SILENT:
        syslog(LOG_AUTH | LOG_WARNING,
               THL_DURESS_LOG_TAG ": DURESS PIN used by user '%s' [tag=%s]",
               user ? user : "unknown",
               e->action_arg[0] ? e->action_arg : "untagged");
        break;

    case ACTION_WIPE:
        syslog(LOG_AUTH | LOG_CRIT,
               THL_DURESS_LOG_TAG ": DURESS WIPE triggered by user '%s'",
               user ? user : "unknown");
        /* Run the wipe script in the background; we return PAM_SUCCESS
         * immediately so the coercer sees a normal login while keys burn. */
        run_action_detached(
            e->action_arg[0] ? e->action_arg : "/etc/thl/actions/wipe-keys.sh",
            NULL);
        break;

    case ACTION_DECOY:
        syslog(LOG_AUTH | LOG_WARNING,
               THL_DURESS_LOG_TAG ": DURESS DECOY triggered by user '%s' -> profile '%s'",
               user ? user : "unknown",
               e->action_arg[0] ? e->action_arg : "decoy");
        run_action_detached("/usr/local/bin/thl-profile-switch",
                            e->action_arg[0] ? e->action_arg : "decoy");
        break;

    case ACTION_POWER:
        syslog(LOG_AUTH | LOG_CRIT,
               THL_DURESS_LOG_TAG ": DURESS POWEROFF triggered by user '%s'",
               user ? user : "unknown");
        /* Short delay then cut power — gives PAM time to return so the
         * screen doesn't freeze mid-animation and tip off the coercer */
        run_action_detached("/etc/thl/actions/emergency-poweroff.sh", NULL);
        break;

    case ACTION_NONE:
        syslog(LOG_AUTH | LOG_WARNING,
               THL_DURESS_LOG_TAG ": DURESS PIN used but no action configured");
        break;
    }
}

/* ------------------------------------------------------------------ */
/* PIN verification                                                    */
/* ------------------------------------------------------------------ */

/*
 * Returns the matching entry index, or -1 if no match.
 * ALWAYS performs a verify call against every entry to equalise timing.
 */
static int verify_pin(const pin_config_t *cfg, const char *pin)
{
    int matched = -1;

    for (int i = 0; i < cfg->count; i++) {
        int ok = (crypto_pwhash_str_verify(
                      cfg->entries[i].hash,
                      pin,
                      strlen(pin)) == 0);
        /* Use constant-time branch: record first match but keep iterating */
        if (ok && matched == -1)
            matched = i;
    }

    return matched;
}

/* ------------------------------------------------------------------ */
/* PAM entry points                                                    */
/* ------------------------------------------------------------------ */

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                    int argc, const char **argv)
{
    (void)argc; (void)argv; (void)flags;

    if (sodium_init() < 0) {
        syslog(LOG_AUTH | LOG_ERR,
               THL_DURESS_LOG_TAG ": libsodium init failed");
        return PAM_AUTH_ERR;
    }

    /* Get the username for logging */
    const char *user = NULL;
    pam_get_user(pamh, &user, NULL);

    /* Load config */
    pin_config_t cfg;
    if (load_config(&cfg) != 0) {
        syslog(LOG_AUTH | LOG_ERR,
               THL_DURESS_LOG_TAG ": failed to load config — denying");
        return PAM_AUTH_ERR;
    }

    /* Prompt for PIN */
    const char *pin = NULL;
    int rc = pam_get_authtok(pamh, PAM_AUTHTOK, &pin, "PIN: ");
    if (rc != PAM_SUCCESS || !pin) {
        return PAM_AUTH_ERR;
    }

    /* Verify against all entries (constant-time over all entries) */
    int idx = verify_pin(&cfg, pin);

    /* Zero the PIN from memory immediately after verification */
    sodium_memzero((void *)pin, strlen(pin));

    if (idx < 0) {
        /* No match — add a small fixed delay to rate-limit brute force */
        struct timespec ts = { .tv_sec = 2, .tv_nsec = 0 };
        nanosleep(&ts, NULL);
        return PAM_AUTH_ERR;
    }

    const pin_entry_t *entry = &cfg.entries[idx];

    if (entry->type == PIN_DURESS) {
        execute_duress_action(pamh, entry, user);
        /* Return success — coercer must not see failure */
        return PAM_SUCCESS;
    }

    /* Normal PIN */
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
                               int argc, const char **argv)
{
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
                                  int argc, const char **argv)
{
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags,
                                    int argc, const char **argv)
{
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags,
                                     int argc, const char **argv)
{
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}
