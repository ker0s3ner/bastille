/*
 * thl-duress-setup — interactive tool to configure duress PINs
 *
 * Writes /etc/thl/duress.conf with Argon2id hashes.
 * Must run as root.
 *
 * Usage:
 *   thl-duress-setup              interactive wizard
 *   thl-duress-setup --show       print current entries (types only, no hashes)
 *   thl-duress-setup --clear      remove all entries (prompts for confirmation)
 *
 * Build:
 *   gcc -o thl-duress-setup thl-duress-setup.c -lsodium -Wall -Wextra -O2
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sodium.h>

#define THL_DURESS_CONF     "/etc/thl/duress.conf"
#define THL_CONF_DIR        "/etc/thl"
#define MAX_PIN_LEN         128
#define MAX_LINE            512

/* ------------------------------------------------------------------ */
/* Terminal helpers                                                    */
/* ------------------------------------------------------------------ */

static void echo_off(struct termios *saved)
{
    struct termios raw;
    tcgetattr(STDIN_FILENO, saved);
    raw = *saved;
    raw.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
}

static void echo_on(const struct termios *saved)
{
    tcsetattr(STDIN_FILENO, TCSAFLUSH, saved);
}

/*
 * Read a PIN from stdin without echoing. Returns length, or -1 on error.
 * Buffer is always NUL-terminated.
 */
static int read_pin(const char *prompt, char *buf, size_t buflen)
{
    fprintf(stderr, "%s", prompt);
    fflush(stderr);

    struct termios saved;
    echo_off(&saved);

    int len = 0;
    int c;
    while ((c = getchar()) != '\n' && c != EOF && len < (int)(buflen - 1)) {
        buf[len++] = (char)c;
    }
    buf[len] = '\0';

    echo_on(&saved);
    fprintf(stderr, "\n");

    return (c == EOF && len == 0) ? -1 : len;
}

/* ------------------------------------------------------------------ */
/* Hashing                                                             */
/* ------------------------------------------------------------------ */

/*
 * Hash a PIN with Argon2id (libsodium's crypto_pwhash_str).
 * out must be at least crypto_pwhash_STRBYTES bytes.
 */
static int hash_pin(const char *pin, char *out)
{
    if (crypto_pwhash_str(
            out,
            pin, strlen(pin),
            crypto_pwhash_OPSLIMIT_SENSITIVE,
            crypto_pwhash_MEMLIMIT_SENSITIVE) != 0) {
        fprintf(stderr, "Error: out of memory during hashing\n");
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Config file operations                                              */
/* ------------------------------------------------------------------ */

static void ensure_conf_dir(void)
{
    struct stat st;
    if (stat(THL_CONF_DIR, &st) != 0) {
        if (mkdir(THL_CONF_DIR, 0700) != 0) {
            fprintf(stderr, "Cannot create %s: %s\n",
                    THL_CONF_DIR, strerror(errno));
            exit(1);
        }
    }
}

static void show_entries(void)
{
    FILE *f = fopen(THL_DURESS_CONF, "r");
    if (!f) {
        printf("No duress config found at %s\n", THL_DURESS_CONF);
        return;
    }

    int normal_count = 0, duress_count = 0;
    char line[MAX_LINE];

    printf("Current entries in %s:\n", THL_DURESS_CONF);
    printf("  %-8s  %-10s  %s\n", "Type", "Action", "Arg");
    printf("  %-8s  %-10s  %s\n", "----", "------", "---");

    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\n")] = '\0';
        if (line[0] == '\0' || line[0] == '#') continue;

        char type[16] = {0}, hash[256] = {0}, action[64] = {0}, arg[256] = {0};
        int n = sscanf(line, "%15s %255s %63s %255s", type, hash, action, arg);
        if (n < 2) continue;

        /* Redact hash */
        printf("  %-8s  %-10s  %s\n",
               type,
               n >= 3 ? action : "-",
               n >= 4 ? arg    : "-");

        if (strcmp(type, "normal") == 0) normal_count++;
        if (strcmp(type, "duress") == 0) duress_count++;
    }

    fclose(f);
    printf("\n  %d normal PIN(s), %d duress PIN(s)\n", normal_count, duress_count);
}

static void append_entry(const char *type, const char *hash,
                          const char *action, const char *arg)
{
    ensure_conf_dir();

    /* Create with restrictive perms if it doesn't exist */
    int fd = open(THL_DURESS_CONF,
                  O_WRONLY | O_CREAT | O_APPEND,
                  0600);
    if (fd < 0) {
        fprintf(stderr, "Cannot open %s: %s\n",
                THL_DURESS_CONF, strerror(errno));
        exit(1);
    }
    FILE *f = fdopen(fd, "a");
    if (!f) { close(fd); exit(1); }

    if (arg && arg[0] && strcmp(arg, "-") != 0)
        fprintf(f, "%s  %s  %s  %s\n", type, hash, action, arg);
    else
        fprintf(f, "%s  %s  %s\n", type, hash, action);

    fclose(f);

    /* Ensure perms are still 0600 (umask might have widened them) */
    chmod(THL_DURESS_CONF, 0600);
}

/* ------------------------------------------------------------------ */
/* Interactive wizard                                                  */
/* ------------------------------------------------------------------ */

static const char *ACTIONS[] = { "wipe", "silent", "decoy", "power", NULL };
static const char *ACTION_DESC[] = {
    "wipe    — run a key-destruction script, then log in normally",
    "silent  — log the event to syslog silently, log in normally",
    "decoy   — switch to a named decoy profile",
    "power   — immediately power off",
    NULL
};

static void wizard(void)
{
    char hash[crypto_pwhash_STRBYTES];
    char pin[MAX_PIN_LEN];
    char confirm[MAX_PIN_LEN];

    printf("=== THL Duress PIN Setup ===\n\n");
    printf("This wizard configures the PINs stored in %s.\n\n", THL_DURESS_CONF);
    printf("Step 1: Set the NORMAL PIN\n");
    printf("  This is your everyday PIN. It grants normal access.\n\n");

    for (;;) {
        if (read_pin("  Enter normal PIN: ", pin, sizeof(pin)) < 0) goto abort;
        if (read_pin("  Confirm normal PIN: ", confirm, sizeof(confirm)) < 0) goto abort;

        if (strcmp(pin, confirm) != 0) {
            fprintf(stderr, "  PINs do not match. Try again.\n\n");
            sodium_memzero(pin, sizeof(pin));
            sodium_memzero(confirm, sizeof(confirm));
            continue;
        }
        if (strlen(pin) < 6) {
            fprintf(stderr, "  PIN must be at least 6 characters.\n\n");
            sodium_memzero(pin, sizeof(pin));
            sodium_memzero(confirm, sizeof(confirm));
            continue;
        }
        break;
    }

    printf("\n  Hashing normal PIN (Argon2id, this may take a moment)...\n");
    if (hash_pin(pin, hash) != 0) goto abort;
    sodium_memzero(pin, sizeof(pin));
    sodium_memzero(confirm, sizeof(confirm));

    append_entry("normal", hash, "-", NULL);
    sodium_memzero(hash, sizeof(hash));
    printf("  Normal PIN saved.\n\n");

    /* One or more duress PINs */
    int duress_num = 1;
    char again[4];

    do {
        printf("Step %d: Set duress PIN #%d\n", duress_num + 1, duress_num);
        printf("  This PIN looks like a normal login but triggers a hidden action.\n\n");

        for (;;) {
            if (read_pin("  Enter duress PIN: ", pin, sizeof(pin)) < 0) goto abort;
            if (read_pin("  Confirm duress PIN: ", confirm, sizeof(confirm)) < 0) goto abort;

            if (strcmp(pin, confirm) != 0) {
                fprintf(stderr, "  PINs do not match. Try again.\n\n");
                sodium_memzero(pin, sizeof(pin));
                sodium_memzero(confirm, sizeof(confirm));
                continue;
            }
            if (strlen(pin) < 6) {
                fprintf(stderr, "  PIN must be at least 6 characters.\n\n");
                sodium_memzero(pin, sizeof(pin));
                sodium_memzero(confirm, sizeof(confirm));
                continue;
            }
            break;
        }
        sodium_memzero(confirm, sizeof(confirm));

        printf("\n  Choose action for this duress PIN:\n");
        for (int i = 0; ACTION_DESC[i]; i++)
            printf("    %d) %s\n", i + 1, ACTION_DESC[i]);
        printf("\n  Choice [1-%d]: ", 4);
        fflush(stdout);

        int choice = 0;
        if (scanf(" %d", &choice) != 1 || choice < 1 || choice > 4) {
            fprintf(stderr, "Invalid choice.\n");
            sodium_memzero(pin, sizeof(pin));
            continue;
        }
        /* Consume rest of line */
        int ch; while ((ch = getchar()) != '\n' && ch != EOF) {}

        const char *action = ACTIONS[choice - 1];
        char arg[256] = {0};

        if (choice == 1) { /* wipe */
            printf("  Path to wipe script [/etc/thl/actions/wipe-keys.sh]: ");
            fflush(stdout);
            if (fgets(arg, sizeof(arg), stdin))
                arg[strcspn(arg, "\n")] = '\0';
            if (arg[0] == '\0')
                strncpy(arg, "/etc/thl/actions/wipe-keys.sh", sizeof(arg) - 1);
        } else if (choice == 2) { /* silent */
            printf("  Tag to include in syslog entry [duress]: ");
            fflush(stdout);
            if (fgets(arg, sizeof(arg), stdin))
                arg[strcspn(arg, "\n")] = '\0';
            if (arg[0] == '\0')
                strncpy(arg, "duress", sizeof(arg) - 1);
        } else if (choice == 3) { /* decoy */
            printf("  Profile name to switch to [decoy]: ");
            fflush(stdout);
            if (fgets(arg, sizeof(arg), stdin))
                arg[strcspn(arg, "\n")] = '\0';
            if (arg[0] == '\0')
                strncpy(arg, "decoy", sizeof(arg) - 1);
        }
        /* power needs no arg */

        printf("\n  Hashing duress PIN (Argon2id)...\n");
        if (hash_pin(pin, hash) != 0) {
            sodium_memzero(pin, sizeof(pin));
            goto abort;
        }
        sodium_memzero(pin, sizeof(pin));

        append_entry("duress", hash, action, arg[0] ? arg : NULL);
        sodium_memzero(hash, sizeof(hash));
        printf("  Duress PIN #%d saved (action: %s).\n\n", duress_num, action);
        duress_num++;

        printf("  Add another duress PIN? [y/N]: ");
        fflush(stdout);
        if (fgets(again, sizeof(again), stdin))
            again[strcspn(again, "\n")] = '\0';

    } while (again[0] == 'y' || again[0] == 'Y');

    printf("\nSetup complete. Config written to %s\n", THL_DURESS_CONF);
    printf("Permissions: 0600 (root only)\n");
    return;

abort:
    sodium_memzero(pin, sizeof(pin));
    sodium_memzero(confirm, sizeof(confirm));
    sodium_memzero(hash, sizeof(hash));
    fprintf(stderr, "\nAborted.\n");
    exit(1);
}

/* ------------------------------------------------------------------ */
/* Main                                                                */
/* ------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
    if (getuid() != 0) {
        fprintf(stderr, "Error: thl-duress-setup must run as root.\n");
        return 1;
    }

    if (sodium_init() < 0) {
        fprintf(stderr, "Error: libsodium init failed.\n");
        return 1;
    }

    if (argc >= 2 && strcmp(argv[1], "--show") == 0) {
        show_entries();
        return 0;
    }

    if (argc >= 2 && strcmp(argv[1], "--clear") == 0) {
        printf("This will delete all entries in %s.\n", THL_DURESS_CONF);
        printf("Are you sure? [yes/N]: ");
        fflush(stdout);
        char ans[8] = {0};
        if (fgets(ans, sizeof(ans), stdin) && strncmp(ans, "yes", 3) == 0) {
            unlink(THL_DURESS_CONF);
            printf("Config cleared.\n");
        } else {
            printf("Aborted.\n");
        }
        return 0;
    }

    if (argc >= 2 && strcmp(argv[1], "--help") == 0) {
        printf("Usage: thl-duress-setup [--show | --clear | --help]\n");
        printf("  (no args)   interactive wizard to set normal + duress PINs\n");
        printf("  --show      list current entry types (hashes are not shown)\n");
        printf("  --clear     remove all entries\n");
        return 0;
    }

    wizard();
    return 0;
}
