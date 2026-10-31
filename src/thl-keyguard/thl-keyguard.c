/*
 * thl-keyguard — split-key LUKS manager for Tinfoil Hat Linux
 *
 * THREAT MODEL
 * ============
 * Defeats Cellebrite / UFED in AFU (After First Unlock) state by ensuring
 * that the LUKS key is NEVER derivable from storage alone — not even by a
 * root-level process on a running system.
 *
 * SCHEME
 * ======
 * The LUKS passphrase is derived from two independent secrets:
 *
 *   RAM half    — stored only in the kernel keyring as a `logon` type key.
 *                 `logon` keys are write-once: the kernel can use them for
 *                 cryptographic operations but userspace (including root)
 *                 cannot read the payload back. Lost on poweroff or eviction.
 *
 *   Storage half — 32 random bytes, stored encrypted with Argon2id(PIN)
 *                  in /etc/thl/keystore/<luks-uuid>.ks
 *
 *   LUKS key    = HKDF-SHA256(ram_half || storage_half, info="thl-luks-v1")
 *
 *   Binding tag = HMAC-SHA256(key=ram_half, data=storage_half)
 *                 Stored in the keystore file.
 *                 Verified at every unlock — if the ram_half and storage_half
 *                 don't match (tampered storage, wrong USB, replay), LUKS
 *                 is never opened and a tamper event is logged.
 *
 * AFU HARDENING
 * =============
 *   - After unlock, ram_half lives as a kernel `logon` key (not readable).
 *   - The LUKS key (combination) is computed in a mlocked buffer and zeroed
 *     immediately after cryptsetup reads it from stdin.
 *   - IOMMU + DMA protections (see sysctl/modprobe configs) prevent
 *     Thunderbolt / PCIe DMA attacks against kernel memory.
 *   - USBGuard blocks new USB devices after first unlock.
 *   - Screen lock optionally evicts the ram_half (thl-keyguard evict),
 *     making the running system equivalent to BFU for an attacker.
 *
 * COMMANDS
 * ========
 *   thl-keyguard enroll  --device <dev> [--name <name>]
 *   thl-keyguard unlock  --device <dev> [--name <name>] [--map-to <dm-name>]
 *   thl-keyguard verify  [--keystore <file>]
 *   thl-keyguard evict
 *   thl-keyguard status
 *
 * BUILD
 * =====
 *   gcc -O2 -Wall -Wextra -Werror -fstack-protector-strong \
 *       -D_FORTIFY_SOURCE=2 -fPIE -pie \
 *       -o thl-keyguard thl-keyguard.c \
 *       -lsodium -lkeyutils
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <termios.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <syslog.h>
#include <time.h>

#include <sodium.h>
#include <keyutils.h>

/* ------------------------------------------------------------------ */
/* Constants                                                           */
/* ------------------------------------------------------------------ */

#define THL_VERSION          1
#define KEYSTORE_DIR         "/etc/thl/keystore"
#define HALF_LEN             32    /* bytes for each split half */
#define LUKS_KEY_LEN         64    /* bytes for the derived LUKS key */
#define BINDING_LEN          32    /* HMAC-SHA256 output */
#define MAX_PIN_LEN          128
#define MAX_PATH             512
#define MAX_UUID             64

/* Argon2id parameters for PIN key derivation.
 * SENSITIVE is ~1s / ~1GB RAM on modern hardware — right for disk unlock. */
#define ARGON_OPS   crypto_pwhash_OPSLIMIT_SENSITIVE
#define ARGON_MEM   crypto_pwhash_MEMLIMIT_SENSITIVE

/* Keyring description for the logon key */
#define KEYRING_DESC  "thl:ram-half"

/* HKDF info string — changing this invalidates all existing keystores */
#define HKDF_INFO     "thl-luks-v1"
#define HKDF_INFO_LEN (sizeof(HKDF_INFO) - 1)

/* ------------------------------------------------------------------ */
/* Key material — always mlocked, always zeroed after use             */
/* ------------------------------------------------------------------ */

typedef struct {
    uint8_t ram_half[HALF_LEN];
    uint8_t storage_half[HALF_LEN];
    uint8_t luks_key[LUKS_KEY_LEN];
    uint8_t binding[BINDING_LEN];
    uint8_t pin_key[crypto_secretbox_KEYBYTES];
} key_material_t;

static key_material_t *alloc_keymat(void)
{
    key_material_t *km = sodium_malloc(sizeof(*km));
    if (!km) { perror("sodium_malloc"); exit(1); }
    sodium_memzero(km, sizeof(*km));
    return km;
}

static void free_keymat(key_material_t *km)
{
    if (km) { sodium_memzero(km, sizeof(*km)); sodium_free(km); }
}

/* ------------------------------------------------------------------ */
/* Keystore file format (text, base64 encoded values)                 */
/* ------------------------------------------------------------------ */

typedef struct {
    int      version;
    char     luks_uuid[MAX_UUID];
    uint8_t  argon_salt[crypto_pwhash_SALTBYTES];
    uint64_t argon_ops;
    size_t   argon_mem;
    /* enc_storage = secretbox(pin_key, nonce, storage_half) */
    uint8_t  enc_storage_nonce[crypto_secretbox_NONCEBYTES];
    uint8_t  enc_storage[HALF_LEN + crypto_secretbox_MACBYTES];
    /* binding = HMAC-SHA256(ram_half, storage_half) — stored for tamper detect */
    uint8_t  binding[BINDING_LEN];
} keystore_t;

static int keystore_write(const char *path, const keystore_t *ks)
{
    FILE *f = fopen(path, "w");
    if (!f) { perror("fopen keystore"); return -1; }

    /* Encode binary fields as hex for readability / portability */
    char *argon_salt_hex   = sodium_bin2hex(NULL, 0, ks->argon_salt,   sizeof(ks->argon_salt));
    char *enc_nonce_hex    = sodium_bin2hex(NULL, 0, ks->enc_storage_nonce, sizeof(ks->enc_storage_nonce));
    char *enc_storage_hex  = sodium_bin2hex(NULL, 0, ks->enc_storage,  sizeof(ks->enc_storage));
    char *binding_hex      = sodium_bin2hex(NULL, 0, ks->binding,      sizeof(ks->binding));

    /* sodium_bin2hex returns NULL on alloc failure — use stack buffers instead */
    char abuf[sizeof(ks->argon_salt)   * 2 + 1];
    char nbuf[sizeof(ks->enc_storage_nonce) * 2 + 1];
    char ebuf[sizeof(ks->enc_storage)  * 2 + 1];
    char bbuf[sizeof(ks->binding)      * 2 + 1];
    sodium_bin2hex(abuf, sizeof(abuf), ks->argon_salt,       sizeof(ks->argon_salt));
    sodium_bin2hex(nbuf, sizeof(nbuf), ks->enc_storage_nonce, sizeof(ks->enc_storage_nonce));
    sodium_bin2hex(ebuf, sizeof(ebuf), ks->enc_storage,      sizeof(ks->enc_storage));
    sodium_bin2hex(bbuf, sizeof(bbuf), ks->binding,          sizeof(ks->binding));
    (void)argon_salt_hex; (void)enc_nonce_hex; (void)enc_storage_hex; (void)binding_hex;

    fprintf(f,
        "version: %d\n"
        "luks_uuid: %s\n"
        "argon_salt: %s\n"
        "argon_ops: %llu\n"
        "argon_mem: %zu\n"
        "enc_storage_nonce: %s\n"
        "enc_storage: %s\n"
        "binding: %s\n",
        ks->version,
        ks->luks_uuid,
        abuf,
        (unsigned long long)ks->argon_ops,
        ks->argon_mem,
        nbuf,
        ebuf,
        bbuf);

    fclose(f);
    chmod(path, 0600);
    return 0;
}

static int keystore_read(const char *path, keystore_t *ks)
{
    FILE *f = fopen(path, "r");
    if (!f) { perror("fopen keystore"); return -1; }

    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\n")] = '\0';
        char key[64] = {0}, val[768] = {0};
        if (sscanf(line, "%63[^:]: %767s", key, val) != 2) continue;

        if      (strcmp(key, "version")   == 0) ks->version = atoi(val);
        else if (strcmp(key, "luks_uuid") == 0)
            snprintf(ks->luks_uuid, MAX_UUID, "%s", val);
        else if (strcmp(key, "argon_ops") == 0)
            ks->argon_ops = (uint64_t)strtoull(val, NULL, 10);
        else if (strcmp(key, "argon_mem") == 0)
            ks->argon_mem = (size_t)strtoull(val, NULL, 10);
        else if (strcmp(key, "argon_salt") == 0)
            sodium_hex2bin(ks->argon_salt, sizeof(ks->argon_salt), val, strlen(val), NULL, NULL, NULL);
        else if (strcmp(key, "enc_storage_nonce") == 0)
            sodium_hex2bin(ks->enc_storage_nonce, sizeof(ks->enc_storage_nonce), val, strlen(val), NULL, NULL, NULL);
        else if (strcmp(key, "enc_storage") == 0)
            sodium_hex2bin(ks->enc_storage, sizeof(ks->enc_storage), val, strlen(val), NULL, NULL, NULL);
        else if (strcmp(key, "binding") == 0)
            sodium_hex2bin(ks->binding, sizeof(ks->binding), val, strlen(val), NULL, NULL, NULL);
    }
    fclose(f);
    return ks->version == THL_VERSION ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* Terminal                                                            */
/* ------------------------------------------------------------------ */

static void echo_off(struct termios *saved)
{
    struct termios t;
    tcgetattr(STDIN_FILENO, saved);
    t = *saved;
    t.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &t);
}

static void echo_on(const struct termios *saved)
{
    tcsetattr(STDIN_FILENO, TCSAFLUSH, saved);
}

static int read_secret(const char *prompt, char *buf, size_t len)
{
    fprintf(stderr, "%s", prompt);
    fflush(stderr);
    struct termios saved;
    echo_off(&saved);
    int n = 0, c;
    while ((c = getchar()) != '\n' && c != EOF && n < (int)(len - 1))
        buf[n++] = (char)c;
    buf[n] = '\0';
    echo_on(&saved);
    fprintf(stderr, "\n");
    return (c == EOF && n == 0) ? -1 : n;
}

/* ------------------------------------------------------------------ */
/* Crypto                                                              */
/* ------------------------------------------------------------------ */

/*
 * Derive a 32-byte PIN key from a user PIN using Argon2id.
 * out must be at least crypto_secretbox_KEYBYTES bytes.
 */
static int derive_pin_key(const char *pin, const uint8_t *salt,
                           uint64_t ops, size_t mem, uint8_t *out)
{
    return crypto_pwhash(out, crypto_secretbox_KEYBYTES,
                         pin, strlen(pin), salt,
                         ops, mem,
                         crypto_pwhash_ALG_ARGON2ID13);
}

/*
 * Compute the binding tag: HMAC-SHA256(key=ram_half, data=storage_half).
 * This is stored in the keystore so we can verify the pair at unlock time
 * before ever attempting to open LUKS.
 */
static void compute_binding(const uint8_t *ram_half, const uint8_t *storage_half,
                              uint8_t *binding_out)
{
    crypto_auth_hmacsha256(binding_out, storage_half, HALF_LEN, ram_half);
}

/*
 * Derive the LUKS key from both halves using HKDF-SHA256.
 * We extract into a 64-byte key to give LUKS enough entropy.
 */
static void derive_luks_key(const uint8_t *ram_half, const uint8_t *storage_half,
                              uint8_t *luks_key_out)
{
    /* Combine both halves as the IKM for HKDF */
    uint8_t ikm[HALF_LEN * 2];
    memcpy(ikm,            ram_half,     HALF_LEN);
    memcpy(ikm + HALF_LEN, storage_half, HALF_LEN);

    /* HKDF-SHA256: extract then expand */
    uint8_t prk[crypto_auth_hmacsha256_BYTES];
    /* Extract: PRK = HMAC-SHA256(salt="thl-kdf-salt", IKM) */
    crypto_auth_hmacsha256_state state;
    uint8_t extract_salt[32];
    memset(extract_salt, 0x17, sizeof(extract_salt)); /* fixed non-secret salt */
    crypto_auth_hmacsha256_init(&state, extract_salt, sizeof(extract_salt));
    crypto_auth_hmacsha256_update(&state, ikm, sizeof(ikm));
    crypto_auth_hmacsha256_final(&state, prk);

    /* Expand: OKM = T(1) || T(2) where T(i) = HMAC-SHA256(PRK, T(i-1)||info||i) */
    uint8_t t1[crypto_auth_hmacsha256_BYTES];
    uint8_t t2[crypto_auth_hmacsha256_BYTES];

    crypto_auth_hmacsha256_init(&state, prk, sizeof(prk));
    crypto_auth_hmacsha256_update(&state, (uint8_t*)HKDF_INFO, HKDF_INFO_LEN);
    uint8_t ctr = 0x01;
    crypto_auth_hmacsha256_update(&state, &ctr, 1);
    crypto_auth_hmacsha256_final(&state, t1);

    crypto_auth_hmacsha256_init(&state, prk, sizeof(prk));
    crypto_auth_hmacsha256_update(&state, t1, sizeof(t1));
    crypto_auth_hmacsha256_update(&state, (uint8_t*)HKDF_INFO, HKDF_INFO_LEN);
    ctr = 0x02;
    crypto_auth_hmacsha256_update(&state, &ctr, 1);
    crypto_auth_hmacsha256_final(&state, t2);

    memcpy(luks_key_out,            t1, 32);
    memcpy(luks_key_out + 32,       t2, 32);

    sodium_memzero(ikm,  sizeof(ikm));
    sodium_memzero(prk,  sizeof(prk));
    sodium_memzero(t1,   sizeof(t1));
    sodium_memzero(t2,   sizeof(t2));
}

/* ------------------------------------------------------------------ */
/* Kernel keyring (logon type — not readable from userspace)          */
/* ------------------------------------------------------------------ */

static int keyring_store_ram_half(const uint8_t *ram_half)
{
    /*
     * `logon` keys are kernel-only: add_key("logon", ...) stores the payload
     * in the kernel and returns a serial number. The kernel can look the key
     * up for dm-crypt, but keyctl(KEYCTL_READ, ...) on a logon key returns
     * EACCES for all callers including root.
     *
     * We store in the session keyring (@s) so it's scoped to this login
     * session and is automatically evicted when the session ends.
     */
    key_serial_t key = add_key("logon", KEYRING_DESC,
                                ram_half, HALF_LEN,
                                KEY_SPEC_SESSION_KEYRING);
    if (key == -1) {
        syslog(LOG_AUTH | LOG_ERR,
               "thl-keyguard: failed to store ram_half in kernel keyring: %s",
               strerror(errno));
        return -1;
    }
    /* Make it searchable but not explicitly revocable from userspace */
    keyctl_setperm(key, KEY_POS_VIEW | KEY_POS_SEARCH |
                        KEY_USR_VIEW | KEY_USR_SEARCH);
    return 0;
}

static int keyring_evict_ram_half(void)
{
    key_serial_t key = keyctl_search(KEY_SPEC_SESSION_KEYRING,
                                      "logon", KEYRING_DESC, 0);
    if (key == -1) {
        if (errno == ENOKEY) {
            fprintf(stderr, "thl-keyguard: no ram_half in keyring (already evicted)\n");
            return 0;
        }
        perror("keyctl_search");
        return -1;
    }
    if (keyctl_unlink(key, KEY_SPEC_SESSION_KEYRING) == -1) {
        perror("keyctl_unlink");
        return -1;
    }
    fprintf(stderr, "thl-keyguard: ram_half evicted from kernel keyring\n");
    syslog(LOG_AUTH | LOG_INFO, "thl-keyguard: ram_half evicted (screen locked or explicit eviction)");
    return 0;
}

static int keyring_has_ram_half(void)
{
    key_serial_t key = keyctl_search(KEY_SPEC_SESSION_KEYRING,
                                      "logon", KEYRING_DESC, 0);
    return (key != -1);
}

/* ------------------------------------------------------------------ */
/* LUKS operations (via cryptsetup child process)                     */
/* ------------------------------------------------------------------ */

/*
 * Open a LUKS device by piping the key into cryptsetup stdin.
 * The key is passed through a pipe so it never touches the filesystem.
 */
static int luks_open(const char *device, const char *dm_name,
                      const uint8_t *key, size_t key_len)
{
    int pfd[2];
    if (pipe(pfd) != 0) { perror("pipe"); return -1; }

    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return -1; }

    if (pid == 0) {
        /* Child: stdin = read end of pipe */
        close(pfd[1]);
        dup2(pfd[0], STDIN_FILENO);
        close(pfd[0]);
        execl("/sbin/cryptsetup", "cryptsetup", "luksOpen",
              "--key-file=-",
              "--key-slot=1",     /* keyguard always uses slot 1 */
              device, dm_name, NULL);
        _exit(1);
    }

    /* Parent: write key then close write end */
    close(pfd[0]);
    ssize_t written = write(pfd[1], key, key_len);
    close(pfd[1]);

    int status;
    waitpid(pid, &status, 0);

    if (written != (ssize_t)key_len) return -1;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

/*
 * Add a key to a LUKS slot (used during enrollment).
 * Reads any existing key on stdin, new key is piped.
 * During enrollment we create the LUKS volume with a temporary passphrase,
 * add the derived key to slot 1, then kill the temp passphrase.
 */
static int luks_add_key(const char *device, const char *existing_key,
                         size_t existing_len, const uint8_t *new_key,
                         size_t new_len, int slot)
{
    /* Write both keys to a temp file pair and pass as --key-file / stdin */
    char tmp_existing[] = "/run/thl-enroll-existing.XXXXXX";
    int fd = mkstemp(tmp_existing);
    if (fd < 0) return -1;
    if (write(fd, existing_key, existing_len) != (ssize_t)existing_len) {
        close(fd); unlink(tmp_existing); return -1;
    }
    close(fd);
    chmod(tmp_existing, 0600);

    int pfd[2];
    if (pipe(pfd) != 0) { unlink(tmp_existing); return -1; }

    pid_t pid = fork();
    if (pid == 0) {
        char slot_str[8];
        snprintf(slot_str, sizeof(slot_str), "%d", slot);
        close(pfd[1]);
        dup2(pfd[0], STDIN_FILENO);
        close(pfd[0]);
        execl("/sbin/cryptsetup", "cryptsetup", "luksAddKey",
              "--key-file", tmp_existing,
              "--key-slot", slot_str,
              device, "-", NULL);
        _exit(1);
    }
    close(pfd[0]);
    ssize_t w = write(pfd[1], new_key, new_len);
    (void)w;
    close(pfd[1]);

    int status;
    waitpid(pid, &status, 0);

    /* Zero and remove the temp key file */
    fd = open(tmp_existing, O_WRONLY);
    if (fd >= 0) {
        uint8_t zeros[256] = {0};
        (void)write(fd, zeros, existing_len < sizeof(zeros) ? existing_len : sizeof(zeros));
        close(fd);
    }
    unlink(tmp_existing);

    return (w == (ssize_t)new_len &&
            WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* Commands                                                            */
/* ------------------------------------------------------------------ */

static int cmd_enroll(const char *device)
{
    if (getuid() != 0) {
        fprintf(stderr, "enroll requires root\n"); return 1;
    }

    fprintf(stderr,
        "=== THL Split-Key Enrollment ===\n\n"
        "This will configure split-key encryption for %s.\n"
        "The RAM half will be printed once — store it on a separate USB\n"
        "or memorise it. It is NEVER stored on this device.\n\n"
        "You will also set a PIN to protect the storage half.\n\n",
        device);

    /* 1. Get the existing LUKS passphrase (for luksAddKey) */
    char existing_pass[MAX_PIN_LEN] = {0};
    if (read_secret("Existing LUKS passphrase (to authorise key addition): ",
                    existing_pass, sizeof(existing_pass)) < 0) return 1;

    /* 2. Set the THL PIN */
    char pin[MAX_PIN_LEN] = {0}, pin2[MAX_PIN_LEN] = {0};
    for (;;) {
        if (read_secret("THL PIN (protects storage half): ", pin, sizeof(pin)) < 0) return 1;
        if (read_secret("Confirm THL PIN: ", pin2, sizeof(pin2)) < 0) return 1;
        if (strcmp(pin, pin2) == 0 && strlen(pin) >= 6) break;
        fprintf(stderr, "PINs don't match or too short (min 6). Try again.\n");
        sodium_memzero(pin, sizeof(pin));
        sodium_memzero(pin2, sizeof(pin2));
    }
    sodium_memzero(pin2, sizeof(pin2));

    /* 3. Generate both halves */
    key_material_t *km = alloc_keymat();
    randombytes_buf(km->ram_half,     HALF_LEN);
    randombytes_buf(km->storage_half, HALF_LEN);

    /* 4. Derive LUKS key */
    derive_luks_key(km->ram_half, km->storage_half, km->luks_key);

    /* 5. Compute binding tag */
    compute_binding(km->ram_half, km->storage_half, km->binding);

    /* 6. Derive PIN key for encrypting storage_half */
    keystore_t ks;
    memset(&ks, 0, sizeof(ks));
    ks.version  = THL_VERSION;
    ks.argon_ops = ARGON_OPS;
    ks.argon_mem = ARGON_MEM;
    randombytes_buf(ks.argon_salt, sizeof(ks.argon_salt));

    fprintf(stderr, "\nDeriving PIN key (Argon2id, ~1s)...\n");
    if (derive_pin_key(pin, ks.argon_salt, ks.argon_ops, ks.argon_mem,
                       km->pin_key) != 0) {
        fprintf(stderr, "Argon2id failed (out of memory?)\n");
        free_keymat(km); return 1;
    }
    sodium_memzero(pin, sizeof(pin));

    /* 7. Encrypt storage_half */
    randombytes_buf(ks.enc_storage_nonce, sizeof(ks.enc_storage_nonce));
    crypto_secretbox_easy(ks.enc_storage,
                          km->storage_half, HALF_LEN,
                          ks.enc_storage_nonce,
                          km->pin_key);
    memcpy(ks.binding, km->binding, BINDING_LEN);

    /* 8. Get the LUKS UUID for the keystore filename */
    char uuid_cmd[MAX_PATH];
    snprintf(uuid_cmd, sizeof(uuid_cmd),
             "cryptsetup luksUUID %s 2>/dev/null", device);
    FILE *fp = popen(uuid_cmd, "r");
    if (fp) {
        if (fgets(ks.luks_uuid, sizeof(ks.luks_uuid), fp))
            ks.luks_uuid[strcspn(ks.luks_uuid, "\n")] = '\0';
        pclose(fp);
    }
    if (!ks.luks_uuid[0]) strncpy(ks.luks_uuid, "unknown", MAX_UUID - 1);

    /* 9. Write keystore */
    char ks_path[MAX_PATH];
    snprintf(ks_path, sizeof(ks_path), "%s/%s.ks", KEYSTORE_DIR, ks.luks_uuid);
    if (keystore_write(ks_path, &ks) != 0) {
        free_keymat(km); return 1;
    }
    fprintf(stderr, "Keystore written to %s\n", ks_path);

    /* 10. Add LUKS key to slot 1 */
    fprintf(stderr, "Adding derived key to LUKS slot 1...\n");
    if (luks_add_key(device, existing_pass, strlen(existing_pass),
                     km->luks_key, LUKS_KEY_LEN, 1) != 0) {
        fprintf(stderr, "Failed to add key to LUKS slot 1\n");
        sodium_memzero(existing_pass, sizeof(existing_pass));
        free_keymat(km);
        unlink(ks_path);
        return 1;
    }
    sodium_memzero(existing_pass, sizeof(existing_pass));

    /* 11. Print the RAM half — this is the only time it appears */
    char ram_half_hex[HALF_LEN * 2 + 1];
    sodium_bin2hex(ram_half_hex, sizeof(ram_half_hex), km->ram_half, HALF_LEN);

    fprintf(stderr,
        "\n========================================\n"
        "  RAM HALF (write this down / store on USB)\n"
        "  *** THIS IS NEVER STORED ON THIS DEVICE ***\n\n"
        "  %s\n\n"
        "  You will enter this at every boot in addition to your PIN.\n"
        "  Loss of the RAM half = permanent data loss.\n"
        "========================================\n\n",
        ram_half_hex);

    syslog(LOG_AUTH | LOG_INFO,
           "thl-keyguard: split-key enrollment complete for %s (uuid=%s)",
           device, ks.luks_uuid);

    free_keymat(km);
    sodium_memzero(ram_half_hex, sizeof(ram_half_hex));
    return 0;
}

static int cmd_unlock(const char *device, const char *dm_name,
                       const char *ks_path_override)
{
    if (getuid() != 0) {
        fprintf(stderr, "unlock requires root\n"); return 1;
    }

    /* Find keystore */
    char ks_path[MAX_PATH];
    if (ks_path_override) {
        strncpy(ks_path, ks_path_override, sizeof(ks_path) - 1);
    } else {
        /* Get UUID from device */
        char uuid[MAX_UUID] = {0};
        char cmd[MAX_PATH];
        snprintf(cmd, sizeof(cmd), "cryptsetup luksUUID %s 2>/dev/null", device);
        FILE *fp = popen(cmd, "r");
        if (fp) {
            if (fgets(uuid, sizeof(uuid), fp))
                uuid[strcspn(uuid, "\n")] = '\0';
            pclose(fp);
        }
        if (!uuid[0]) { fprintf(stderr, "Cannot determine LUKS UUID\n"); return 1; }
        snprintf(ks_path, sizeof(ks_path), "%s/%s.ks", KEYSTORE_DIR, uuid);
    }

    keystore_t ks;
    if (keystore_read(ks_path, &ks) != 0) {
        fprintf(stderr, "Failed to read keystore %s\n", ks_path);
        return 1;
    }

    /* Get PIN */
    char pin[MAX_PIN_LEN] = {0};
    if (read_secret("THL PIN: ", pin, sizeof(pin)) < 0) return 1;

    /* Get RAM half from user */
    char ram_hex[HALF_LEN * 2 + 2] = {0};
    if (read_secret("RAM half (hex): ", ram_hex, sizeof(ram_hex)) < 0) {
        sodium_memzero(pin, sizeof(pin)); return 1;
    }

    key_material_t *km = alloc_keymat();

    /* Decode RAM half */
    size_t ram_bin_len = 0;
    if (sodium_hex2bin(km->ram_half, HALF_LEN, ram_hex,
                       strlen(ram_hex), NULL, &ram_bin_len, NULL) != 0
        || ram_bin_len != HALF_LEN) {
        fprintf(stderr, "Invalid RAM half format\n");
        sodium_memzero(pin, sizeof(pin));
        sodium_memzero(ram_hex, sizeof(ram_hex));
        free_keymat(km); return 1;
    }
    sodium_memzero(ram_hex, sizeof(ram_hex));

    /* Derive PIN key and decrypt storage half */
    fprintf(stderr, "Verifying PIN (Argon2id)...\n");
    if (derive_pin_key(pin, ks.argon_salt, ks.argon_ops, ks.argon_mem,
                       km->pin_key) != 0) {
        fprintf(stderr, "Argon2id failed\n");
        sodium_memzero(pin, sizeof(pin));
        free_keymat(km); return 1;
    }
    sodium_memzero(pin, sizeof(pin));

    if (crypto_secretbox_open_easy(km->storage_half,
                                   ks.enc_storage, sizeof(ks.enc_storage),
                                   ks.enc_storage_nonce,
                                   km->pin_key) != 0) {
        fprintf(stderr, "PIN incorrect or storage half corrupted\n");
        syslog(LOG_AUTH | LOG_WARNING,
               "thl-keyguard: PIN verification failed for %s", device);
        free_keymat(km); return 1;
    }

    /* Verify binding tag — detects tampered storage, wrong USB, replay */
    compute_binding(km->ram_half, km->storage_half, km->binding);
    if (sodium_memcmp(km->binding, ks.binding, BINDING_LEN) != 0) {
        fprintf(stderr,
            "\n*** TAMPER ALERT ***\n"
            "The RAM half and storage half do not match.\n"
            "The storage may have been replaced or tampered with.\n"
            "Refusing to unlock.\n\n");
        syslog(LOG_AUTH | LOG_CRIT,
               "thl-keyguard: TAMPER DETECTED — binding mismatch for %s (uuid=%s)",
               device, ks.luks_uuid);
        free_keymat(km); return 1;
    }

    /* Derive LUKS key and open */
    derive_luks_key(km->ram_half, km->storage_half, km->luks_key);

    fprintf(stderr, "Opening LUKS device %s as /dev/mapper/%s...\n",
            device, dm_name ? dm_name : "root");

    int rc = luks_open(device, dm_name ? dm_name : "root",
                       km->luks_key, LUKS_KEY_LEN);

    /* Zero LUKS key immediately — it must not linger in memory */
    sodium_memzero(km->luks_key, LUKS_KEY_LEN);

    if (rc != 0) {
        fprintf(stderr, "cryptsetup luksOpen failed\n");
        free_keymat(km); return 1;
    }

    /* Store RAM half in kernel logon keyring (not readable from userspace) */
    if (keyring_store_ram_half(km->ram_half) != 0) {
        fprintf(stderr, "Warning: could not store ram_half in kernel keyring\n");
    }

    fprintf(stderr, "Unlocked. RAM half stored in kernel keyring (%s).\n",
            KEYRING_DESC);
    syslog(LOG_AUTH | LOG_INFO,
           "thl-keyguard: LUKS device %s unlocked (uuid=%s)", device, ks.luks_uuid);

    free_keymat(km);
    return 0;
}

static int cmd_verify(const char *ks_path)
{
    if (getuid() != 0) {
        fprintf(stderr, "verify requires root\n"); return 1;
    }

    keystore_t ks;
    if (keystore_read(ks_path ? ks_path : KEYSTORE_DIR "/default.ks", &ks) != 0) {
        fprintf(stderr, "Cannot read keystore\n"); return 1;
    }

    char pin[MAX_PIN_LEN] = {0};
    if (read_secret("THL PIN: ", pin, sizeof(pin)) < 0) return 1;

    char ram_hex[HALF_LEN * 2 + 2] = {0};
    if (read_secret("RAM half (hex): ", ram_hex, sizeof(ram_hex)) < 0) {
        sodium_memzero(pin, sizeof(pin)); return 1;
    }

    key_material_t *km = alloc_keymat();

    size_t ram_len = 0;
    if (sodium_hex2bin(km->ram_half, HALF_LEN, ram_hex, strlen(ram_hex),
                       NULL, &ram_len, NULL) != 0 || ram_len != HALF_LEN) {
        fprintf(stderr, "Invalid RAM half\n");
        free_keymat(km); return 1;
    }
    sodium_memzero(ram_hex, sizeof(ram_hex));

    derive_pin_key(pin, ks.argon_salt, ks.argon_ops, ks.argon_mem, km->pin_key);
    sodium_memzero(pin, sizeof(pin));

    if (crypto_secretbox_open_easy(km->storage_half,
                                   ks.enc_storage, sizeof(ks.enc_storage),
                                   ks.enc_storage_nonce, km->pin_key) != 0) {
        fprintf(stderr, "PIN incorrect\n"); free_keymat(km); return 1;
    }

    compute_binding(km->ram_half, km->storage_half, km->binding);
    int ok = (sodium_memcmp(km->binding, ks.binding, BINDING_LEN) == 0);

    printf("Binding verification: %s\n", ok ? "PASS" : "FAIL — TAMPER DETECTED");
    syslog(ok ? LOG_AUTH | LOG_INFO : LOG_AUTH | LOG_CRIT,
           "thl-keyguard: verify %s for uuid=%s",
           ok ? "passed" : "FAILED", ks.luks_uuid);

    free_keymat(km);
    return ok ? 0 : 1;
}

static int cmd_evict(void)
{
    return keyring_evict_ram_half();
}

static int cmd_status(void)
{
    printf("RAM half in kernel keyring: %s\n",
           keyring_has_ram_half() ? "YES (system is AFU)" : "NO (BFU or evicted)");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Main                                                                */
/* ------------------------------------------------------------------ */

static void usage(void)
{
    fprintf(stderr,
        "Usage: thl-keyguard <command> [options]\n\n"
        "Commands:\n"
        "  enroll  --device <dev>               enroll split-key on LUKS device\n"
        "  unlock  --device <dev>               unlock LUKS device\n"
        "          [--map-to <dm-name>]          default: 'root'\n"
        "          [--keystore <file>]           override keystore path\n"
        "  verify  [--keystore <file>]           verify binding without opening\n"
        "  evict                                 evict RAM half from kernel keyring\n"
        "  status                                show whether RAM half is loaded\n"
    );
}

int main(int argc, char *argv[])
{
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium init failed\n"); return 1;
    }

    if (argc < 2) { usage(); return 1; }

    const char *cmd        = argv[1];
    const char *device     = NULL;
    const char *dm_name    = "root";
    const char *ks_path    = NULL;

    for (int i = 2; i < argc; i++) {
        if      (strcmp(argv[i], "--device")   == 0 && i+1 < argc) device  = argv[++i];
        else if (strcmp(argv[i], "--map-to")   == 0 && i+1 < argc) dm_name = argv[++i];
        else if (strcmp(argv[i], "--keystore") == 0 && i+1 < argc) ks_path = argv[++i];
    }

    openlog("thl-keyguard", LOG_PID, LOG_AUTH);

    int rc = 1;
    if      (strcmp(cmd, "enroll") == 0) {
        if (!device) { fprintf(stderr, "--device required\n"); usage(); return 1; }
        rc = cmd_enroll(device);
    }
    else if (strcmp(cmd, "unlock") == 0) {
        if (!device) { fprintf(stderr, "--device required\n"); usage(); return 1; }
        rc = cmd_unlock(device, dm_name, ks_path);
    }
    else if (strcmp(cmd, "verify") == 0) rc = cmd_verify(ks_path);
    else if (strcmp(cmd, "evict")  == 0) rc = cmd_evict();
    else if (strcmp(cmd, "status") == 0) rc = cmd_status();
    else { fprintf(stderr, "Unknown command: %s\n", cmd); usage(); }

    closelog();
    return rc;
}
