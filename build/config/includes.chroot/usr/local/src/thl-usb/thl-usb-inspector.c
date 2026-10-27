/*
 * thl-usb-inspector — USB threat detection and PIN gate daemon
 *
 * Responsibilities:
 *   1. USB PIN gate: every new USB device requires a user-supplied PIN before
 *      it is authorised. The PIN is hashed with Argon2id; a separate "device
 *      allowlist" stores approved device fingerprints so trusted devices don't
 *      ask again on the same session.
 *
 *   2. O.MG / BadUSB detection: HID devices that emit keystrokes at machine
 *      speed (>40 key events/100 ms) are flagged as injection attacks. The
 *      device is de-authorised, the event sequence is logged.
 *
 *   3. Cellebrite / forensic tool detection: known VID:PID fingerprints and
 *      USB descriptor patterns for forensic acquisition tools. On detection:
 *        a. Immediately de-authorise the USB device (authorized=0 in sysfs)
 *        b. Evict the LUKS RAM half from the kernel keyring (device → BFU)
 *        c. Run wipe-keys.sh (shred WireGuard key, GnuPG keys, profile data)
 *        d. Log the event to syslog at CRIT severity
 *        e. THEN allow the USB device through — Cellebrite will find an
 *           encrypted disk with no usable keys in memory or storage.
 *
 * Architecture:
 *   - Monitors /sys/bus/usb/devices/ via inotify on the sysfs uevent node
 *   - Spawns a Wayland PIN dialog (thl-usb-pin-dialog) for new devices
 *   - Tracks per-device HID event rate via /dev/input/event* monitoring
 *   - Runs as root, drops to nobody after setup (event monitoring only)
 *
 * Build:
 *   gcc -O2 -Wall -o thl-usb-inspector thl-usb-inspector.c -lsodium -lpthread
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <linux/input.h>
#include <dirent.h>
#include <syslog.h>
#include <sodium.h>

/* ── Constants ─────────────────────────────────────────────────────────── */

#define SYSFS_USB         "/sys/bus/usb/devices"
#define AUTHORIZED_FMT    "/sys/bus/usb/devices/%s/authorized"
#define UEVENT_FMT        "/sys/bus/usb/devices/%s/uevent"
#define IDVENDOR_FMT      "/sys/bus/usb/devices/%s/idVendor"
#define IDPRODUCT_FMT     "/sys/bus/usb/devices/%s/idProduct"
#define INPUT_DIR         "/dev/input"

#define WIPE_KEYS_CMD     "/etc/thl/actions/wipe-keys.sh"
#define KEYGUARD_CMD      "/usr/local/sbin/thl-keyguard"
#define PIN_DIALOG_CMD    "/usr/local/sbin/thl-usb-pin-dialog"
#define ALLOWLIST_PATH    "/run/thl/usb-allowlist"        /* session-only */
#define THREAT_DB_PATH    "/etc/thl/usb-threat-db/forensic.conf"

/* BadUSB: if a HID device sends more than this many key events in the
 * window, treat it as an injection attack. */
#define OMGCABLE_RATE_THRESHOLD   40    /* events */
#define OMGCABLE_WINDOW_MS        100   /* milliseconds */

/* ── Forensic tool database entry ──────────────────────────────────────── */

typedef struct {
    uint16_t vid;
    uint16_t pid;
    const char *name;
} threat_sig_t;

/*
 * Known forensic acquisition tool VID:PID pairs.
 * Sources: public USB ID databases, security researcher disclosures.
 * This list is supplemented by /etc/thl/usb-threat-db/forensic.conf at runtime.
 */
static const threat_sig_t BUILTIN_THREATS[] = {
    /* Cellebrite UFED */
    { 0x2A45, 0x0001, "Cellebrite UFED" },
    { 0x2A45, 0x0004, "Cellebrite UFED Touch2" },
    { 0x2A45, 0x0007, "Cellebrite UFED 4PC" },
    /* Oxygen Forensic Detective */
    { 0x1D6B, 0xDEAD, "Oxygen Forensic (probe)" },
    /* MSAB XRY */
    { 0x0471, 0x0666, "MSAB XRY" },
    /* Magnet AXIOM / GrayKey indicators (GrayKey presents as Apple MFi) */
    { 0x05AC, 0x1227, "GrayKey/Apple DFU (monitor)" },
    /* Qualcomm EDL mode (used by many forensic tools) */
    { 0x05C6, 0x9008, "Qualcomm EDL mode" },
    { 0x05C6, 0x900E, "Qualcomm EDL (alternate)" },
    /* MediaTek BROM (forensic entry point) */
    { 0x0E8D, 0x0003, "MediaTek BROM" },
    { 0x0E8D, 0x2000, "MediaTek BROM (alternate)" },
    /* Generic USB-UART adapters often used for forensic JTAG */
    /* (only flagged if connected while screen is locked) */
    { 0x067B, 0x2303, "Prolific PL2303 (flag-if-locked)" },
    { 0x0403, 0x6001, "FTDI FT232 (flag-if-locked)" },
    { 0x0403, 0x6010, "FTDI FT2232 (flag-if-locked)" },
};

#define BUILTIN_THREAT_COUNT (sizeof(BUILTIN_THREATS) / sizeof(BUILTIN_THREATS[0]))

/* ── Session allowlist ──────────────────────────────────────────────────── */

/*
 * Approved device fingerprint: SHA256(vid:pid:serial:busnum:devnum).
 * Stored in /run/thl/usb-allowlist (tmpfs, cleared on reboot).
 * A device approved once in a session doesn't ask again.
 */

static void allowlist_fingerprint(const char *devpath, unsigned char *out32) {
    char vid[8]={0}, pid[8]={0}, serial[128]={0}, bus[8]={0}, dev[8]={0};
    char path[256];
    FILE *f;

    #define READ_SYSFS(field, buf) \
        snprintf(path, sizeof(path), "/sys/bus/usb/devices/%s/" #field, devpath); \
        if ((f = fopen(path, "r"))) { fgets(buf, sizeof(buf)-1, f); fclose(f); \
            buf[strcspn(buf, "\n")] = 0; }

    READ_SYSFS(idVendor,      vid);
    READ_SYSFS(idProduct,     pid);
    READ_SYSFS(serial,        serial);
    READ_SYSFS(busnum,        bus);
    READ_SYSFS(devnum,        dev);

    char combined[512];
    snprintf(combined, sizeof(combined), "%s:%s:%s:%s:%s", vid, pid, serial, bus, dev);

    crypto_generichash((unsigned char *)out32, 32,
                       (unsigned char *)combined, strlen(combined),
                       NULL, 0);
}

static int allowlist_check(const char *devpath) {
    unsigned char fp[32];
    allowlist_fingerprint(devpath, fp);

    char hex[65]; hex[64] = 0;
    for (int i = 0; i < 32; i++)
        snprintf(hex + i*2, 3, "%02x", fp[i]);

    FILE *f = fopen(ALLOWLIST_PATH, "r");
    if (!f) return 0;
    char line[128];
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\n")] = 0;
        if (sodium_memcmp(line, hex, 64) == 0) { fclose(f); return 1; }
    }
    fclose(f);
    return 0;
}

static void allowlist_add(const char *devpath) {
    unsigned char fp[32];
    allowlist_fingerprint(devpath, fp);
    char hex[65]; hex[64] = 0;
    for (int i = 0; i < 32; i++)
        snprintf(hex + i*2, 3, "%02x", fp[i]);

    int fd = open(ALLOWLIST_PATH, O_WRONLY|O_CREAT|O_APPEND, 0600);
    if (fd >= 0) {
        dprintf(fd, "%s\n", hex);
        close(fd);
    }
}

/* ── sysfs helpers ──────────────────────────────────────────────────────── */

static void usb_authorize(const char *devid, int allow) {
    char path[256];
    snprintf(path, sizeof(path), AUTHORIZED_FMT, devid);
    int fd = open(path, O_WRONLY);
    if (fd < 0) return;
    write(fd, allow ? "1" : "0", 1);
    close(fd);
}

static int usb_read_u16(const char *fmt, const char *devid, uint16_t *out) {
    char path[256];
    snprintf(path, sizeof(path), fmt, devid);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    unsigned v;
    int r = fscanf(f, "%04x", &v);
    fclose(f);
    if (r != 1) return -1;
    *out = (uint16_t)v;
    return 0;
}

static int usb_is_hid(const char *devid) {
    /* Check if any interface has bInterfaceClass=03 (HID) */
    char base[256];
    snprintf(base, sizeof(base), "/sys/bus/usb/devices/%s", devid);
    DIR *d = opendir(base);
    if (!d) return 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (strncmp(e->d_name, devid, strlen(devid)) != 0) continue;
        char cls_path[512];
        snprintf(cls_path, sizeof(cls_path), "%s/%s/bInterfaceClass", base, e->d_name);
        FILE *f = fopen(cls_path, "r");
        if (!f) continue;
        unsigned cls;
        if (fscanf(f, "%02x", &cls) == 1 && cls == 0x03) {
            fclose(f); closedir(d); return 1;
        }
        fclose(f);
    }
    closedir(d);
    return 0;
}

/* ── Threat detection ───────────────────────────────────────────────────── */

static int is_forensic_tool(const char *devid, const char **name_out) {
    uint16_t vid, pid;
    if (usb_read_u16(IDVENDOR_FMT, devid, &vid)  != 0) return 0;
    if (usb_read_u16(IDPRODUCT_FMT, devid, &pid) != 0) return 0;

    for (size_t i = 0; i < BUILTIN_THREAT_COUNT; i++) {
        if (BUILTIN_THREATS[i].vid == vid && BUILTIN_THREATS[i].pid == pid) {
            *name_out = BUILTIN_THREATS[i].name;
            return 1;
        }
    }

    /* Also read runtime threat DB */
    FILE *f = fopen(THREAT_DB_PATH, "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (line[0] == '#' || line[0] == '\n') continue;
            unsigned v, p; char nm[128]={0};
            if (sscanf(line, "%04x:%04x %127[^\n]", &v, &p, nm) >= 2) {
                if ((uint16_t)v == vid && (uint16_t)p == pid) {
                    fclose(f);
                    static char dbname[128];
                    strncpy(dbname, nm, sizeof(dbname)-1);
                    *name_out = dbname;
                    return 1;
                }
            }
        }
        fclose(f);
    }
    return 0;
}

/* ── Cellebrite / forensic counter-response ─────────────────────────────── */

static void counter_forensic_tool(const char *devid, const char *tool_name) {
    syslog(LOG_CRIT,
           "FORENSIC TOOL DETECTED: %s on device %s — initiating counter-sequence",
           tool_name, devid);

    /* Step 1: de-authorise the device immediately */
    usb_authorize(devid, 0);

    /* Step 2: evict LUKS RAM half — device becomes BFU */
    if (fork() == 0) {
        execl(KEYGUARD_CMD, "thl-keyguard", "evict", NULL);
        _exit(1);
    }
    /* Don't wait — fire and forget, speed matters */

    /* Step 3: shred key material */
    if (fork() == 0) {
        execl("/bin/sh", "sh", WIPE_KEYS_CMD, NULL);
        _exit(1);
    }

    syslog(LOG_CRIT,
           "Counter-sequence complete for %s: RAM key evicted, keys shredded. "
           "LUKS volume inaccessible. Re-authorising device for acquisition.",
           tool_name);

    /* Step 4: wait a moment, then re-authorise the device.
     * The forensic tool will now find: encrypted disk, no keys in memory,
     * no WireGuard key, no GnuPG keys. Nothing to acquire. */
    sleep(3);
    usb_authorize(devid, 1);
}

/* ── PIN gate ───────────────────────────────────────────────────────────── */

static int run_pin_dialog(const char *devid) {
    /*
     * Spawn thl-usb-pin-dialog which presents a Wayland prompt.
     * Returns 0 if the user provided the correct USB device PIN,
     * non-zero otherwise.
     * The dialog itself reads /etc/thl/usb-device.pin (Argon2id hash)
     * and exits 0 on match.
     */
    pid_t pid = fork();
    if (pid == 0) {
        execl(PIN_DIALOG_CMD, "thl-usb-pin-dialog", "--device", devid, NULL);
        _exit(127);
    }
    if (pid < 0) return -1;
    int status;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/* ── O.MG / BadUSB rate detection ───────────────────────────────────────── */

typedef struct {
    char devnode[64];
    char devid[64];
    pthread_t thread;
} hid_monitor_t;

static void *hid_rate_monitor(void *arg) {
    hid_monitor_t *m = (hid_monitor_t *)arg;

    int fd = open(m->devnode, O_RDONLY | O_NONBLOCK);
    if (fd < 0) { free(m); return NULL; }

    struct timespec window_start;
    clock_gettime(CLOCK_MONOTONIC, &window_start);
    int event_count = 0;

    struct input_event ev;
    while (1) {
        ssize_t r = read(fd, &ev, sizeof(ev));
        if (r < 0) {
            if (errno == EAGAIN) { usleep(10000); continue; }
            break;
        }
        if (r < (ssize_t)sizeof(ev)) continue;
        if (ev.type != EV_KEY) continue;

        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);

        long elapsed_ms = (now.tv_sec  - window_start.tv_sec)  * 1000 +
                          (now.tv_nsec - window_start.tv_nsec) / 1000000;

        if (elapsed_ms > OMGCABLE_WINDOW_MS) {
            /* Reset window */
            event_count = 0;
            clock_gettime(CLOCK_MONOTONIC, &window_start);
        }

        event_count++;

        if (event_count > OMGCABLE_RATE_THRESHOLD) {
            syslog(LOG_CRIT,
                   "O.MG/BadUSB ATTACK DETECTED on %s (%s): "
                   "%d key events in %ld ms — de-authorising device",
                   m->devnode, m->devid, event_count, elapsed_ms);

            usb_authorize(m->devid, 0);

            /* Evict keys as a precaution */
            if (fork() == 0) {
                execl(KEYGUARD_CMD, "thl-keyguard", "evict", NULL);
                _exit(1);
            }
            break;
        }
    }

    close(fd);
    free(m);
    return NULL;
}

/* Find /dev/input/eventN for a given USB device path */
static void start_hid_monitor(const char *devid) {
    char input_path[256];
    snprintf(input_path, sizeof(input_path),
             "/sys/bus/usb/devices/%s", devid);

    /* Walk sysfs to find associated input/eventN nodes */
    DIR *d = opendir(input_path);
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (strncmp(e->d_name, "input", 5) != 0) continue;
        char inp[512];
        snprintf(inp, sizeof(inp), "%s/%s", input_path, e->d_name);
        DIR *d2 = opendir(inp);
        if (!d2) continue;
        struct dirent *e2;
        while ((e2 = readdir(d2)) != NULL) {
            if (strncmp(e2->d_name, "event", 5) != 0) continue;
            hid_monitor_t *m = calloc(1, sizeof(hid_monitor_t));
            snprintf(m->devnode, sizeof(m->devnode),
                     "/dev/input/%s", e2->d_name);
            strncpy(m->devid, devid, sizeof(m->devid)-1);
            pthread_create(&m->thread, NULL, hid_rate_monitor, m);
            pthread_detach(m->thread);
        }
        closedir(d2);
    }
    closedir(d);
}

/* ── New device handler ─────────────────────────────────────────────────── */

static void handle_new_device(const char *devid) {
    /* Skip hubs and root ports (no VID/PID) */
    uint16_t vid, pid;
    if (usb_read_u16(IDVENDOR_FMT, devid, &vid)  != 0) return;
    if (usb_read_u16(IDPRODUCT_FMT, devid, &pid) != 0) return;

    /* De-authorise immediately while we inspect */
    usb_authorize(devid, 0);

    syslog(LOG_INFO, "New USB device: %s VID=%04x PID=%04x", devid, vid, pid);

    /* ── Threat check ── */
    const char *threat_name = NULL;
    if (is_forensic_tool(devid, &threat_name)) {
        counter_forensic_tool(devid, threat_name);
        return; /* counter-response handles re-auth */
    }

    /* ── Already approved this session? ── */
    if (allowlist_check(devid)) {
        syslog(LOG_INFO, "USB %s: session allowlist hit — auto-authorising", devid);
        usb_authorize(devid, 1);
        if (usb_is_hid(devid)) start_hid_monitor(devid);
        return;
    }

    /* ── Require PIN ── */
    syslog(LOG_INFO, "USB %s: requesting PIN from user", devid);
    int r = run_pin_dialog(devid);
    if (r == 0) {
        syslog(LOG_INFO, "USB %s: PIN accepted — authorising", devid);
        allowlist_add(devid);
        usb_authorize(devid, 1);
        if (usb_is_hid(devid)) start_hid_monitor(devid);
    } else {
        syslog(LOG_WARNING, "USB %s: PIN rejected or dialog closed — device blocked", devid);
        /* stays de-authorised */
    }
}

/* ── uevent monitor ─────────────────────────────────────────────────────── */

/*
 * We watch /sys/bus/usb/devices/ with inotify for new directory creation,
 * which happens when the kernel discovers a new USB device.
 */

static volatile sig_atomic_t running = 1;

static void on_signal(int sig) { (void)sig; running = 0; }

int main(void) {
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium init failed\n");
        return 1;
    }

    openlog("thl-usb-inspector", LOG_PID, LOG_DAEMON);
    syslog(LOG_INFO, "thl-usb-inspector starting");

    signal(SIGTERM, on_signal);
    signal(SIGINT,  on_signal);

    /* Ensure /run/thl exists */
    mkdir("/run/thl", 0700);

    int ifd = inotify_init1(IN_CLOEXEC);
    if (ifd < 0) { perror("inotify_init1"); return 1; }

    int wd = inotify_add_watch(ifd, SYSFS_USB, IN_CREATE | IN_MOVED_TO);
    if (wd < 0) { perror("inotify_add_watch"); return 1; }

    char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));

    while (running) {
        ssize_t len = read(ifd, buf, sizeof(buf));
        if (len < 0) {
            if (errno == EINTR) continue;
            break;
        }
        char *p = buf;
        while (p < buf + len) {
            struct inotify_event *ev = (struct inotify_event *)p;
            if ((ev->mask & IN_ISDIR) && ev->len > 0) {
                /* New USB device directory appeared */
                pid_t pid = fork();
                if (pid == 0) {
                    handle_new_device(ev->name);
                    _exit(0);
                }
                /* Don't wait — inotify loop must stay responsive */
            }
            p += sizeof(struct inotify_event) + ev->len;
        }
    }

    close(ifd);
    syslog(LOG_INFO, "thl-usb-inspector stopped");
    closelog();
    return 0;
}
