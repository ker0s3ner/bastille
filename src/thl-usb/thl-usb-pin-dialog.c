/*
 * thl-usb-pin-dialog — Wayland PIN dialog for USB device authorisation
 *
 * Presents a minimal foot terminal window with a PIN prompt.
 * Reads the device USB PIN hash from /etc/thl/usb-device.pin.
 * Exits 0 on correct PIN, 1 on wrong PIN or timeout.
 *
 * Built as a small standalone binary so it can be invoked by
 * thl-usb-inspector without a heavy UI dependency.
 *
 * For the Wayland dialog we exec `foot -T "USB Device PIN" thl-usb-pin-input`
 * where thl-usb-pin-input is a shell helper that does the actual PIN entry.
 *
 * Build: gcc -O2 -Wall -o thl-usb-pin-dialog thl-usb-pin-dialog.c -lsodium
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <termios.h>
#include <sodium.h>

#define PIN_HASH_FILE  "/etc/thl/usb-device.pin"
#define PIN_MAX        64
#define DIALOG_TIMEOUT 30   /* seconds before auto-deny */

static int verify_pin(const char *pin) {
    FILE *f = fopen(PIN_HASH_FILE, "r");
    if (!f) {
        /* No PIN file → no PIN required. Treat as "no device PIN set" = allow. */
        return 1;
    }
    char hash[crypto_pwhash_STRBYTES + 1] = {0};
    fgets(hash, sizeof(hash)-1, f);
    fclose(f);
    hash[strcspn(hash, "\n")] = 0;

    int r = crypto_pwhash_str_verify(hash, pin, strlen(pin));
    sodium_memzero((void *)pin, strlen(pin));
    return r == 0 ? 1 : 0;
}

int main(int argc, char *argv[]) {
    if (sodium_init() < 0) return 1;

    const char *devid = "unknown";
    for (int i = 1; i < argc-1; i++) {
        if (strcmp(argv[i], "--device") == 0) devid = argv[i+1];
    }

    /*
     * Launch a foot terminal running thl-usb-pin-input, which writes
     * the PIN to a tmpfile we pass via environment.
     */
    char tmppath[] = "/run/thl/.usb-pin-XXXXXX";
    int tmpfd = mkstemp(tmppath);
    if (tmpfd < 0) return 1;
    close(tmpfd);
    chmod(tmppath, 0600);

    /* Build the terminal command */
    char title[128];
    snprintf(title, sizeof(title), "USB Device PIN — %s", devid);

    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "THL_PIN_FILE=%s /usr/local/sbin/thl-usb-pin-input", tmppath);

    pid_t pid = fork();
    if (pid == 0) {
        /* Set a timeout alarm handled by the shell wrapper */
        char timeout_str[16];
        snprintf(timeout_str, sizeof(timeout_str), "%d", DIALOG_TIMEOUT);
        setenv("THL_PIN_FILE",    tmppath,      1);
        setenv("THL_PIN_TIMEOUT", timeout_str,  1);
        setenv("THL_USB_DEVICE",  devid,        1);
        execl("/usr/bin/foot", "foot",
              "-t", title,
              "-a", "thl-usb-pin",
              "--", "/usr/local/sbin/thl-usb-pin-input",
              NULL);
        _exit(127);
    }

    /* Wait for dialog */
    int status;
    waitpid(pid, &status, 0);

    /* Read PIN from tmpfile */
    char pin[PIN_MAX+1] = {0};
    FILE *f = fopen(tmppath, "r");
    if (f) {
        fgets(pin, sizeof(pin)-1, f);
        fclose(f);
        pin[strcspn(pin, "\n")] = 0;
    }

    /* Unlink before verify so PIN never lingers on disk */
    unlink(tmppath);

    if (strlen(pin) == 0) return 1;   /* cancelled */

    int ok = verify_pin(pin);
    sodium_memzero(pin, sizeof(pin));
    return ok ? 0 : 1;
}
