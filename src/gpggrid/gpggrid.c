/*
 * gpggrid — keyboard-logger-defeating passphrase entry for GPG
 *
 * Modernised port of the original THL gpggrid (Shmoo Group, 2002).
 * Uses ncurses for terminal handling, GPG2 for encryption.
 *
 * HOW IT WORKS
 * ============
 * Instead of typing your passphrase, you select each character from a
 * randomised on-screen grid using arrow keys. The grid reshuffles after
 * every character. A hardware keystroke logger captures only cursor
 * movements and Enter presses — useless without the grid state, which
 * is generated from /dev/urandom and never stored.
 *
 * USAGE
 * =====
 *   gpggrid [gpg-args...]
 *
 * gpggrid is a drop-in wrapper for gpg/gpg2. It intercepts the
 * passphrase prompt, collects the passphrase via the grid, then passes
 * it to gpg through a pipe (never on the command line or in a file).
 *
 * EXAMPLES
 *   gpggrid --encrypt -a -r you@example.org document.txt
 *   gpggrid --decrypt message.gpg
 *   gpggrid --gen-key
 *
 * BUILD
 *   gcc -O2 -Wall -Wextra -o gpggrid gpggrid.c -lncurses -lsodium
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>

#include <ncurses.h>
#include <sodium.h>

/* ------------------------------------------------------------------ */
/* Grid parameters                                                     */
/* ------------------------------------------------------------------ */

#define GRID_COLS    10
#define GRID_ROWS    10   /* 10×10 = 100 cells, covers all printable ASCII */
#define MAX_PASS     256

/* The character set displayed in the grid: printable ASCII 33–126
 * plus space (32). We shuffle these into the grid randomly. */
static const char CHARSET[] =
    " !\"#$%&'()*+,-./"
    "0123456789:;<=>?"
    "@ABCDEFGHIJKLMNO"
    "PQRSTUVWXYZ[\\]^_"
    "`abcdefghijklmno"
    "pqrstuvwxyz{|}~";
#define CHARSET_LEN  95   /* 95 printable ASCII characters */

typedef struct {
    char cells[GRID_ROWS][GRID_COLS];
    int  cursor_row;
    int  cursor_col;
} grid_t;

/* ------------------------------------------------------------------ */
/* Grid operations                                                     */
/* ------------------------------------------------------------------ */

/*
 * Shuffle CHARSET into the grid using the Fisher-Yates algorithm
 * seeded by libsodium's CSPRNG. Any cells beyond CHARSET_LEN are
 * filled with '.' as a sentinel (not selectable).
 */
static void grid_shuffle(grid_t *g)
{
    char chars[GRID_COLS * GRID_ROWS];
    int  total = GRID_COLS * GRID_ROWS;

    /* Fill with charset, pad remainder */
    memcpy(chars, CHARSET, CHARSET_LEN);
    memset(chars + CHARSET_LEN, '.', total - CHARSET_LEN);

    /* Fisher-Yates shuffle using randombytes_uniform (unbiased) */
    for (int i = total - 1; i > 0; i--) {
        int j = (int)randombytes_uniform((uint32_t)(i + 1));
        char tmp = chars[i]; chars[i] = chars[j]; chars[j] = tmp;
    }

    for (int r = 0; r < GRID_ROWS; r++)
        for (int c = 0; c < GRID_COLS; c++)
            g->cells[r][c] = chars[r * GRID_COLS + c];
}

static char grid_selected(const grid_t *g)
{
    return g->cells[g->cursor_row][g->cursor_col];
}

/* ------------------------------------------------------------------ */
/* Display                                                             */
/* ------------------------------------------------------------------ */

static void draw_grid(const grid_t *g, int pass_len, int max_len,
                       const char *status_msg)
{
    int start_row = 3;
    int start_col = 4;

    /* Header */
    move(0, 0); clrtoeol();
    attron(A_BOLD);
    mvprintw(0, start_col, "THL gpggrid — passphrase entry");
    attroff(A_BOLD);

    mvprintw(1, start_col,
             "Navigate: arrow keys   Select: Enter   Cancel: Ctrl+C");
    mvprintw(2, start_col,
             "Passphrase: [%.*s]  (%d chars)",
             pass_len, "**********************************************",
             pass_len);

    /* Column headers */
    move(start_row, start_col - 2);
    for (int c = 0; c < GRID_COLS; c++)
        printw("  %d", c);
    printw("\n");

    /* Grid cells */
    for (int r = 0; r < GRID_ROWS; r++) {
        move(start_row + 1 + r, start_col - 2);
        printw("%d ", r);
        for (int c = 0; c < GRID_COLS; c++) {
            if (r == g->cursor_row && c == g->cursor_col)
                attron(A_REVERSE | A_BOLD);
            printw(" %c ", g->cells[r][c]);
            if (r == g->cursor_row && c == g->cursor_col)
                attroff(A_REVERSE | A_BOLD);
        }
    }

    /* Status line */
    int status_row = start_row + GRID_ROWS + 2;
    move(status_row, start_col);
    clrtoeol();
    if (status_msg)
        mvprintw(status_row, start_col, "%s", status_msg);

    /* Instructions */
    move(status_row + 1, start_col);
    printw("Done entering passphrase: press Tab or F10");
    move(status_row + 2, start_col);
    printw("Delete last char: Backspace");

    refresh();
    (void)max_len;
}

/* ------------------------------------------------------------------ */
/* Passphrase collection                                               */
/* ------------------------------------------------------------------ */

static int collect_passphrase(char *pass_out, size_t max_len)
{
    grid_t grid;
    memset(&grid, 0, sizeof(grid));
    grid.cursor_row = GRID_ROWS / 2;
    grid.cursor_col = GRID_COLS / 2;

    initscr();
    raw();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(0);
    clear();

    int pass_len  = 0;
    char *pass    = calloc(max_len + 1, 1);
    if (!pass) { endwin(); return -1; }

    grid_shuffle(&grid);
    const char *msg = NULL;

    for (;;) {
        draw_grid(&grid, pass_len, (int)max_len, msg);
        msg = NULL;
        int ch = getch();

        switch (ch) {
        case KEY_UP:
            grid.cursor_row = (grid.cursor_row - 1 + GRID_ROWS) % GRID_ROWS;
            break;
        case KEY_DOWN:
            grid.cursor_row = (grid.cursor_row + 1) % GRID_ROWS;
            break;
        case KEY_LEFT:
            grid.cursor_col = (grid.cursor_col - 1 + GRID_COLS) % GRID_COLS;
            break;
        case KEY_RIGHT:
            grid.cursor_col = (grid.cursor_col + 1) % GRID_COLS;
            break;

        case '\n': case KEY_ENTER: {
            /* Select character and reshuffle */
            char sel = grid_selected(&grid);
            if (sel == '.') { msg = "That cell is empty — move cursor"; break; }
            if (pass_len >= (int)(max_len - 1)) { msg = "Passphrase too long"; break; }
            pass[pass_len++] = sel;
            grid_shuffle(&grid);
            break;
        }

        case KEY_BACKSPACE: case 127: case '\b':
            if (pass_len > 0) {
                pass[--pass_len] = '\0';
                grid_shuffle(&grid);
            }
            break;

        case '\t': case KEY_F(10):
            /* Done */
            goto done;

        case 3: /* Ctrl+C */
            sodium_memzero(pass, max_len);
            free(pass);
            endwin();
            return -1;
        }
    }

done:
    endwin();
    if (pass_len == 0) {
        free(pass);
        return -1;
    }
    memcpy(pass_out, pass, pass_len + 1);
    sodium_memzero(pass, max_len);
    free(pass);
    return pass_len;
}

/* ------------------------------------------------------------------ */
/* GPG invocation                                                      */
/* ------------------------------------------------------------------ */

/*
 * Build a GPG2 argument vector.
 * Injects --passphrase-fd 0 so GPG reads the passphrase from stdin
 * rather than spawning pinentry. We provide the passphrase through a
 * pipe to avoid it ever appearing as a command-line argument or temp file.
 */
static char **build_gpg_argv(int argc, char **argv)
{
    /* argc+1 for --passphrase-fd, +1 for 0, +1 for NULL sentinel */
    char **gpg_argv = calloc((size_t)(argc + 3), sizeof(char *));
    if (!gpg_argv) return NULL;

    gpg_argv[0] = "gpg2";
    gpg_argv[1] = "--passphrase-fd";
    gpg_argv[2] = "0";

    for (int i = 1; i < argc; i++)
        gpg_argv[i + 2] = argv[i];
    gpg_argv[argc + 2] = NULL;

    return gpg_argv;
}

static int run_gpg(const char *passphrase, int pass_len,
                    int argc, char *argv[])
{
    int pfd[2];
    if (pipe(pfd) != 0) { perror("pipe"); return 1; }

    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return 1; }

    if (pid == 0) {
        /* Child: stdin = read end of pipe */
        close(pfd[1]);
        dup2(pfd[0], STDIN_FILENO);
        close(pfd[0]);

        char **gpg_argv = build_gpg_argv(argc, argv);
        execvp("gpg2", gpg_argv);
        /* Fallback to gpg if gpg2 not found */
        gpg_argv[0] = "gpg";
        execvp("gpg", gpg_argv);
        perror("execvp gpg");
        _exit(1);
    }

    /* Parent: write passphrase + newline, then close */
    close(pfd[0]);
    write(pfd[1], passphrase, (size_t)pass_len);
    write(pfd[1], "\n", 1);
    close(pfd[1]);

    int status;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}

/* ------------------------------------------------------------------ */
/* Main                                                                */
/* ------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
    if (sodium_init() < 0) {
        fprintf(stderr, "gpggrid: libsodium init failed\n");
        return 1;
    }

    /* If no GPG args given, just show usage */
    if (argc < 2) {
        fprintf(stderr,
            "gpggrid — keyboard-logger-defeating GPG passphrase entry\n\n"
            "Usage: gpggrid [gpg-args...]\n\n"
            "gpggrid is a drop-in wrapper for gpg2. It collects your passphrase\n"
            "via a randomised on-screen grid instead of keyboard typing.\n"
            "Hardware keystroke loggers capture only cursor movements, not the passphrase.\n\n"
            "Examples:\n"
            "  gpggrid --encrypt -a -r you@example.org file.txt\n"
            "  gpggrid --decrypt file.gpg\n"
            "  gpggrid --gen-key\n");
        return 1;
    }

    fprintf(stderr, "gpggrid: collecting passphrase via grid...\n");

    char *pass = sodium_malloc(MAX_PASS);
    if (!pass) { perror("sodium_malloc"); return 1; }

    int pass_len = collect_passphrase(pass, MAX_PASS);
    if (pass_len < 0) {
        fprintf(stderr, "gpggrid: cancelled\n");
        sodium_free(pass);
        return 1;
    }

    fprintf(stderr, "gpggrid: passphrase collected (%d chars), invoking gpg2...\n",
            pass_len);

    int rc = run_gpg(pass, pass_len, argc, argv);

    sodium_memzero(pass, MAX_PASS);
    sodium_free(pass);
    return rc;
}
