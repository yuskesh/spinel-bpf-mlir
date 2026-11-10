// An uprobe fixture (the same contract as cfix: a child process that calls put_buf for each line of stdin; DWARF in the binary):
//   put LEN TEXT  -> copies TEXT to the start of a zeroed 256-byte buffer and calls put_buf(buf, LEN), printing "put <return value>" (TEXT may be omitted: empty)
//   putnull LEN   -> put_buf(NULL, LEN)
//   quit          -> ends
// It prints "ready <pid>" first. The probe is put_buf (const void *buf, a pointer of depth 1; int len).
// Built by scripts/build-uprobe-fixtures.sh (a rebuild is byte-identical; see SHA256SUMS).
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__attribute__((noinline)) int put_buf(const void *buf, int len) {
  __asm__ volatile("" ::"r"(buf), "r"(len) : "memory");
  return len;
}

int main(void) {
  char line[1024], text[512];
  static char buf[256];
  int n;
  setvbuf(stdout, NULL, _IOLBF, 0);
  printf("ready %d\n", (int)getpid());
  while (fgets(line, sizeof line, stdin) != NULL) {
    size_t len = strlen(line);
    if (len > 0 && line[len - 1] == '\n') line[--len] = '\0';
    text[0] = '\0';
    if (sscanf(line, "put %d %511s", &n, text) >= 1) {
      memset(buf, 0, sizeof buf);
      memcpy(buf, text, strlen(text) < sizeof buf ? strlen(text) : sizeof buf);
      printf("put %d\n", put_buf(buf, n));
    } else if (sscanf(line, "putnull %d", &n) == 1) {
      printf("putnull %d\n", put_buf(NULL, n));
    } else if (strcmp(line, "quit") == 0) {
      break;
    } else {
      printf("error %s\n", line);
    }
  }
  return 0;
}
