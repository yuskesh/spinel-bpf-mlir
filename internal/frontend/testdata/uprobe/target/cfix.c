// An uprobe fixture: started as a child process, it calls a function for each line of stdin (the differential harness drives it).
//   sum A B C      -> calls sum_args(int64_t A, uint32_t B, int32_t C) and prints "sum <result>"
//   greet N TEXT   -> greet(TEXT, N) (TEXT is the rest of the line; empty gives an empty string)
//   null N         -> greet(NULL, N)
//   quit           -> ends
// It prints "ready <pid>" first. Built by scripts/build-uprobe-fixtures.sh (a rebuild is byte-identical; see SHA256SUMS).
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__attribute__((noinline)) int64_t sum_args(int64_t a, uint32_t b, int32_t c) {
  return a + (int64_t)b + (int64_t)c;
}

__attribute__((noinline)) uint32_t greet(const char *s, uint32_t n) {
  if (s == NULL) return n;
  return (uint32_t)strlen(s) + n;
}

int main(void) {
  char line[1024];
  setvbuf(stdout, NULL, _IOLBF, 0);
  printf("ready %d\n", (int)getpid());
  while (fgets(line, sizeof line, stdin) != NULL) {
    size_t len = strlen(line);
    if (len > 0 && line[len - 1] == '\n') line[--len] = '\0';
    int64_t a;
    uint32_t b, n;
    int32_t c;
    int off = 0;
    if (sscanf(line, "sum %" SCNd64 " %" SCNu32 " %" SCNd32, &a, &b, &c) == 3) {
      printf("sum %" PRId64 "\n", sum_args(a, b, c));
    } else if (sscanf(line, "greet %" SCNu32 "%n", &n, &off) == 1) {
      const char *text = line + off;
      if (*text == ' ') text++;
      printf("greet %" PRIu32 "\n", greet(text, n));
    } else if (sscanf(line, "null %" SCNu32, &n) == 1) {
      printf("greet %" PRIu32 "\n", greet(NULL, n));
    } else if (strcmp(line, "quit") == 0) {
      break;
    } else {
      printf("error %s\n", line);
    }
  }
  return 0;
}
