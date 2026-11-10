

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

__attribute__((noinline)) uint32_t greet(const char *name, uint32_t count) {
  if (name == NULL) return count;
  return (uint32_t)strlen(name) + count;
}

int main(void) {
  char line[1024];
  uint32_t count = 0;
  setvbuf(stdout, NULL, _IOLBF, 0);
  printf("ready %d\n", (int)getpid());
  while (fgets(line, sizeof line, stdin) != NULL) {
    size_t len = strlen(line);
    if (len > 0 && line[len - 1] == '\n') line[--len] = '\0';
    count++;
    if (strcmp(line, "(null)") == 0) {
      printf("greeted %" PRIu32 "\n", greet(NULL, count));
    } else {
      printf("greeted %" PRIu32 "\n", greet(line, count));
    }
  }
  return 0;
}
