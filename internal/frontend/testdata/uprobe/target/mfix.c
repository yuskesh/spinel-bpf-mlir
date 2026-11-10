// An uprobe fixture (the same contract as cfix and gfix: a child process that calls a system libc function for each line of stdin):
//   lock I    -> calls pthread_mutex_lock(&m[I]) and prints "lock <&m[I] in decimal>" (I is 0 or 1)
//   unlock I  -> calls pthread_mutex_unlock(&m[I]) and prints "unlock <&m[I] in decimal>"
//   quit      -> ends
// It prints "ready <pid>" first. The probes are libc's pthread_mutex_lock and unlock (the target is libc's absolute path, not this binary).
// Built by scripts/build-uprobe-fixtures.sh (a rebuild is byte-identical; see SHA256SUMS).
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static pthread_mutex_t m[2] = {PTHREAD_MUTEX_INITIALIZER, PTHREAD_MUTEX_INITIALIZER};

int main(void) {
  char line[256];
  int i;
  setvbuf(stdout, NULL, _IOLBF, 0);
  printf("ready %d\n", (int)getpid());
  while (fgets(line, sizeof line, stdin) != NULL) {
    size_t len = strlen(line);
    if (len > 0 && line[len - 1] == '\n') line[--len] = '\0';
    if (sscanf(line, "lock %d", &i) == 1 && i >= 0 && i < 2) {
      pthread_mutex_lock(&m[i]);
      printf("lock %lu\n", (unsigned long)&m[i]);
    } else if (sscanf(line, "unlock %d", &i) == 1 && i >= 0 && i < 2) {
      pthread_mutex_unlock(&m[i]);
      printf("unlock %lu\n", (unsigned long)&m[i]);
    } else if (strcmp(line, "quit") == 0) {
      break;
    } else {
      printf("error %s\n", line);
    }
  }
  return 0;
}
