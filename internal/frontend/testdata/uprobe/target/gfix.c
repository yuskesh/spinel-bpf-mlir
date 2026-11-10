// An uprobe fixture (the same contract as cfix: a child process that calls a system libc function for each line of stdin):
//   gai HOST SERV  -> calls getaddrinfo(HOST, SERV, {AI_NUMERICHOST | AI_NUMERICSERV}, &r) and prints "gai <return value>" (freeaddrinfo on success; no network)
//   quit           -> ends
// It prints "ready <pid>" first. The probe is libc's getaddrinfo (the target is libc's absolute path, not this binary).
// Built by scripts/build-uprobe-fixtures.sh (a rebuild is byte-identical; see SHA256SUMS).
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
  char line[1024], host[512], serv[512];
  setvbuf(stdout, NULL, _IOLBF, 0);
  printf("ready %d\n", (int)getpid());
  while (fgets(line, sizeof line, stdin) != NULL) {
    size_t len = strlen(line);
    if (len > 0 && line[len - 1] == '\n') line[--len] = '\0';
    if (sscanf(line, "gai %511s %511s", host, serv) == 2) {
      struct addrinfo hints, *r = NULL;
      memset(&hints, 0, sizeof hints);
      hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
      hints.ai_socktype = SOCK_STREAM;
      int rc = getaddrinfo(host, serv, &hints, &r);
      if (rc == 0) freeaddrinfo(r);
      printf("gai %d\n", rc);
    } else if (strcmp(line, "quit") == 0) {
      break;
    } else {
      printf("error %s\n", line);
    }
  }
  return 0;
}
