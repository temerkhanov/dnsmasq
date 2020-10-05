/* Copyright (c) 2020 Sergey Temerkhanov
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 dated June, 1991, or
 * (at your option) version 3 dated 29 June, 2007.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * .....
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * */

#include "dnsmasq.h"
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>

#define MAX_MSGSIZE 4096
#define MAX_CMDLEN  20
#define BACKLOG     5

int ctrl_socket_init()
{
  int sockfd;
  int ret;
  struct sockaddr_un sa;


  memset(&sa, 0, sizeof(sa));

  sockfd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
  if (sockfd < 0) {
    return sockfd;
  }

  sa.sun_family = AF_UNIX;
  strncpy(sa.sun_path, daemon->ctrlsock, strnlen(daemon->ctrlsock, sizeof(sa.sun_path)));

  ret = bind(sockfd, (struct sockaddr *)&sa, sizeof(struct sockaddr_un));
  if (ret < 0) {
    close(sockfd);
    return ret;
  }

  ret = listen(sockfd, BACKLOG);
  if (ret < 0) {
    close(sockfd);
  }

  return sockfd;
}

struct command {
  char* cmd;
  int (*handler)(char *args, time_t now);
};

static const struct command handlers[] = {
  {.cmd = NULL, .handler = NULL},
};

int ctrl_socket_check(time_t now)
{
  struct command const *handler = handlers;
  char msg[MAX_MSGSIZE];
  int sockfd, ret;
  size_t offs = 0;
  struct sockaddr fsin;
  socklen_t slen = sizeof(fsin);

  while (((sockfd = accept(daemon->ctrlsockfd, &fsin, &slen)) < 0) && (errno == EINTR));

  do {
    ret = read(sockfd, msg + offs, sizeof(msg));
    offs += ret > 0 ? ret : 0;
  } while ((ret > 0) || (errno == EINTR));

  msg[offs] = '\0';

  close(sockfd);

  while (handler->cmd != NULL) {
    if (!strncmp(msg, handler->cmd, strlen(handler->cmd))) {
      return handler->handler(msg + strlen(handler->cmd) + 1, now);
    }

    handler++;
  }

  return -ENOENT;
}
