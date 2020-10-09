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

static int sock_reload(char *args, time_t now)
{
  (void)args;
  clear_cache_and_reload(now);

  return 0;
}

static int sock_del_lease(char *args, time_t now)
{
  char *ipaddr = args;
  union all_addr addr;
  struct dhcp_lease *lease;
  int ret = 0;

  if (inet_pton(AF_INET, ipaddr, &addr.addr4))
    lease = lease_find_by_addr(addr.addr4);
#ifdef HAVE_DHCP6
  else if (inet_pton(AF_INET6, ipaddr, &addr.addr6))
    lease = lease6_find_by_addr(&addr.addr6, 128, 0);
#endif
  else {
    my_syslog(LOG_INFO, _("No lease for address %s"), ipaddr);
    return -ENOENT;
  }

  if (lease)
    {
      my_syslog(LOG_INFO, _("Removing lease for address %s"), ipaddr);
      lease_prune(lease, now);
      lease_update_file(now);
      lease_update_dns(0);
    }
  else
    ret = -ENOENT;

  return ret;
}

static int sock_add_lease(char *args, time_t now)
{
  union all_addr addr;
  struct dhcp_lease *lease;
  int ret = 0;
  char *str = strdupa(args);
  unsigned char hw_addr_hex[DHCP_CHADDR_MAX];
  int hw_addr_len = 0, hw_type = 0;

  char *ipaddr = strtok_r(str, " ", &str);
  char *hwaddr = strtok_r(str, " ", &str);
  char *hostname = strtok_r(str, " ", &str);

  if (!ipaddr || !hwaddr) {
    my_syslog(LOG_INFO, _("Invalid parameters for adding a lease"));
    return -ENOENT;
  }

  if (inet_pton(AF_INET, ipaddr, &addr.addr4)) {
    lease = lease_find_by_addr(addr.addr4);
    if (!lease)
      lease = lease4_allocate(addr.addr4);
  }
#ifdef HAVE_DHCP6
  else if (inet_pton(AF_INET6, ipaddr, &addr.addr6)) {
    lease = lease6_find_by_addr(&addr.addr6, 128, 0);
    if (!lease)
      lease = lease6_allocate(&addr.addr6, LEASE_NA);
  }
#endif
  else {
    my_syslog(LOG_INFO, _("Invalid address %s"), ipaddr);
    return -EINVAL;
  }

  if (lease)
    {
      my_syslog(LOG_INFO, _("Adding lease for address %s : %s : %s"), ipaddr, hwaddr, hostname);
      hw_addr_len = parse_hex(hwaddr, hw_addr_hex, DHCP_CHADDR_MAX, NULL, &hw_type);
      if (!hw_type && hw_addr_len)
        hw_type = ARPHRD_ETHER;
      lease_set_hwaddr(lease, hw_addr_hex, NULL, hw_addr_len, hw_type, 0, now, 0);
      if (hostname)
        lease_set_hostname(lease, hostname, 1, get_domain(lease->addr), NULL);
      lease_set_expires(lease, 0xffffffff, now);
      lease_update_file(now);
      lease_update_dns(0);
    }
  else
    ret = -ENOENT;

  return ret;
}

static int sock_add_host(char *args, time_t now)
{
  (void)now;
  char *str = strdupa(args);
  union all_addr addr;
  struct dhcp_config *config, *configs;

  char *ipaddr = strtok_r(str, " ", &str);
  char *hwaddr = strtok_r(str, " ", &str);
  char *hostname = strtok_r(str, " ", &str);

  if (!ipaddr || !hwaddr) {
    my_syslog(LOG_INFO, _("Invalid parameters for adding a lease"));
    return -ENOENT;
  }

  if (inet_pton(AF_INET, ipaddr, &addr.addr4))
    {
      config = safe_malloc(sizeof(struct dhcp_config));

      config->next = daemon->dhcp_conf;
      config->flags = CONFIG_ADDR;
      config->hwaddr = NULL;
      config->netid = NULL;
      config->filter = NULL;
      config->clid = NULL;
      config->addr = addr.addr4;
#ifdef HAVE_DHCP6
      config->addr6 = NULL;
#endif
      config->lease_time = 0xffffffff;
      config->flags |= CONFIG_TIME;
    }
  else
    return -EINVAL;

  /* If the same IP appears in more than one host config, then DISCOVER
      for one of the hosts will get the address, but REQUEST will be NAKed,
      since the address is reserved by the other one -> protocol loop. */
  for (configs = daemon->dhcp_conf; configs; configs = configs->next)
    if ((configs->flags & CONFIG_ADDR) &&
        configs->addr.s_addr == addr.addr4.s_addr)
      {
	print_mac(daemon->namebuff, configs->hwaddr->hwaddr, configs->hwaddr->hwaddr_len);
	my_syslog(LOG_INFO, _("Host entry for address %s : %s : %s is already present"),
		  inet_ntoa(configs->addr), daemon->namebuff, hostname);
	free(config);
	return -EINVAL;
      }

  struct hwaddr_config *newhw = safe_malloc(sizeof(struct hwaddr_config));
  if ((newhw->hwaddr_len = parse_hex(hwaddr, newhw->hwaddr, DHCP_CHADDR_MAX,
				     &newhw->wildcard_mask, &newhw->hwaddr_type)) == -1)
    {
      free(newhw);
      free(config);
      return -EINVAL;
    }
  else
    {
      newhw->next = config->hwaddr;
      config->hwaddr = newhw;
    }

  if (hostname &&
      legal_hostname(hostname))
    {
      config->hostname = safe_malloc(strlen(hostname) + 1);
      safe_strncpy(config->hostname, hostname, strlen(hostname));

      config->flags |= CONFIG_NAME;
      config->domain = strip_hostname(config->hostname);
    }

  print_mac(daemon->namebuff, config->hwaddr->hwaddr, config->hwaddr->hwaddr_len);
  my_syslog(LOG_INFO, _("Adding host entry for address %s : %s : %s"),
	    inet_ntoa(config->addr), daemon->namebuff, config->hostname);
  daemon->dhcp_conf = config;

  return 0;
}

static int sock_del_host(char *args, time_t now)
{
  (void)now;
  int ret = -ENOENT;
  union all_addr addr;
  struct dhcp_config *config, *next;
  char *ipaddr = args;

  if (!ipaddr) {
    my_syslog(LOG_INFO, _("No IP address specified"));
    return -ENOENT;
  }

  if (!inet_pton(AF_INET, ipaddr, &addr.addr4))
    return -EINVAL;

  if (have_config(daemon->dhcp_conf, CONFIG_ADDR) &&
      daemon->dhcp_conf->addr.s_addr == addr.addr4.s_addr)
    {
      config = daemon->dhcp_conf;

      my_syslog(LOG_INFO, _("Removing host entry for address %s"), ipaddr);

      daemon->dhcp_conf = daemon->dhcp_conf->next;
      dhcp_config_free(config);
    }
  else
    {
      for (config = daemon->dhcp_conf; config; config = config->next) {
	next = config->next;
	if (have_config(next, CONFIG_ADDR) &&
	    next->addr.s_addr == addr.addr4.s_addr)
	  {
	    config->next = next->next;

	    my_syslog(LOG_INFO, _("Removing host entry for address %s"), ipaddr);

	    dhcp_config_free(next);

	    break;
	  }
    }
  }

  my_syslog(LOG_INFO, _("Not removing host entry for address %s"), ipaddr);

  return ret;
}

static const struct command handlers[] = {
  {.cmd = "reload", .handler = sock_reload},
  /* reload */
  {.cmd = "del_lease", .handler = sock_del_lease},
  /* del_lease <IP address> */
  {.cmd = "add_lease", .handler = sock_add_lease},
  /* add_lease <IP address> <hw address> <hostname>*/
  {.cmd = "add_host", .handler = sock_add_host},
  /* add_host <IP address> <hw address> <hostname>*/
  {.cmd = "del_host", .handler = sock_del_host},
  /* del_host <IP address>*/

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
