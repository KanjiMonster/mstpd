/*
 * brmon.c      RTnetlink listener.
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version
 *  2 of the License, or (at your option) any later version.
 *
 * Authors: Stephen Hemminger <shemminger@osdl.org>
 * Modified by Srinivas Aji <Aji_Srinivas@emc.com>
 *    for use in RSTP daemon. - 2006-09-01
 * Modified by Vitalii Demianets <dvitasgs@gmail.com>
 *    for use in MSTP daemon. - 2011-07-18
 */

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <linux/if_bridge.h>
#include <linux/rtnetlink.h>

#include <libmnl/libmnl.h>

#include "log.h"
#include "bridge_ctl.h"
#include "netif_utils.h"
#include "epoll_loop.h"

/* RFC 2863 operational status */
enum
{
    IF_OPER_UNKNOWN,
    IF_OPER_NOTPRESENT,
    IF_OPER_DOWN,
    IF_OPER_LOWERLAYERDOWN,
    IF_OPER_TESTING,
    IF_OPER_DORMANT,
    IF_OPER_UP,
};

/* link modes */
enum
{
    IF_LINK_MODE_DEFAULT,
    IF_LINK_MODE_DORMANT, /* limit upward transition to dormant */
};

static const char *port_states[] =
{
    [BR_STATE_DISABLED] = "disabled",
    [BR_STATE_LISTENING] = "listening",
    [BR_STATE_LEARNING] = "learning",
    [BR_STATE_FORWARDING] = "forwarding",
    [BR_STATE_BLOCKING] = "blocking",
};

static struct mnl_socket *mnl;
static struct epoll_event_handler br_handler;

static struct mnl_socket *mnl_state;

int br_set_state(unsigned ifindex, __u8 state)
{
#if 0	
    struct
    {
        struct nlmsghdr n;
        struct ifinfomsg ifi;
        char buf[256];
    } req;

    memset(&req, 0, sizeof(req));

    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_REPLACE;
    req.n.nlmsg_type = RTM_SETLINK;
    req.ifi.ifi_family = AF_BRIDGE;
    req.ifi.ifi_index = ifindex;

    addattr8(&req.n, sizeof(req.buf), IFLA_PROTINFO, state);

    return rtnl_talk(&rth_state, &req.n, NULL);
#endif
    return 0;
}
#if 0
static int listen_msg(struct rtnl_ctrl_data *data, struct nlmsghdr *n,
                    void *arg)
{
    struct ifinfomsg *ifi = NLMSG_DATA(n);
    struct rtattr * tb[IFLA_MAX + 1];
    int len = n->nlmsg_len;
    char b1[IFNAMSIZ];
    int af_family;
    bool newlink;
    int br_index;

    if(n->nlmsg_type == NLMSG_DONE)
        return 0;

    len -= NLMSG_LENGTH(sizeof(*ifi));
    if(len < 0)
    {
        return -1;
    }

    af_family = ifi->ifi_family;

    if(af_family != AF_BRIDGE && af_family != AF_UNSPEC)
        return 0;

    if(n->nlmsg_type != RTM_NEWLINK && n->nlmsg_type != RTM_DELLINK)
        return 0;

    parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), len);

    /* Check if we got this from bonding */
    if(tb[IFLA_MASTER] && af_family != AF_BRIDGE)
        return 0;

    if(tb[IFLA_IFNAME] == NULL)
    {
        ERROR("BUG: nil ifname");
        return -1;
    }

    if(n->nlmsg_type == RTM_DELLINK)
        LOG("Deleted ");

    LOG("%d: %s ", ifi->ifi_index, (char*)RTA_DATA(tb[IFLA_IFNAME]));

    if(tb[IFLA_OPERSTATE])
    {
        __u8 state = *(__u8*)RTA_DATA(tb[IFLA_OPERSTATE]);
        switch (state)
        {
            case IF_OPER_UNKNOWN:
                LOG("Unknown ");
                break;
            case IF_OPER_NOTPRESENT:
                LOG("Not Present ");
                break;
            case IF_OPER_DOWN:
                LOG("Down ");
                break;
            case IF_OPER_LOWERLAYERDOWN:
                LOG("Lowerlayerdown ");
                break;
            case IF_OPER_TESTING:
                LOG("Testing ");
                break;
            case IF_OPER_DORMANT:
                LOG("Dormant ");
                break;
            case IF_OPER_UP:
                LOG("Up ");
                break;
            default:
                LOG("State(%d) ", state);
        }
    }

    if(tb[IFLA_MTU])
        LOG("mtu %u ", *(int*)RTA_DATA(tb[IFLA_MTU]));

    if(tb[IFLA_MASTER])
    {
        LOG("master %s ",
                if_indextoname(*(int*)RTA_DATA(tb[IFLA_MASTER]), b1));
    }

    if(tb[IFLA_PROTINFO])
    {
        uint8_t state = *(uint8_t *)RTA_DATA(tb[IFLA_PROTINFO]);
        if(state <= BR_STATE_BLOCKING)
            LOG("state %s", port_states[state]);
        else
            LOG("state (%d)", state);
    }

    newlink = (n->nlmsg_type == RTM_NEWLINK);

    if(tb[IFLA_MASTER])
        br_index = *(int*)RTA_DATA(tb[IFLA_MASTER]);
    else if(is_bridge((char*)RTA_DATA(tb[IFLA_IFNAME])))
        br_index = ifi->ifi_index;
    else
        br_index = -1;

    bridge_notify(br_index, ifi->ifi_index, newlink, ifi->ifi_flags);

    return 0;
}
static int dump_msg(struct nlmsghdr *n, void *arg)
{
    return listen_msg(NULL, n, arg);
}

static inline void br_ev_handler(uint32_t events, struct epoll_event_handler *h)
{
    if(rtnl_listen(&rth, listen_msg, stdout) < 0)
    {
        ERROR("Error on bridge monitoring socket");
    }
}
#endif

static int link_attr_cb(const struct nlattr *attr, void *data)
{
    const struct nlattr **tb = data;
    int type = mnl_attr_get_type(attr);

    if (mnl_attr_type_valid(attr, IFLA_MAX) < 0)
	    return MNL_CB_OK;

    switch(type) {
	    case IFLA_ADDRESS:
		    if (mnl_attr_validate(attr, MNL_TYPE_BINARY) < 0)
			    return MNL_CB_ERROR;
		    break;
	    case IFLA_MTU:
		    if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
			    return MNL_CB_ERROR;
		    break;
	    case IFLA_IFNAME:
		    if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0)
			    return MNL_CB_ERROR;
		    break;
    }

    tb[type] = attr;
    return MNL_CB_OK;
}

static int link_cb(const struct nlmsghdr *n, void *data)
{
    struct ifinfomsg *ifi = NLMSG_DATA(n);
    struct nlattr * tb[IFLA_MAX + 1];
    int len = n->nlmsg_len;
    char b1[IFNAMSIZ];
    int af_family;
    bool newlink;
    int br_index;

    if(n->nlmsg_type == NLMSG_DONE)
        return 0;

    len -= NLMSG_LENGTH(sizeof(*ifi));
    if(len < 0)
    {
        return -1;
    }

    af_family = ifi->ifi_family;

    if(af_family != AF_BRIDGE && af_family != AF_UNSPEC)
        return 0;

    if(n->nlmsg_type != RTM_NEWLINK && n->nlmsg_type != RTM_DELLINK)
        return 0;

    mnl_attr_parse(n, sizeof(*ifi), link_attr_cb, tb);

    /* Check if we got this from bonding */
    if(tb[IFLA_MASTER] && af_family != AF_BRIDGE)
        return 0;

    if(tb[IFLA_IFNAME] == NULL)
    {
        ERROR("BUG: nil ifname");
        return -1;
    }

    if(n->nlmsg_type == RTM_DELLINK)
        LOG("Deleted ");

    INFO("%d: %s ", ifi->ifi_index, mnl_attr_get_str(tb[IFLA_IFNAME]));

    if(tb[IFLA_OPERSTATE])
    {
        __u8 state = mnl_attr_get_u8(tb[IFLA_OPERSTATE]);
        switch (state)
        {
            case IF_OPER_UNKNOWN:
                LOG("Unknown ");
                break;
            case IF_OPER_NOTPRESENT:
                LOG("Not Present ");
                break;
            case IF_OPER_DOWN:
                LOG("Down ");
                break;
            case IF_OPER_LOWERLAYERDOWN:
                LOG("Lowerlayerdown ");
                break;
            case IF_OPER_TESTING:
                LOG("Testing ");
                break;
            case IF_OPER_DORMANT:
                LOG("Dormant ");
                break;
            case IF_OPER_UP:
                LOG("Up ");
                break;
            default:
                LOG("State(%d) ", state);
        }
    }

    if(tb[IFLA_MTU])
        LOG("mtu %u ", mnl_attr_get_u32(tb[IFLA_MTU]));

    if(tb[IFLA_MASTER])
    {
        LOG("master %s ",
                if_indextoname(mnl_attr_get_u32(tb[IFLA_MASTER]), b1));
    }

    if(tb[IFLA_PROTINFO])
    {
        uint8_t state = mnl_attr_get_u8(tb[IFLA_PROTINFO]);
        if(state <= BR_STATE_BLOCKING)
            LOG("state %s", port_states[state]);
        else
            LOG("state (%d)", state);
    }

    newlink = (n->nlmsg_type == RTM_NEWLINK);

    if(tb[IFLA_MASTER])
        br_index = mnl_attr_get_u32(tb[IFLA_MASTER]);
    else if(is_bridge((char*)mnl_attr_get_str(tb[IFLA_IFNAME])))
        br_index = ifi->ifi_index;
    else
        br_index = -1;

    bridge_notify(br_index, ifi->ifi_index, newlink, ifi->ifi_flags);

    return 0;
}

static inline void br_ev_handler(uint32_t events, struct epoll_event_handler *h)
{
    char buf[MNL_SOCKET_BUFFER_SIZE];
    int ret;

    INFO("rcv messages");

    ret = mnl_socket_recvfrom(mnl, buf, sizeof(buf));
    while (ret > 0)
    {
        ret = mnl_cb_run(buf, ret, 0, 0, link_cb, NULL);
	INFO("br_ev_handler: mnl_cb_run() = %i", ret);
	if (ret <= MNL_CB_STOP)
		break;

	ret = mnl_socket_recvfrom(mnl, buf, sizeof(buf));
	INFO("br_ev_handler: mnl_socket_recvfrom() = %i", ret);
    }

    if(ret == -1)
    {
        ERROR("Error on bridge monitoring socket: %m");
    }
}

static int br_linkdump(struct mnl_socket *mnl, int family)
{
    char buf[MNL_SOCKET_DUMP_SIZE];
    unsigned int seq, portid;
    struct nlmsghdr *nlh;
    struct ifinfomsg *ifm;
    int ret;

    nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = RTM_GETLINK;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_seq = seq = time(NULL);
    ifm = mnl_nlmsg_put_extra_header(nlh, sizeof(*ifm));
    ifm->ifi_family = family;

    portid = mnl_socket_get_portid(mnl);

    ret = mnl_socket_sendto(mnl, nlh, nlh->nlmsg_len);
    if (ret < 0)
    {
        ERROR("Cannot send dump request: %m");
	return -1;
    }

    ret = mnl_socket_recvfrom(mnl, buf, sizeof(buf));
    while (ret > 0)
    {
        ret = mnl_cb_run(buf, ret, seq, portid, link_cb, NULL);
	INFO("br_linkdump: mnl_cb_run() = %i", ret);
	if (ret <= MNL_CB_STOP)
		break;

	ret = mnl_socket_recvfrom(mnl, buf, sizeof(buf));
	INFO("br_linkdump: mnl_socket_recvfrom() = %i", ret);
    }

    if (ret == -1)
    {
        ERROR("Failed receiving dump request: %m");
	return -1;
    }

    return 0;
}



int init_bridge_ops(void)
{
    int fd;

    mnl = mnl_socket_open(NETLINK_ROUTE);
    if (mnl == NULL)
    {
        ERROR("Couldn't open rtnl socket for monitoring");
        return -1;
    }

    if(mnl_socket_bind(mnl, RTMGRP_LINK, MNL_SOCKET_AUTOPID) < 0)
    {
        ERROR("Couldn't bind rtnl socket to RTMGRP_LINK: %m");
        return -1;
    }

    mnl_state = mnl_socket_open(NETLINK_ROUTE);
    if (mnl == NULL)
    {
        ERROR("Couldn't open rtnl socket for monitoring");
        return -1;
    }

    if(mnl_socket_bind(mnl_state, 0, MNL_SOCKET_AUTOPID) < 0)
    {
        ERROR("Couldn't bind rtnl socket to RTMGRP_LINK: %m");
        return -1;
    }
#if 1
    if(br_linkdump(mnl_state, PF_BRIDGE) < 0)
    {
        ERROR("Cannot send dump request: %m");
        return -1;
    }

    fd = mnl_socket_get_fd(mnl);

#else
    if(rtnl_linkdump_req(&rth, PF_BRIDGE) < 0)
    {
        ERROR("Cannot send dump request: %m");
        return -1;
    }

    if(rtnl_dump_filter(&rth, dump_msg, stdout) < 0)
    {
        ERROR("Dump terminated");
        return -1;
    }
#endif

    if(fcntl(fd, F_SETFL, O_NONBLOCK) < 0)
    {
        ERROR("Error setting O_NONBLOCK: %m");
        return -1;
    }

    br_handler.fd = fd;
    br_handler.arg = NULL;
    br_handler.handler = br_ev_handler;

    if(add_epoll(&br_handler) < 0)
        return -1;

    return 0;
}
