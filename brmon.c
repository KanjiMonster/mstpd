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
#include <string.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <string.h>
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
static int state_seq;

bool have_per_vlan_state = 1;

static int mnl_talk(struct mnl_socket *nl, struct nlmsghdr *msg,
		    struct nlmsghdr **answer)
{
    char buf[MNL_SOCKET_BUFFER_SIZE];
    unsigned int seq = ++state_seq;
    int ret;

    msg->nlmsg_seq = seq;

    if (mnl_socket_sendto(nl, msg, msg->nlmsg_len) < 0)
    {
        ERROR("mnl_socket_sendto failed: %m");
	return -1;
    }

    if(answer) {
        ret = mnl_socket_recvfrom(nl, buf, sizeof(*buf));
        if (ret < 0)
        {
            ERROR("mnl_socket_recvfrom failed: %m");
    	return -1;
        }
    
        ret = mnl_cb_run(buf, ret, seq, mnl_socket_get_portid(nl), NULL, NULL);
        if (ret < 0)
        {
            ERROR("mnl_cb_run failed: %m");
    	return -1;
        }

        *answer = malloc(msg->nlmsg_len);
	memcpy(*answer, buf, msg->nlmsg_len);
    }

    return 0;
}

int br_set_vlan_state(unsigned ifindex, __u16 vid, __u8 state)
{
    char buf[MNL_SOCKET_BUFFER_SIZE];
    struct br_vlan_msg *bvm;
    struct nlmsghdr *n;
    struct bridge_vlan_info vlan_info;
    struct nlattr *entry;

    LOG("ifindex %d vid %d state %d", ifindex, vid, state);


    n = mnl_nlmsg_put_header(buf);
    n->nlmsg_type = RTM_NEWVLAN;
    n->nlmsg_flags = NLM_F_REQUEST | NLM_F_REPLACE;
    bvm = mnl_nlmsg_put_extra_header(n, sizeof(*bvm));
    bvm->family = AF_BRIDGE;
    bvm->ifindex = ifindex;


    entry = mnl_attr_nest_start(n, BRIDGE_VLANDB_ENTRY);
    mnl_attr_put(n, BRIDGE_VLANDB_ENTRY_INFO, sizeof(vlan_info), &vlan_info);
    mnl_attr_put_u8(n, BRIDGE_VLANDB_ENTRY_STATE, state);
    mnl_attr_nest_end(n, entry);

    return mnl_talk(mnl_state, n, NULL);
}

int br_set_state(unsigned ifindex, __u8 state)
{
    char buf[MNL_SOCKET_BUFFER_SIZE];
    struct ifinfomsg *ifi;
    struct nlmsghdr *n;

    n = mnl_nlmsg_put_header(buf);
    n->nlmsg_type = RTM_SETLINK;
    n->nlmsg_flags = NLM_F_REQUEST | NLM_F_REPLACE;
    ifi = mnl_nlmsg_put_extra_header(n, sizeof(*ifi));
    ifi->ifi_family = AF_BRIDGE;
    ifi->ifi_index = ifindex;

    mnl_attr_put_u8(n, IFLA_PROTINFO, state);

    return mnl_talk(mnl_state, n, NULL);
}

static const enum mnl_attr_data_type link_policy[IFLA_MAX + 1] =
{
    [IFLA_ADDRESS] = MNL_TYPE_BINARY,
    [IFLA_IFNAME] = MNL_TYPE_STRING,
    [IFLA_MTU] = MNL_TYPE_U32,
    [IFLA_MASTER] = MNL_TYPE_U32,
    [IFLA_PROTINFO] = MNL_TYPE_U8,
    [IFLA_OPERSTATE] = MNL_TYPE_U8,
};

static int link_attr_cb(const struct nlattr *attr, void *data)
{
    const struct nlattr **tb = data;
    int type = mnl_attr_get_type(attr);

    if (mnl_attr_type_valid(attr, IFLA_MAX) < 0)
	    return MNL_CB_OK;

    if (mnl_attr_validate(attr, link_policy[type]) < 0)
	    return MNL_CB_ERROR;

    tb[type] = attr;
    return MNL_CB_OK;
}

static int link_cb(const struct nlmsghdr *n, void *data)
{
    struct ifinfomsg *ifi = NLMSG_DATA(n);
    struct nlattr * tb[IFLA_MAX + 1] = { };
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

static const enum mnl_attr_data_type vlandb_policy[BRIDGE_VLANDB_ENTRY_MAX + 1] =
{
    [BRIDGE_VLANDB_ENTRY_INFO] = MNL_TYPE_BINARY,
    [BRIDGE_VLANDB_ENTRY_STATE] = MNL_TYPE_U8,
    [BRIDGE_VLANDB_ENTRY_RANGE] = MNL_TYPE_U16,
};

static int vlandb_entry_cb(const struct nlattr *attr, void *data)
{
    const struct nlattr **tb = data;
    int type = mnl_attr_get_type(attr);

    if (mnl_attr_type_valid(attr, BRIDGE_VLANDB_ENTRY_MAX) < 0)
	    return MNL_CB_OK;

    if (mnl_attr_validate(attr, vlandb_policy[type]) < 0)
	    return MNL_CB_ERROR;

    tb[type] = attr;
    return MNL_CB_OK;
}

static int vlan_cb(const struct nlmsghdr *n, void *data)
{
    struct br_vlan_msg *bvm = NLMSG_DATA(n);
    struct nlattr *attr;
    bool newvlan = n->nlmsg_type == RTM_NEWVLAN;

    INFO("%d: RTM_%sVLAN ", bvm->ifindex, newvlan ? "NEW" : "DEL");

    mnl_attr_for_each(attr, n, sizeof(*bvm))
    {
        struct nlattr *tb[BRIDGE_VLANDB_ENTRY_MAX +1];
        struct bridge_vlan_info *info = NULL;
        uint8_t state = VLAN_STATE_UNASSIGNED;
        uint16_t range = 0;
        uint16_t i;

        if (mnl_attr_get_type(attr) != BRIDGE_VLANDB_ENTRY)
            continue;

	mnl_attr_parse_nested(attr, vlandb_entry_cb, tb);

        if (tb[BRIDGE_VLANDB_ENTRY_INFO])
            info = mnl_attr_get_payload(tb[BRIDGE_VLANDB_ENTRY_INFO]);
        if (tb[BRIDGE_VLANDB_ENTRY_STATE])
            state = mnl_attr_get_u8(tb[BRIDGE_VLANDB_ENTRY_STATE]);
        if (tb[BRIDGE_VLANDB_ENTRY_RANGE])
            range = mnl_attr_get_u16(tb[BRIDGE_VLANDB_ENTRY_RANGE]);

        if (!info)
            continue;

        if (!range)
            range = info->vid;

    	INFO("%d %i-%i: %i", bvm->ifindex, info->vid, range, state);

        for (i = info->vid; i <= range; i++)
            vlan_notify(bvm->ifindex, newvlan, i, state);
    }

    return 0;
}

struct vlan_dump_table {
    int if_index;
    uint8_t *table;
};

static int vlan_table_cb(const struct nlmsghdr *n, void *data)
{
    struct br_vlan_msg *bvm = NLMSG_DATA(n);
    struct nlattr *attr;
    sysdep_if_data_t *if_data = data;

    if (bvm->ifindex != if_data->if_index)
            return 0;

    INFO("%d", bvm->ifindex);

    mnl_attr_for_each(attr, n, sizeof(*bvm))
    {
        struct nlattr *tb[BRIDGE_VLANDB_ENTRY_MAX +1];
        struct bridge_vlan_info *info = NULL;
        uint8_t state = VLAN_STATE_UNASSIGNED;
        uint16_t range = 0;
        uint16_t i;

        if (mnl_attr_get_type(attr) != BRIDGE_VLANDB_ENTRY)
            continue;

	mnl_attr_parse_nested(attr, vlandb_entry_cb, tb);

        if (tb[BRIDGE_VLANDB_ENTRY_INFO])
            info = mnl_attr_get_payload(tb[BRIDGE_VLANDB_ENTRY_INFO]);
        if (tb[BRIDGE_VLANDB_ENTRY_STATE])
            state = mnl_attr_get_u8(tb[BRIDGE_VLANDB_ENTRY_STATE]);
        if (tb[BRIDGE_VLANDB_ENTRY_RANGE])
            range = mnl_attr_get_u16(tb[BRIDGE_VLANDB_ENTRY_RANGE]);

        if (!info)
            continue;

        if (!range)
            range = info->vid;

    	INFO("%d %i-%i: %i", bvm->ifindex, info->vid, range, state);

        for (i = info->vid; i <= range; i++)
            if_data->vlan_state[i] = state;
    }

    return 0;
}

static int msg_cb(const struct nlmsghdr *n, void *data)
{
    switch (n->nlmsg_type)
    {
        case RTM_NEWLINK:
        case RTM_DELLINK:
            return link_cb(n, data);
        case RTM_NEWVLAN:
        case RTM_DELVLAN:
            return vlan_cb(n, data);
        default:
            return 0;
    }
}

int fill_vlan_table(sysdep_if_data_t *if_data)
{
    char buf[MNL_SOCKET_DUMP_SIZE];
    unsigned int seq, portid;
    struct nlmsghdr *nlh;
    int ret;
    struct br_vlan_msg *bvm;

    if(!have_per_vlan_state)
        return 0;

    nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = RTM_GETVLAN;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_seq = seq = time(NULL);

    bvm = mnl_nlmsg_put_extra_header(nlh, sizeof(*bvm));
    bvm->family = PF_BRIDGE;

    portid = mnl_socket_get_portid(mnl_state);

    ret = mnl_socket_sendto(mnl_state, nlh, nlh->nlmsg_len);
    if (ret < 0)
    {
        ERROR("Cannot send dump request: %m");
	return -1;
    }

    ret = mnl_socket_recvfrom(mnl_state, buf, sizeof(buf));
    while (ret > 0)
    {
    /* For unknown reason setting ifindex to non-zero will cause the kernel
     * to flood us with the same message over and over again, so filter
     * within mstpd for now */
        ret = mnl_cb_run(buf, ret, seq, portid, vlan_table_cb, if_data);
	if (ret <= MNL_CB_STOP)
		break;

	ret = mnl_socket_recvfrom(mnl_state, buf, sizeof(buf));
    }

    if (ret == -1)
    {
        ERROR("Failed receiving dump request: %m");
	return -1;
    }

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
        ret = mnl_cb_run(buf, ret, 0, 0, msg_cb, NULL);
	if (ret <= MNL_CB_STOP)
		break;

	ret = mnl_socket_recvfrom(mnl, buf, sizeof(buf));
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
	if (ret <= MNL_CB_STOP)
		break;

	ret = mnl_socket_recvfrom(mnl, buf, sizeof(buf));
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
    unsigned int group = RTNLGRP_BRVLAN;
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

    if(mnl_socket_setsockopt(mnl, NETLINK_ADD_MEMBERSHIP, &group, sizeof(&group)) < 0)
    {
        ERROR("Couldn't join RTNLGRP_BRVLAN, per vlan STP state not available\n");
        have_per_vlan_state = 0;
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
    if(br_linkdump(mnl, PF_BRIDGE) < 0)
    {
        ERROR("Cannot send dump request: %m");
        return -1;
    }

    fd = mnl_socket_get_fd(mnl);
    state_seq = time(NULL);

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
