#ifndef MYFWAPI_H
#define MYFWAPI_H

#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/socket.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <fstream> 
#include <iostream> 
using namespace std;

#define NETLINK_TEST (25)
#define MAX_PAYLOAD (1024)
#define TEST_PID (100)
#define TCP 6
#define UDP 17
#define ICMP 1
#define ANY -1
#define MAX_RULE_NUM 50
#define MAX_STATU_NUM 101
#define MAX_NAT_NUM 100
#define MAX_LOG_NUM 1000

bool ac_or_drop = false;

typedef struct {
    char src_ip[20];
    char dst_ip[20];
    int src_port;
    int dst_port;
    char protocol;
    bool action;
    bool log;
}Rule;
static Rule rules[MAX_RULE_NUM];
static int rnum = 0; //rules num

typedef struct {
    unsigned src_ip;
    unsigned short src_port;
    unsigned dst_ip;
    unsigned short dst_port;
    unsigned char protocol;
    unsigned long t;
}Connection;
static Connection cons[MAX_STATU_NUM];
static int cnum = 0;

typedef struct {
    //unsigned firewall_ip;
    unsigned nat_ip;
    unsigned short firewall_port;
    unsigned short nat_port;
}NatEntry;
static NatEntry natTable[MAX_NAT_NUM];
static int nnum = 0; //nat rules num
unsigned net_ip = 0, net_mask = 0, firewall_ip = 0;

typedef struct {
    unsigned src_ip;
    unsigned dst_ip;
    unsigned short src_port;
    unsigned short dst_port;
    unsigned char protocol;
    unsigned char action;
}Log;
static Log logs[MAX_LOG_NUM];
static int lnum = 0;//logs num

/*----------------------------------------------------------------------------------------------------------------*/
unsigned ipstr_to_num(const char *ip_str){
    int count = 0;
    unsigned tmp = 0,ip = 0, i;
    for(i = 0; i < strlen(ip_str); i++){
        if(ip_str[i] == '.'){
            ip = ip | (tmp << (8 * (3 - count)));
            tmp = 0;
            count++;
            continue;
        }
        tmp *= 10;
        tmp += ip_str[i] - '0';
    }
    ip = ip | tmp;
    return ip;
}

char * addr_from_net(char * buff, __be32 addr){
    __u8 *p = (__u8*)&addr;
    snprintf(buff, 16, "%u.%u.%u.%u",
        (__u32)p[0], (__u32)p[1], (__u32)p[2], (__u32)p[3]);
    return buff;
}

void Convert(unsigned &ip, unsigned &mask, const char *ip_range){
    char tmp_ip[20];
    int p = -1, count = 0;
    unsigned len = 0, tmp = 0, i;
    ip = 0, mask = 0;
    strcpy(tmp_ip, ip_range);
    for(i = 0; i < strlen(tmp_ip); i++){
        if(p != -1){
            len *= 10;
            len += tmp_ip[i] - '0';
        }
        else if(tmp_ip[i] == '/')
            p = i;
    }
    if(p != -1){
        tmp_ip[p] = '\0';
		if(len)
	        mask = 0xFFFFFFFF << (32 - len);
    }
    else mask = 0xFFFFFFFF;
    for(i = 0; i < strlen(tmp_ip); i++){
        if(tmp_ip[i] == '.'){
            ip = ip | (tmp << (8 * (3 - count)));
            tmp = 0;
            count++;
            continue;
        }
        tmp *= 10;
        tmp += tmp_ip[i] - '0';
    }
    ip = ip | tmp;
}
/*----------------------------------------------------------------------------------------------------------------*/
int netlink_create_socket(void)
{
    //create a socket
    return socket(AF_NETLINK, SOCK_RAW, NETLINK_TEST);
}

int netlink_bind(int sock_fd)
{
    struct sockaddr_nl addr;
    memset(&addr, 0, sizeof(struct sockaddr_nl));
    addr.nl_family = AF_NETLINK;
    addr.nl_pid = TEST_PID;
    addr.nl_groups = 0;
    return bind(sock_fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_nl));
}

int netlink_send_message(int sock_fd, const unsigned char *message, int len,unsigned int pid, unsigned int group)
{
    struct nlmsghdr *nlh = NULL;
    struct sockaddr_nl dest_addr;
    struct iovec iov;
    struct msghdr msg;
    if( !message ) {
        return -1;
    }
    //create message
    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(len));
    if( !nlh ) {
        perror("malloc");
        return -2;
    }
    nlh->nlmsg_len = NLMSG_SPACE(len);
    nlh->nlmsg_pid = TEST_PID;
    nlh->nlmsg_flags = 0;
    memcpy(NLMSG_DATA(nlh), message, len);
    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;
    memset(&dest_addr, 0, sizeof(struct sockaddr_nl));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = pid;
    dest_addr.nl_groups = group;
    memset(&msg, 0, sizeof(struct msghdr));
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(struct sockaddr_nl);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    //send message
    if( sendmsg(sock_fd, &msg, 0) < 0 )
    {
        printf("send error!\n");
        free(nlh);
        return -3;
    }
    free(nlh);
    return 0;
}

int netlink_recv_message(int sock_fd, unsigned char *message, int *len)
{
    struct nlmsghdr *nlh = NULL;
    struct sockaddr_nl source_addr;
    struct iovec iov;
    struct msghdr msg;
    if( !message || !len ) {
        return -1;
    }
    //create message
    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    if( !nlh ) {
        perror("malloc");
        return -2;
    }
    iov.iov_base = (void *)nlh;
    iov.iov_len = NLMSG_SPACE(MAX_PAYLOAD);
    memset(&source_addr, 0, sizeof(struct sockaddr_nl));
    memset(&msg, 0, sizeof(struct msghdr));
    msg.msg_name = (void *)&source_addr;
    msg.msg_namelen = sizeof(struct sockaddr_nl);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    if ( recvmsg(sock_fd, &msg, 0) < 0 ) {
        printf("recvmsg error!\n");
        return -3;
    }
    *len = nlh->nlmsg_len - NLMSG_SPACE(0);
    memcpy(message, (unsigned char *)NLMSG_DATA(nlh), *len);
    free(nlh);
    return 0;
}

/*------------------------------Rules-------------------------------*/
bool AddRule(
	const char *src_ip, const char *dst_ip,
	int src_port,
	int dst_port,
	char protocol,
	bool action, bool log) {
	if (rnum < 100) {
		strcpy(rules[rnum].src_ip, src_ip);
		strcpy(rules[rnum].dst_ip, dst_ip);
		rules[rnum].src_port = src_port;
		rules[rnum].dst_port = dst_port;
		rules[rnum].protocol = protocol;
		rules[rnum].action = action;
		rules[rnum].log = log;
		rnum++;
		return true;
	}
	return false;
}

bool DelRule(int pos) {
	if (pos >= rnum || pos < 0)
		return false;
	memcpy(rules + pos, rules + pos + 1, sizeof(Rule) * (rnum - pos));
	rnum--;
	return true;
}

int SendRules()
{
	if (ac_or_drop) {
		AddRule("any", "any", -1, -1, -1, 1, 0);
	}
	else AddRule("any", "any", -1, -1, -1, 0, 0);
    int sock_fd;
    unsigned char buf[MAX_PAYLOAD];
    unsigned char a[5000];
    int len;
    sock_fd = netlink_create_socket();
    if(sock_fd == -1) {
        printf("socket error!\n");
        return -1;
    }
    if( netlink_bind(sock_fd) < 0 ) {
        perror("bind");
        close(sock_fd);
        exit(EXIT_FAILURE);
    }
    a[0] = 0;
    a[1] = rnum;
    memcpy(a + 2, rules, rnum * sizeof(Rule));
    netlink_send_message(sock_fd, (const unsigned char *)a, rnum * sizeof(Rule) + 2, 0, 0);
    close(sock_fd);
	rnum--;
    return 1;
}

void SetDefault(bool flag) {
	ac_or_drop = flag;
}

/*----------------------------NAT RULES-----------------------------*/
int SendNatRules()
{
    int sock_fd;
    unsigned char a[5000];
    sock_fd = netlink_create_socket();
    if(sock_fd == -1) {
        printf("socket error!\n");
        return -1;
    }
    if( netlink_bind(sock_fd) < 0 ) {
        perror("bind");
        close(sock_fd);
        exit(EXIT_FAILURE);
    }
    a[0] = 1;
    a[1] = nnum;
    memcpy(a + 2, &net_ip, sizeof(unsigned));
    memcpy(a + 6, &net_mask, sizeof(unsigned));
    memcpy(a + 10, &firewall_ip, sizeof(unsigned));
    memcpy(a + 14, natTable, nnum * sizeof(NatEntry));
    netlink_send_message(sock_fd, (const unsigned char *)a, nnum * sizeof(NatEntry) + 14, 0, 0);
    close(sock_fd);
    return 1;
}

bool AddNatRule(unsigned nat_ip, unsigned short nat_port, unsigned short firewall_port){
    if(nnum < 100){
        natTable[nnum].nat_ip = nat_ip;
        //natTable[nnum].firewall_ip = firewall_ip;
        natTable[nnum].nat_port = nat_port;
        natTable[nnum].firewall_port = firewall_port;
        nnum++;
        return true;
    }
    return false;
}

bool DelNatRule(int pos){
    if(pos >= nnum || pos < 0)
        return false;
    memcpy(rules + pos, rules + pos + 1, sizeof(Rule) * (nnum - pos));
    nnum--;
    return true;
}

void SetNat(unsigned net, unsigned mask, unsigned ip){
    firewall_ip = ip;
    net_ip = net;
    net_mask = mask;
}

/*--------------------------------------Log-------------------------------------*/
int GetLogs()
{
    int sock_fd;
    //unsigned char buf[MAX_PAYLOAD];
    unsigned char a[100];
    unsigned char buf[1000 * sizeof(Log)];
    int len;
    sock_fd = netlink_create_socket();
    if(sock_fd == -1) {
        printf("socket error!\n");
        return -1;
    }
    if( netlink_bind(sock_fd) < 0 ) {
        perror("bind");
        close(sock_fd);
        exit(EXIT_FAILURE);
    }
    a[0] = 2;
    netlink_send_message(sock_fd, (const unsigned char *)a, 2, 0, 0);
    if( netlink_recv_message(sock_fd, buf, &len) == 0 ) {
        printf("recvlen:%d\n",len);
        memcpy(logs, buf, len);
        lnum = len / sizeof(Log);
    }
    close(sock_fd);
    return 1;
}

/*---------------------------------------Statu list-------------------------------------*/
int GetConnections()
{
    int sock_fd;
    //unsigned char buf[MAX_PAYLOAD];
    unsigned char a[100];
    unsigned char buf[101 * sizeof(Connection)];
    int len;
    sock_fd = netlink_create_socket();
    if(sock_fd == -1) {
        printf("socket error!\n");
        return -1;
    }
    if( netlink_bind(sock_fd) < 0 ) {
        perror("bind");
        close(sock_fd);
        exit(EXIT_FAILURE);
    }
    a[0] = 3;
    netlink_send_message(sock_fd, (const unsigned char *)a, 1, 0, 0);
    if( netlink_recv_message(sock_fd, buf, &len) == 0 ) {
        printf("recvlen:%d\n",len);
        memcpy(cons, buf, len);
        cnum = len / sizeof(Connection);
    }
    close(sock_fd);
    return 1;
}

#endif // MYFWAPI_H
