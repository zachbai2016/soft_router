#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <string.h>
#include <strings.h>

#include <pthread.h>

#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <netinet/ether.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <net/if_arp.h>

#include <mysql/mysql.h>

#include <strings.h>

extern void dequeue(int type, void *queue, void *data);

uint32_t ip_38 = 0, ip_39 = 0;

uint32_t subnet_ip_38 = 0, subnet_ip_39 = 0;
unsigned char subnet_ens38[16] = "", subnet_ens39[16] = "";

void prepare_ens38(int sockfd)
{
    struct ifreq ifr;
    struct sockaddr_in *addr;

    strcpy(ifr.ifr_name, "ens38"); // 替换为你的网络接口名

    // todo 1 子网掩码
    if (ioctl(sockfd, SIOCGIFNETMASK, &ifr) < 0)
    {
        perror("ioctl");
        close(sockfd);
        return;
    }
    addr = (struct sockaddr_in *)&(ifr.ifr_netmask);
    unsigned char netmask[16] = "";
    struct in_addr netmaskaddr;
    netmaskaddr.s_addr = addr->sin_addr.s_addr;
    strcpy((char *)netmask, inet_ntoa(addr->sin_addr));
    printf("netmask: %s\n", netmask);
    // unsigned char *netmast_arr[32] = {netmask};

    // todo 2 获取IP
    if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0)
    {
        perror("ioctl");
        close(sockfd);
        return;
    }
    addr = (struct sockaddr_in *)&(ifr.ifr_addr);
    unsigned char localip[16] = "";
    struct in_addr localaddr;
    localaddr.s_addr = addr->sin_addr.s_addr;
    strcpy((char *)localip, inet_ntoa(addr->sin_addr));
    printf("localip: %s\n", localip);
    // unsigned char *localip_arr[32] = {localip};

    struct in_addr subnetaddr;
    subnetaddr.s_addr = localaddr.s_addr & netmaskaddr.s_addr;
    inet_ntop(AF_INET, (struct sockaddr_in *)&subnetaddr, (char *)subnet_ens38, 16);
    printf("subnet_ens38: %s\n", subnet_ens38);
    subnet_ip_38 = ntohl(inet_addr((char *)subnet_ens38));
    printf("subnet_ip_38:%#08x\n", subnet_ip_38);
}

void prepare_ens39(int sockfd)
{
    struct ifreq ifr;
    struct sockaddr_in *addr;

    strcpy(ifr.ifr_name, "ens39"); // 替换为你的网络接口名

    // todo 1 子网掩码
    if (ioctl(sockfd, SIOCGIFNETMASK, &ifr) < 0)
    {
        perror("ioctl");
        close(sockfd);
        return;
    }
    addr = (struct sockaddr_in *)&(ifr.ifr_netmask);
    unsigned char netmask[16] = "";
    struct in_addr netmaskaddr;
    netmaskaddr.s_addr = addr->sin_addr.s_addr;
    strcpy((char *)netmask, inet_ntoa(addr->sin_addr));
    printf("netmask: %s\n", netmask);

    // todo 2 获取IP
    if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0)
    {
        perror("ioctl");
        close(sockfd);
        return;
    }
    addr = (struct sockaddr_in *)&(ifr.ifr_addr);
    unsigned char localip[16] = "";
    struct in_addr localaddr;
    localaddr.s_addr = addr->sin_addr.s_addr;
    strcpy((char *)localip, inet_ntoa(addr->sin_addr));
    printf("localip: %s\n", localip);
    // unsigned char *localip_arr[32] = {localip};

    struct in_addr subnetaddr;
    subnetaddr.s_addr = localaddr.s_addr & netmaskaddr.s_addr;
    inet_ntop(AF_INET, (struct sockaddr_in *)&subnetaddr, (char *)subnet_ens39, 16);
    printf("subnet_ens39: %s\n", subnet_ens39);
    subnet_ip_39 = ntohl(inet_addr((char *)subnet_ens39));
    printf("subnet_ip_39:%#08x\n", subnet_ip_39);
}

// a. 定义一个 结构体 封装 ICMP
typedef struct icmp_t
{
    struct ether_header eth_h;
    struct iphdr ip_h;
    struct icmphdr icmp_h;
} ICMP_PDU;

typedef struct icmp2_t
{
    uint8_t *p_icmp_e; // 指向 icmp 完整报文的指针
} ICMP_PDU2;

// b.定义一个结构体 封装 ARP 报文
typedef struct arp_t
{
    struct ether_header eth_h;
    uint16_t hd_type;
    uint16_t sp_type;
    uint8_t hd_len;
    uint8_t sp_len;
    uint16_t op_code;
    uint8_t dst_mac[6];
    uint32_t src_ip;
    uint8_t src_mac[6];
    uint32_t dst_ip;
} ARP_PDU;

typedef struct arp2_t
{
    uint8_t *p_arp_e; // 指向 arp完整报文的指针
} ARP_PDU2;

// 队列
#define MAX_QUEUE_SIZE 1024

// A. 定义一个 ICMP 队列
typedef struct
{
    ICMP_PDU2 icmps[MAX_QUEUE_SIZE];
    uint32_t head;
    uint32_t tail;
    uint32_t size;
    pthread_mutex_t mutex;
    pthread_cond_t queue_not_empty;
    pthread_cond_t queue_not_full;
} ICMPBlockingQueue;

typedef struct
{
    int icmp_size_arr[MAX_QUEUE_SIZE];
    uint32_t head;
    uint32_t tail;
    uint32_t size;
    pthread_mutex_t mutex;
    pthread_cond_t queue_not_empty;
    pthread_cond_t queue_not_full;
} ICMPSizeBlockingQueue;

// B. 定义一个 ARP 队列
typedef struct
{
    ARP_PDU2 arps[MAX_QUEUE_SIZE];
    uint32_t head;
    uint32_t tail;
    uint32_t size;
    pthread_mutex_t mutex;
    pthread_cond_t queue_not_empty;
    pthread_cond_t queue_not_full;
} ARPBlockingQueue;

struct recv_task_param
{
    int sockfd;
    ARPBlockingQueue *arpQueue;
    ICMPBlockingQueue *icmpQueue;
    ICMPSizeBlockingQueue *icmpSizeQueue;
};

void initARPBlockingQueue(ARPBlockingQueue *queue)
{
    for (int i = 0; i < MAX_QUEUE_SIZE; i++)
    {
        queue->arps[i].p_arp_e = NULL;
    }
    queue->head = 0;
    queue->tail = 0;
    queue->size = 0;
    pthread_mutex_init(&queue->mutex, NULL);
    pthread_cond_init(&queue->queue_not_empty, NULL);
    pthread_cond_init(&queue->queue_not_full, NULL);
}

void initICMPSizeBlockingQueue(ICMPSizeBlockingQueue *queue)
{
    memset(queue->icmp_size_arr, 0, sizeof(uint32_t) * MAX_QUEUE_SIZE);
    queue->head = 0;
    queue->tail = 0;
    queue->size = 0;
    pthread_mutex_init(&queue->mutex, NULL);
    pthread_cond_init(&queue->queue_not_empty, NULL);
    pthread_cond_init(&queue->queue_not_full, NULL);
}

void output_ip(uint32_t ip)
{
    char src_ip[16] = "";
    inet_ntop(AF_INET, (void *)&ip, src_ip, 16);
    printf("src_ip=%s\n", src_ip);
}

void output_mac(uint8_t *host)
{
    for (int i = 0; i < ETH_ALEN; i++)
    {
        printf("%02x", host[i]);
        if (i < 5)
        {
            printf(":");
        }
    }
    printf("\n");
}

void out_put_eth_h(unsigned char *buf)
{
    unsigned short type = ntohs(*(unsigned short *)(buf + 12));
    // dst src typ
    printf("#ETH#");
    printf("%02x:%02x:%02x:%02x:%02x:%02x\t%02x:%02x:%02x:%02x:%02x:%02x  %#02x\n",
           buf[0], buf[1], buf[2], buf[3], buf[4], buf[5],
           buf[6], buf[7], buf[8], buf[9], buf[10], buf[11],
           type);
}

void out_put_ip_h(unsigned char *buf)
{

    // 1. 4B
    uint8_t ipv = (buf[14] >> 4) & 0x0F;
    uint8_t hd_len = buf[14] & 0x0F; // 首部长度
    uint8_t tos = buf[15];
    uint16_t tot_len = ntohs(*(uint16_t *)(buf + 16));

    // 2. 4B
    uint16_t flag = ntohs(*(uint16_t *)(buf + 18));
    uint8_t flag2 = (buf[20] >> 5) & 0x07;
    uint16_t frag_off = buf[20] & 0xFC;

    // 3. 4B
    uint8_t ttl = buf[22];
    uint8_t prot_type = buf[23];
    uint16_t hd_chk_sum = ntohs(*(uint16_t *)(buf + 24));

    char srcip[16] = "";
    char dstip[16] = "";
    // 4. 8B
    inet_ntop(AF_INET, buf + 26, srcip, 16);
    inet_ntop(AF_INET, buf + 30, dstip, 16);

    printf("#IP#%02x  %02x  %02x  %hd\n", ipv, hd_len, tos, tot_len);
    printf("#IP#%hu  %01x  %hd\n", flag, flag2, frag_off);
    printf("#IP#%hhd  %01x  %hu\n", ttl, prot_type, hd_chk_sum);
    printf("#IP#%s\n", srcip);
    printf("#IP#%s\n", dstip);

    // unsigned short type = ntohs(*(unsigned short *)(buf + 12));
    if (0x05 == hd_len)
    {
        printf("#IP#无选项\n");
    }
    else if (0x05 < hd_len)
    {
        printf("#IP#有选项\n");
    }
}

void out_put_icmp_h(unsigned char *buf)
{
    u_int8_t icmp_type = buf[34];
    u_int8_t icmp_code = buf[35];
    printf("#ICMP#%#02x %#02x\n", icmp_type, icmp_code);
}

void enqueue(uint32_t type, void *queue, void *data)
{
    if (ETHERTYPE_ARP == type)
    {
        ARPBlockingQueue *arp_queue = (ARPBlockingQueue *)queue;
        // uint8_t *p_arp_data = (uint8_t *)data;

        pthread_mutex_lock(&arp_queue->mutex);
        // printf("enqueue arp before: size=%d head=%d tail=%d\n", arp_queue->size, arp_queue->head, arp_queue->tail);
        while (arp_queue->size == MAX_QUEUE_SIZE)
        {
            // printf("arp_queue full, blocking ... \n");
            pthread_cond_wait(&arp_queue->queue_not_full, &arp_queue->mutex);
        }
        arp_queue->arps[arp_queue->tail].p_arp_e = (uint8_t *)data; // 指向堆内存
        arp_queue->tail = (arp_queue->tail + 1) % MAX_QUEUE_SIZE;
        arp_queue->size = (arp_queue->size + 1);
        // printf("enqueue arp after: size=%d head=%d tail=%d\n", arp_queue->size, arp_queue->head, arp_queue->tail);
        pthread_cond_signal(&arp_queue->queue_not_empty);
        pthread_mutex_unlock(&arp_queue->mutex);
    }
    else if (0x080001 == type)
    {
        ICMPBlockingQueue *icmp_queue = (ICMPBlockingQueue *)queue;

        // ICMP_PDU2 *icmp_e = (ICMP_PDU2 *)data;

        pthread_mutex_lock(&icmp_queue->mutex);
        // printf("enqueue icmp before: size=%d head=%d tail=%d\n", icmp_queue->size, icmp_queue->head, icmp_queue->tail);
        while (icmp_queue->size == MAX_QUEUE_SIZE)
        {
            // printf("icmp_queue full, blocking ... \n");
            pthread_cond_wait(&icmp_queue->queue_not_full, &icmp_queue->mutex);
        }
        // 内存中的数据
        // memcpy(&icmp_queue->icmps[icmp_queue->tail], p_icmp_data, sizeof(ICMP_PDU));
        icmp_queue->icmps[icmp_queue->tail].p_icmp_e = (uint8_t *)data;
        icmp_queue->tail = (icmp_queue->tail + 1) % MAX_QUEUE_SIZE;
        icmp_queue->size = (icmp_queue->size + 1);
        // printf("enqueue icmp after: size=%d head=%d tail=%d\n\n", icmp_queue->size, icmp_queue->head, icmp_queue->tail);
        pthread_cond_signal(&icmp_queue->queue_not_empty);
        pthread_mutex_unlock(&icmp_queue->mutex);
    }
    else if (0x08000199 == type)
    {
        ICMPSizeBlockingQueue *icmpSizeQueue = (ICMPSizeBlockingQueue *)queue;

        // ICMP_PDU2 *icmp_e = (ICMP_PDU2 *)data;

        pthread_mutex_lock(&icmpSizeQueue->mutex);
        // printf("enqueue icmp before: size=%d head=%d tail=%d\n", icmpSizeQueue->size, icmpSizeQueue->head, icmpSizeQueue->tail);
        while (icmpSizeQueue->size == MAX_QUEUE_SIZE)
        {
            // printf("icmpSizeQueue full, blocking ... \n");
            pthread_cond_wait(&icmpSizeQueue->queue_not_full, &icmpSizeQueue->mutex);
        }
        // 内存中的数据
        // memcpy(&icmpSizeQueue->icmps[icmpSizeQueue->tail], p_icmp_data, sizeof(ICMP_PDU));
        icmpSizeQueue->icmp_size_arr[icmpSizeQueue->tail] = *(int *)data;
        icmpSizeQueue->tail = (icmpSizeQueue->tail + 1) % MAX_QUEUE_SIZE;
        icmpSizeQueue->size = (icmpSizeQueue->size + 1);
        // printf("enqueue icmp after: size=%d head=%d tail=%d\n\n", icmpSizeQueue->size, icmpSizeQueue->head, icmpSizeQueue->tail);
        pthread_cond_signal(&icmpSizeQueue->queue_not_empty);
        pthread_mutex_unlock(&icmpSizeQueue->mutex);
    }
}

void dequeue(int type, void *queue, void *data)
{
    if (0x0806 == type)
    {
        ARPBlockingQueue *arpQueue = (ARPBlockingQueue *)queue;
        pthread_mutex_lock(&arpQueue->mutex);
        // printf("dequeue arp defore: size=%d head=%d tail=%d\n", arpQueue->size, arpQueue->head, arpQueue->tail);
        // printf("\t##1. dequeue arp data:%p## \n", ((ARP_PDU2 *)data)->p_arp_e);
        while (arpQueue->size == 0)
        {
            // printf("dequeue: arpQueue empty, block ... \n");
            pthread_cond_wait(&arpQueue->queue_not_empty, &arpQueue->mutex);
        }
        // memcpy(data, &arpQueue->arps[arpQueue->head], sizeof(arpQueue->arps[arpQueue->head]));
        ((ARP_PDU2 *)data)->p_arp_e = arpQueue->arps[arpQueue->head].p_arp_e;
        // printf("\t##2. dequeue arp data:%p## \n", ((ARP_PDU2 *)data)->p_arp_e);
        arpQueue->head = (arpQueue->head + 1) % MAX_QUEUE_SIZE;
        arpQueue->size = arpQueue->size - 1;
        // printf("dequeue arp after: size=%d head=%d tail=%d\n", arpQueue->size, arpQueue->head, arpQueue->tail);
        pthread_cond_signal(&arpQueue->queue_not_full);
        pthread_mutex_unlock(&arpQueue->mutex);
    }
    else if (0x080001 == type)
    {
        ICMPBlockingQueue *icmp_queue = (ICMPBlockingQueue *)queue;
        pthread_mutex_lock(&icmp_queue->mutex);
        //  printf("dequeue icmp defore: size=%d head=%d tail=%d\n", icmp_queue->size, icmp_queue->head, icmp_queue->tail);
        // printf("\t\t##1. dequeue icmp data:%p## \n", ((ICMP_PDU2 *)data)->p_icmp_e);
        while (icmp_queue->size == 0)
        {
            // printf("dequeue: icmp_queue empty, block ... \n");
            pthread_cond_wait(&icmp_queue->queue_not_empty, &icmp_queue->mutex);
        }
        // memcmp(data, &icmp_queue->icmps[icmp_queue->head], sizeof(icmp_queue->icmps[icmp_queue->head]));
        ((ICMP_PDU2 *)data)->p_icmp_e = icmp_queue->icmps[icmp_queue->head].p_icmp_e;
        // printf("\t\t##2. dequeue icmp data:%p## \n", ((ICMP_PDU2 *)data)->p_icmp_e);
        icmp_queue->head = (icmp_queue->head + 1) % MAX_QUEUE_SIZE;
        icmp_queue->size = icmp_queue->size - 1;
        //  printf("dequeue icmp after: size=%d head=%d tail=%d\n\n", icmp_queue->size, icmp_queue->head, icmp_queue->tail);
        pthread_cond_signal(&icmp_queue->queue_not_full);
        pthread_mutex_unlock(&icmp_queue->mutex);
    }
    else if (0x08000199 == type)
    {
        ICMPSizeBlockingQueue *icmpSizeQueue = (ICMPSizeBlockingQueue *)queue;
        pthread_mutex_lock(&icmpSizeQueue->mutex);
        //  printf("dequeue icmp defore: size=%d head=%d tail=%d\n", icmpSizeQueue->size, icmpSizeQueue->head, icmpSizeQueue->tail);
        // printf("\t\t##1. dequeue icmp data:%p## \n", ((ICMP_PDU2 *)data)->p_icmp_e);
        while (icmpSizeQueue->size == 0)
        {
            // printf("dequeue: icmpSizeQueue empty, block ... \n");
            pthread_cond_wait(&icmpSizeQueue->queue_not_empty, &icmpSizeQueue->mutex);
        }
        // memcmp(data, &icmpSizeQueue->icmps[icmpSizeQueue->head], sizeof(icmpSizeQueue->icmps[icmpSizeQueue->head]));
        *(int *)data = icmpSizeQueue->icmp_size_arr[icmpSizeQueue->head];
        // printf("\t\t##2. dequeue icmp data:%p## \n", ((ICMP_PDU2 *)data)->p_icmp_e);
        icmpSizeQueue->head = (icmpSizeQueue->head + 1) % MAX_QUEUE_SIZE;
        icmpSizeQueue->size = icmpSizeQueue->size - 1;
        //  printf("dequeue icmp after: size=%d head=%d tail=%d\n\n", icmpSizeQueue->size, icmpSizeQueue->head, icmpSizeQueue->tail);
        pthread_cond_signal(&icmpSizeQueue->queue_not_full);
        pthread_mutex_unlock(&icmpSizeQueue->mutex);
    }
}

uint8_t is_broadcast_mac(uint8_t *mac)
{
    printf("1. is_broadcast_mac\n");
    output_mac(mac);
    printf("2. is_broadcast_mac\n");

    int i;
    for (i = 0; i < 6; i++)
    {
        if (0xFF == mac[i])
        {
            continue;
        }
        else
        {
            break;
        }
    }

    return i == 6;
}

uint8_t is_ens38_ip(uint8_t *p_data)
{
    uint32_t dstip = ntohl(*(uint32_t *)(p_data + 38));
    printf("dstip:%u\n", dstip);
    printf("ip_38:%u\n", ip_38);
    return dstip == ip_38;
}

uint8_t is_ens39_ip(uint8_t *p_data)
{
    uint32_t dstip = ntohl(*(uint32_t *)(p_data + 38));
    printf("dstip:%u\n", dstip);
    printf("ip_39:%u\n", ip_39);
    return dstip == ip_39;
}

void *on_arp_task(void *arg)
{

    printf("\033[%dm", 31);
    fflush(stdout);

    struct recv_task_param *rt_param = (struct recv_task_param *)arg;
    // int sockfd = rt_param->sockfd;
    ARPBlockingQueue *arpQueue = rt_param->arpQueue;
    // printf("on_arp_task: %p\n", arpQueue);
    ARP_PDU2 arp_data;
    uint8_t *p_data = NULL;
    bzero(&arp_data, sizeof(ARP_PDU2));

    // 分析 ARP 数据头
    // unsigned short op_code = 0;
    char src_ip[16] = "";
    char dst_ip[16] = "";
    uint8_t src_mac_arr[ETH_ALEN];
    uint8_t dst_mac_arr[ETH_ALEN];

    // sql used
    uint32_t ip = 0;
    char src_mac[32] = "";
    // char dst_mac[32] = "";

    MYSQL *sqlconnect;
    MYSQL sql;
    // 创建mysql 连接
    mysql_init(&sql);

    sqlconnect = mysql_real_connect(&sql, "0.0.0.0", "root", "111111", "wlw2401", 3306, NULL, 0);

    if (sqlconnect == NULL)
    {
        printf("connect error\n");
        return NULL;
    }

    // 判断 网关MAC 用的
    uint8_t ip38_arr[4] = {192, 168, 199, 1};
    uint8_t ip39_arr[4] = {192, 168, 200, 1};
    uint32_t ip_38_ = ntohl(*(uint32_t *)ip38_arr);
    ip_38 = ip_38_;

    uint32_t ip_39_ = ntohl(*(uint32_t *)ip39_arr);
    ip_39 = ip_39_;

    // 原始套接字 需要指定网卡信息
    // struct sockaddr_ll sll;

    // printf("ip_38:%u\n", ip_38);
    // printf("ip_39:%u\n", ip_39);

#if 0
    // sockaddr
    // 根据网卡名字获取类型
    struct ifreq ethreq;
    strncpy(ethreq.ifr_name, , IFNAMSIZ);
    if (-1 == ioctl(sockfd, SIOCGIFINDEX, &ethreq))
    {
        perror("ioctl");
        close(sockfd);
        return -1;
    }

    bzero(&sll, sizeof(sll));
    sll.sll_ifindex = ethreq.ifr_ifindex; // 网络出口结构体

    // 自己的 ip 对应的网卡
    int send_size = sendto(sockfd, udpbuf, 14 + 20 + 8 + datalen, 0, (struct sockaddr *)&sll, sizeof(sll));
    printf("send_size=%d\n", send_size);

#endif

    while (1)
    {
        // printf("size: %d\n", arpQueue->size);
        bzero(&arp_data, sizeof(ARP_PDU2));
        dequeue(0x0806, arpQueue, &arp_data);
        p_data = arp_data.p_arp_e;
        // printf("\t##3: arp_data:%p \n", arp_data.p_arp_e);

        // todo arp_data.p_arp_e 就是 PDU
        // printf("\n");
        // out_put_eth_h(p_data);

        // unsigned short hd_type = ntohs(*(unsigned short *)(p_data + 14));
        // unsigned short proto_type_in_arp = ntohs(*(unsigned short *)(p_data + 16));
        // unsigned char hd_len = p_data[18];
        // unsigned char proto_len = p_data[19];
        unsigned short op_code = ntohs(*(unsigned short *)(p_data + 20));

        memcpy(src_mac_arr, p_data + 22, ETH_ALEN);
        inet_ntop(AF_INET, (void *)p_data + 28, src_ip, 16);

        memcpy(dst_mac_arr, p_data + 32, ETH_ALEN);
        inet_ntop(AF_INET, (void *)p_data + 38, dst_ip, 16);

#if 0
        printf("#ARP#:");
        printf("%02x %02x \n",
               hd_type, proto_type_in_arp);
        printf("#ARP#:");
        printf("%02x %02x %02x\n", hd_len, proto_len, op_code);

        // printf("src_mac_arr: ");
        printf("#ARP#:");
        output_mac(src_mac_arr);

        printf("#ARP#:");
        printf("%s\n", src_ip);
        printf("#ARP#:");
        output_mac(dst_mac_arr);
        printf("#ARP#:");
        printf("%s\n", dst_ip);
#endif

        // 将 arp 保存起来
        char insert_sql[512] = "";

        // uint8_t arr[] = {p_data[28], p_data[29], p_data[30], p_data[31]};

        // printf("%02x.%02x.%02x.%02x\n", p_data[28], p_data[29], p_data[30], p_data[31]);

        // printf("%8x %8x\n", *((uint32_t *)arr), ntohl(*((uint32_t *)arr)));

        ip = ntohl(*(uint32_t *)(p_data + 28)); // ip = ntohl(inet_addr(src_ip));
        // printf("ip=%u\n", ip);

        sprintf(src_mac, "%02x:%02x:%02x:%02x:%02x:%02x",
                src_mac_arr[0], src_mac_arr[1], src_mac_arr[2], src_mac_arr[3], src_mac_arr[4], src_mac_arr[5]);
        // printf("src_mac:%s size:%d\n", src_mac, strlen(src_mac));

        // SQL语句，使用INSERT INTO ... ON DUPLICATE KEY UPDATE 来实现主键重复时更新记录的功能
        sprintf(insert_sql,
                "INSERT INTO arp_t (ip, ip_str, mac_str) VALUES ('%u', '%s', '%s')  ON DUPLICATE KEY UPDATE ip='%u';",
                ip, src_ip, src_mac, ip);
        // printf("%s\n", insert_sql);

        if (mysql_real_query(sqlconnect, insert_sql, strlen(insert_sql)) != 0)
        {
            fprintf(stderr, "mysql_query() failed: %s\n", mysql_error(sqlconnect));
        }

        if (0x01 == op_code) // 如果一直往出发 就会一直收到自己的包
        {
            // todo 存储完之后 分析 目的MAC 是 全F 且
            // printf("分析是否回应这个 ARP 请求包\n");
#if 0
            // 如果 dstmac = f && dstip = ip_38
            uint8_t is_broadcast_addr = is_broadcast_mac(p_data);
            printf("is_broadcast_mac: %hhu\n", is_broadcast_addr);

            // 判断目的主机 是否是 自己的
            uint8_t is_ens38 = is_ens38_ip(p_data);
            printf("is_ens38:%hhu\n", is_ens38);

            uint8_t is_ens39 = is_ens39_ip(p_data);
            printf("is_ens39:%hhu\n", is_ens39);

            if (is_broadcast_addr && is_ens38)
            {
                // 应答 ARP 报文 走 39
            }
            else if (is_broadcast_addr && is_ens39)
            {
                // 应答 ARP 报文 走 39
            }
#endif
        }
        else if (0x02 == op_code)
        {
            printf("这是一个 ARP 应答包\n");
        }
        // printf("\n");
    }
    return NULL;
}

void send_arp(int sockfd, uint8_t *p_data, uint32_t subnet)
{
    // todo 拿到 目的IP 和 目的MAC

    // uint8_t dst_mac[6] = {0};
    uint8_t dst_ip[4] = {0};
    memcpy(dst_ip, p_data + 38, 4);

    unsigned char arpbuf[42] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, //         1.Dest MAC:目的MAC地址
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //         2.Src MAC：源MAC地址
        0x08, 0x06,                         //        3.帧类型：0x0806
        0x00, 0x01,                         //        4.硬件类型：1（以太网）
        0x08, 0x00,                         //         5.协议类型：0x0800（IP地址）
        0x06, 0x04,                         //         6.硬件地址长度：6        7.协议地址长度：4
        0x00, 0x01,                         //        8.OP：1（ARP请求），2（ARP应答），3（RARP请求），4（RARP应答）
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //   源 MAC
        192, 168, 199, 1,                   // 源IP 用真实的网关IP + 假的 网关MAC 向某一个主机 应答ARP
        0, 0, 0, 0, 0, 0,                   // target mac
        0, 0, 0, 0,                         // target ip
    };

    struct sockaddr_ll sll;
    struct ifreq ethreq;
    if (subnet == subnet_ip_38)
    {
        /* via ens38 to 192.168.199.0 */
        strncpy(ethreq.ifr_name, "ens38", IFNAMSIZ);
        uint8_t src_mac[6] = {0x00, 0x0c, 0x29, 0xf4, 0x09, 0x13};
        uint8_t src_ip[4] = {192, 168, 199, 1};

        // 2. src mac
        memcpy(arpbuf + 6, src_mac, 6); // eth_h
        memcpy(arpbuf + 22, src_mac, 6);
        memcpy(arpbuf + 28, src_ip, 4);
    }
    else if (subnet == subnet_ip_39)
    {
        /* via ens39 to 192.168.200.0 */
        strncpy(ethreq.ifr_name, "ens39", IFNAMSIZ);
        uint8_t src_mac[6] = {0x00, 0x0c, 0x29, 0xf4, 0x09, 0x1d};
        uint8_t src_ip[4] = {192, 168, 200, 1};

        // 2. src mac
        memcpy(arpbuf + 6, src_mac, 6); // eth_h
        memcpy(arpbuf + 22, src_mac, 6);
        memcpy(arpbuf + 28, src_ip, 4);
    }
    // 填写 target ip
    // printf("p_data: \n");

    // for (int i = 0; i < 42; i++)
    // {
    //     if (i % 32 == 0)
    //     {
    //         printf("\n");
    //     }
    //     printf("%02x ", p_data[i]);
    // }
    // printf("\n");

    memcpy(arpbuf + 38, p_data + 30, 4); // todo 要 IP 中的 DST_IP

    // printf("arpbuf:\n");
    // for (int i = 0; i < sizeof(arpbuf); i++)
    // {
    //     if (i % 32 == 0)
    //     {
    //         printf("\n");
    //     }
    //     printf("%02x ", arpbuf[i]);
    // }
    // printf("\n");

    int arp_pack_size = 42; // 14 + 28 =
    if (-1 == ioctl(sockfd, SIOCGIFINDEX, &ethreq))
    {
        //
        perror("ioctl");
        close(sockfd);
        return;
    }
    bzero(&sll, sizeof(sll));
    sll.sll_ifindex = ethreq.ifr_ifindex; // 网络出口结构体
    int send_arp_pack_size = sendto(sockfd, arpbuf, arp_pack_size, 0, (struct sockaddr *)&sll, sizeof(sll));
    // printf("send_arp_pack_size=%d\n", send_arp_pack_size);
}

void send_icmp(int sockfd, uint8_t *p_data, uint32_t subnet, int icmp_pack_size)
{
    struct sockaddr_ll sll;
    struct ifreq ethreq;
    if (subnet == subnet_ip_38)
    {
        /* via ens38 to 192.168.199.0 */
        strncpy(ethreq.ifr_name, "ens38", IFNAMSIZ);
        uint8_t src_mac[6] = {0x00, 0x0c, 0x29, 0xf4, 0x09, 0x13}; // 源MAC
        memcpy(p_data + 6, src_mac, 6);
    }
    else if (subnet == subnet_ip_39)
    {
        /* via ens39 to 192.168.200.0 */
        strncpy(ethreq.ifr_name, "ens39", IFNAMSIZ);
        uint8_t src_mac[6] = {0x00, 0x0c, 0x29, 0xf4, 0x09, 0x1d}; // 源MAC
        memcpy(p_data + 6, src_mac, 6);
    }

    // 填写 target ip

    if (-1 == ioctl(sockfd, SIOCGIFINDEX, &ethreq))
    {
        perror("ioctl");
        close(sockfd);
        return;
    }
    bzero(&sll, sizeof(sll));
    sll.sll_ifindex = ethreq.ifr_ifindex; // 网络出口结构体
    int send_icmp_pack_size = sendto(sockfd, p_data, icmp_pack_size, 0, (struct sockaddr *)&sll, sizeof(sll));
    // printf("send_icmp_pack_size=%d\n", send_icmp_pack_size);
}

void *on_icmp_task(void *arg)
{
    printf("\033[%dm", 36);
    fflush(stdout);
    struct recv_task_param *rt_param = (struct recv_task_param *)arg;
    int sockfd = rt_param->sockfd;
    ICMPBlockingQueue *icmp_queue = rt_param->icmpQueue;
    ICMPSizeBlockingQueue *icmpsizeQueue = rt_param->icmpSizeQueue;
    // printf("on_icmp_task : %p\n", icmp_queue);
    ICMP_PDU2 data;
    data.p_icmp_e = NULL;
    uint8_t *p_data = NULL;

    int icmp_pack_size = 0;

    char dstip[16] = "";
    char dstmac[32] = "";
    uint8_t dstmac_arr[6] = {0};

    // mysql-related
    MYSQL *sqlconnect;
    MYSQL sql;
    // 创建mysql 连接
    mysql_init(&sql);
    sqlconnect = mysql_real_connect(&sql, "0.0.0.0", "root", "111111", "wlw2401", 3306, NULL, 0);
    if (sqlconnect == NULL)
    {
        printf("connect error\n");
        return NULL;
    }

    while (1)
    {
        bzero(&data, sizeof(ICMP_PDU2));
        dequeue(0x080001, icmp_queue, &data);
        dequeue(0x08000199, icmpsizeQueue, &icmp_pack_size);
        printf("icmp_pack_size=%d\n", icmp_pack_size);
        printf("\t##3: icmp_data:%p \n", data.p_icmp_e);

        // todo p_data 就是 数据包
        p_data = data.p_icmp_e;
        out_put_eth_h(p_data);
        out_put_ip_h(p_data);
        out_put_icmp_h(p_data);

        bzero(dstip, sizeof(dstip));
        inet_ntop(AF_INET, p_data + 30, dstip, 16);
        if (0x08 == p_data[34] && 0x00 == p_data[35])
        {
            printf("这是一个 ICMP 请求数据包\n");

            // 这里根据收到的 包 做处理
            char select_sql[512] = "";
            u_int32_t ip = ntohl(*(uint32_t *)(p_data + 30));
            sprintf(select_sql,
                    "SELECT mac_str from arp_t WHERE ip='%u';",
                    ip);
            printf("%s\n", select_sql);

            if (mysql_real_query(sqlconnect, select_sql, strlen(select_sql)) != 0)
            {
                fprintf(stderr, "mysql_query() failed: %s\n", mysql_error(sqlconnect));

                // 检查连接状态
                if (mysql_ping(sqlconnect) != 0)
                {
                    fprintf(stderr, "mysql_ping() failed\n");

                    // 重新连接
                    sqlconnect = mysql_real_connect(&sql, "0.0.0.0", "root", "111111", "wlw2401", 3306, NULL, 0);
                    if (sqlconnect == NULL)
                    {
                        fprintf(stderr, "mysql_real_connect() failed\n");
                        mysql_close(sqlconnect);
                        return NULL;
                    }
                }
            }
            else
            {
                MYSQL_RES *res = mysql_store_result(sqlconnect);
                if (res != NULL)
                {
                    int col = mysql_num_fields(res);
                    int row = mysql_num_rows(res);

                    printf("row=%d  col=%d\n", row, col);

                    int i = 0, j = 0;
                    MYSQL_FIELD *colname;
                    for (i = 0; i < col; i++)
                    {
                        colname = mysql_fetch_field(res); // 每调用一次获取一个列名称
                        // printf("%s\t", colname->name);
                    }
                    // printf("\n");
                    // 从结果集获取每行信息
                    MYSQL_ROW row_data;

                    if (row > 0)
                    {
                        // 168369519 10.9.29.111 00:0c:29:f4:09:1d
                        for (i = 0; i < row; i++)
                        {
                            row_data = mysql_fetch_row(res); // 每调用一次获取一行数据
                            for (j = 0; j < col; j++)
                            {
                                // 是将一行中的多列数据依次输出
                                // printf("%s ", row_data[j]);
                                memcpy(dstmac, row_data[j], strlen(row_data[j]));
                            }
                            // printf("\n");
                        }
                    }
                    else
                    {
                        printf("icmp 未查询到ip=%s的记录\n", dstip);
                        // subnet_ip_38:3232286464
                        // subnet_ip_39:3232286720

                        //  发送 ARP

                        // printf("to ens39: %d\n", (ip & subnet_ip_39) == subnet_ip_39);
                        // printf("to ens38: %d\n", (ip & subnet_ip_38) == subnet_ip_38);
                        if ((ip & subnet_ip_39) == subnet_ip_39)
                        {
                            printf("to ens39\n");
                            send_arp(sockfd, p_data, subnet_ip_39);
                        }
                        else if ((ip & subnet_ip_38) == subnet_ip_38)
                        {
                            printf("to ens38\n");
                            send_arp(sockfd, p_data, subnet_ip_38);
                        }

                        continue;
                    }
                    mysql_free_result(res);
                }
                else
                {
                    printf("icmp 结果集为空 ip=%s\n", dstip);
                    continue;
                }
            }

            if (strlen(dstmac) > 0)
            {
                printf("已找到 %s 对应:%s\n", dstip, dstmac);
                sscanf(dstmac, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
                       &dstmac_arr[0], &dstmac_arr[1], &dstmac_arr[2], &dstmac_arr[3], &dstmac_arr[4], &dstmac_arr[5]);
                output_mac(dstmac_arr);

                // 这里先把 目的 mac 换了
                // send 只用换 源mac
                memcpy(p_data, dstmac_arr, 6);
                if ((ip & subnet_ip_39) == subnet_ip_39)
                {
                    printf("icmp to ens39\n");
                    send_icmp(sockfd, p_data, subnet_ip_39, icmp_pack_size);
                }
                else if ((ip & subnet_ip_38) == subnet_ip_38)
                {
                    printf("icmp to ens38\n");
                    send_icmp(sockfd, p_data, subnet_ip_38, icmp_pack_size);
                }
            }
        }
        else if (0x00 == p_data[34] && 0x00 == p_data[35])
        {
            printf("这是一个 ICMP 应答数据包\n");

            // 这里根据收到的 包 做处理
            char select_sql[512] = "";
            u_int32_t ip = ntohl(*(uint32_t *)(p_data + 30));
            sprintf(select_sql,
                    "SELECT mac_str from arp_t WHERE ip='%u';",
                    ip);
            // printf("%s\n", select_sql);

            if (mysql_real_query(sqlconnect, select_sql, strlen(select_sql)) != 0)
            {
                fprintf(stderr, "mysql_query() failed: %s\n", mysql_error(sqlconnect));

                // 检查连接状态
                if (mysql_ping(sqlconnect) != 0)
                {
                    fprintf(stderr, "mysql_ping() failed\n");

                    // 重新连接
                    sqlconnect = mysql_real_connect(&sql, "0.0.0.0", "root", "111111", "wlw2401", 3306, NULL, 0);
                    if (sqlconnect == NULL)
                    {
                        fprintf(stderr, "mysql_real_connect() failed\n");
                        mysql_close(sqlconnect);
                        return NULL;
                    }
                }
            }
            else
            {
                MYSQL_RES *res = mysql_store_result(sqlconnect);
                if (res != NULL)
                {
                    int col = mysql_num_fields(res);
                    int row = mysql_num_rows(res);

                    printf("row=%d  col=%d\n", row, col);

                    int i = 0, j = 0;
                    MYSQL_FIELD *colname;
                    for (i = 0; i < col; i++)
                    {
                        colname = mysql_fetch_field(res); // 每调用一次获取一个列名称
                        // printf("%s\t", colname->name);
                    }
                    // printf("\n");
                    // 从结果集获取每行信息
                    MYSQL_ROW row_data;

                    if (row > 0)
                    {
                        // 168369519 10.9.29.111 00:0c:29:f4:09:1d
                        for (i = 0; i < row; i++)
                        {
                            row_data = mysql_fetch_row(res); // 每调用一次获取一行数据
                            for (j = 0; j < col; j++)
                            {
                                // 是将一行中的多列数据依次输出
                                // printf("%s ", row_data[j]);
                                memcpy(dstmac, row_data[j], strlen(row_data[j]));
                            }
                            // printf("\n");
                        }
                    }
                    else
                    {
                        printf("icmp 未查询到ip=%s的记录\n", dstip);
                        // subnet_ip_38:3232286464
                        // subnet_ip_39:3232286720

                        //  发送 ARP

                        // printf("to ens39: %d\n", (ip & subnet_ip_39) == subnet_ip_39);
                        // printf("to ens38: %d\n", (ip & subnet_ip_38) == subnet_ip_38);
                        if ((ip & subnet_ip_39) == subnet_ip_39)
                        {
                            printf("to ens39\n");
                            send_arp(sockfd, p_data, subnet_ip_39);
                        }
                        else if ((ip & subnet_ip_38) == subnet_ip_38)
                        {
                            printf("to ens38\n");
                            send_arp(sockfd, p_data, subnet_ip_38);
                        }

                        continue;
                    }
                    mysql_free_result(res);
                }
                else
                {
                    printf("icmp 结果集为空 ip=%s\n", dstip);
                    continue;
                }
            }

            if (strlen(dstmac) > 0)
            {
                // printf("已找到 %s 对应:%s\n", dstip, dstmac);
                sscanf(dstmac, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
                       &dstmac_arr[0], &dstmac_arr[1], &dstmac_arr[2], &dstmac_arr[3], &dstmac_arr[4], &dstmac_arr[5]);
                output_mac(dstmac_arr);

                // 这里先把 目的 mac 换了
                // send 只用换 源mac
                memcpy(p_data, dstmac_arr, 6);
                if ((ip & subnet_ip_39) == subnet_ip_39)
                {
                    // printf("icmp to ens39\n");
                    send_icmp(sockfd, p_data, subnet_ip_39, icmp_pack_size);
                }
                else if ((ip & subnet_ip_38) == subnet_ip_38)
                {
                    // printf("icmp to ens38\n");
                    send_icmp(sockfd, p_data, subnet_ip_38, icmp_pack_size);
                }
            }
        }

        // printf("\n");
    }

    mysql_close(sqlconnect);
    return NULL;
}

void *on_recv_task(void *arg)
{
    struct recv_task_param *rt_param = (struct recv_task_param *)arg;

    int sockfd = rt_param->sockfd;
    // printf("sockfd=%d\n", sockfd);
    ARPBlockingQueue *arpQueue = rt_param->arpQueue;
    ICMPBlockingQueue *icmpQueue = rt_param->icmpQueue;
    ICMPSizeBlockingQueue *icmpSizeQueue = rt_param->icmpSizeQueue;
    // printf("on_recv_task: %p\n", arpQueue);

    unsigned char buf[1500] = ""; // MTU大小
    int recv_len = 0;

    while (1)
    {
        bzero(buf, sizeof(buf));
        recv_len = recvfrom(sockfd, buf, sizeof(buf), 0, NULL, NULL);
        if (recv_len > 0)
        {
            // out_put_eth_h(buf);

            if (ntohs(*(unsigned short *)(buf + 12)) == ETHERTYPE_IP)
            {

                if (0x01 == buf[23]) // printf("ICMP\n");
                {
                    printf("\033[%dm", 36);
                    fflush(stdout);

                    uint8_t *p_icmp_e = malloc(recv_len); // 队列中处理完数据 释放内存
                    // printf("icmp recv_len=%d\n", recv_len);
                    memcpy(p_icmp_e, buf, recv_len);
                    // printf("recv_task, p_icmp_e:%p\n", p_icmp_e);
                    enqueue(0x080001, icmpQueue, p_icmp_e);
                    enqueue(0x08000199, icmpSizeQueue, &recv_len);
                }
            }
            else if (ETHERTYPE_ARP == ntohs(*(unsigned short *)(buf + 12))) // printf("ARP\n");
            {
                printf("\033[%dm", 31);
                fflush(stdout);

                // 以太网中 ARP包是60字节
                u_int8_t *arp_e = malloc(recv_len); // 队列中处理完数据 释放内存
                // printf("arp recv_len=%d\n", recv_len);
                memcpy(arp_e, buf, recv_len);
                // printf("recv_task, arp_e:%p\n", arp_e);
                enqueue(ETHERTYPE_ARP, arpQueue, arp_e);
            }
            else
            {
                //
            }
        }
        else
        {
            printf("<=0\n");
        }
    }
    return NULL;
}

void arp_help(void)
{
    printf("查看 apr 表方式:arp -a\n");
    printf("删除 arp 表方式:arp -d a.b.c.d 其中 a b c d 为 0 ~ 255 的整数\n");
}

void select_arp_t(MYSQL *sqlconnect, MYSQL *sql)
{

    printf("sqlconnect:%p sql:%p\n", sqlconnect, sql);
    // 这里根据收到的 包 做处理
    char select_sql[512] = "";
    sprintf(select_sql, "SELECT ip_str as ip, mac_str as mac from arp_t;");
    printf("%s\n", select_sql);
    int res = mysql_real_query(sqlconnect, select_sql, strlen(select_sql));
    printf("res=%d\n", res);
    if (res != 0)
    {
        printf("1111\n");
        fprintf(stderr, "mysql_query() failed: %s\n", mysql_error(sqlconnect));
    }
    else
    {
        printf("xxxx\n");
        MYSQL_RES *res = mysql_store_result(sqlconnect);
        if (res != NULL)
        {
            int col = mysql_num_fields(res);
            int row = mysql_num_rows(res);

            int i = 0, j = 0;
            MYSQL_FIELD *colname;
            for (i = 0; i < col; i++)
            {
                colname = mysql_fetch_field(res); // 每调用一次获取一个列名称
                printf("%s\t", colname->name);
            }
            // printf("\n");
            // 从结果集获取每行信息
            MYSQL_ROW row_data;

            if (row > 0)
            {
                // 168369519 10.9.29.111 00:0c:29:f4:09:1d
                for (i = 0; i < row; i++)
                {
                    row_data = mysql_fetch_row(res); // 每调用一次获取一行数据
                    for (j = 0; j < col; j++)
                    {
                        // 是将一行中的多列数据依次输出
                        printf("%s ", row_data[j]);
                    }
                    // printf("\n");
                }
            }
            else
            {
                printf("arp 表为空\n");
            }
            mysql_free_result(res);
        }
        else
        {
            printf("arp 表为空\n");
        }
    }
}

void *on_cmd_task(void *arg)
{
    // cmd
    char cmd[128] = "";
    char *buf[32] = {cmd};

    // mysql-related
    MYSQL *sqlconnect;
    MYSQL sql;
    // 创建mysql 连接
    mysql_init(&sql);
    sqlconnect = mysql_real_connect(&sql, "0.0.0.0", "root", "111111", "wlw2401", 3306, NULL, 0);
    if (sqlconnect == NULL)
    {
        printf("connect error\n");
        return NULL;
    }

    while (1)
    {

        bzero(cmd, sizeof(cmd));
        for (int i = 1; i < sizeof(buf); i++)
        {
            buf[i] = NULL;
        }

        fgets(cmd, sizeof(cmd), stdin);
        cmd[strlen(cmd) - 1] = '\0';

        if (strlen(cmd) == 0)
        {
            continue;
        }

        int i = 0;
        while ((buf[i] = strtok(buf[i], " ")) && ++i)
            ;

        for (int j = 0; j < i; j++)
        {
            printf("%s\n", buf[j]);
        }

        if (strncmp(buf[0], "arp", 3) == 0 && strncmp(buf[1], "-a", 2) == 0)
        {
            select_arp_t(sqlconnect, &sql);
        }
        else
        {
            arp_help();
        }
    }

    return NULL;
}

int main(int argc, char const *argv[])
{
    // 1. 创建 raw socket
    int sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0)
    {
        perror("socket");
        return -1;
    }

    prepare_ens38(sockfd);
    prepare_ens39(sockfd);

    struct recv_task_param rt_param;
    rt_param.sockfd = sockfd;

    ARPBlockingQueue arpQueue;
    initARPBlockingQueue(&arpQueue);
    rt_param.arpQueue = &arpQueue; // 栈内存

    ICMPBlockingQueue icmpQueue;
    initARPBlockingQueue((ARPBlockingQueue *)&icmpQueue);
    rt_param.icmpQueue = &icmpQueue; // 栈内存

    ICMPSizeBlockingQueue icmpSizeQueue;
    initICMPSizeBlockingQueue(&icmpSizeQueue);
    rt_param.icmpSizeQueue = &icmpSizeQueue; // 栈内存

    MYSQL *sqlconnect;
    MYSQL sql;

    // 创建mysql 连接
    mysql_init(&sql);

    sqlconnect = mysql_real_connect(&sql, "0.0.0.0", "root", "111111", "wlw2401", 3306, NULL, 0);

    if (sqlconnect == NULL)
    {
        printf("connect error\n");
        return -1;
    }

    // 2.0 循环从 socket 收数据报
    pthread_t recv_task;
    int create_recv_task = pthread_create(&recv_task, NULL, on_recv_task, (void *)&rt_param);

    // 2. 循环处理 ICMP

    pthread_t icmp_task;
    int create_icmp_task = pthread_create(&icmp_task, NULL, on_icmp_task, (void *)&rt_param);

    // 3. 循环处理 arp
    pthread_t arp_task;
    int create_arp_task = pthread_create(&arp_task, NULL, on_arp_task, (void *)&rt_param);

    // 4. 循环收 用户cmd
    pthread_t cmd_task;
    int create_cmd_task = pthread_create(&cmd_task, NULL, on_cmd_task, 0);

    // 9.0 等待 recv_task 线程结束
    pthread_join(recv_task, NULL);
    printf("recv_task end\n");

    // 9.1 等待 icmp_task 线程结束
    pthread_join(icmp_task, NULL);
    printf("icmp_task end\n");

    // 9.2 等待 arp_task 线程结束
    pthread_join(arp_task, NULL);
    printf("arp_task end\n");

    // 9.3 等待 cmd_task 线程结束
    pthread_join(cmd_task, NULL);
    printf("cmd_task end\n");

    mysql_close(sqlconnect);
    return 0;
}
