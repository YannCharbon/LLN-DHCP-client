/**
 * @file dhcp_client.c
 * @author Yann Charbon <yann.charbon@ik.me>
 * @brief Basic Linux DHCP client using Rapid Commit supporting Low-power and Lossy Networks
 * @version 1.0
 * @date 2023-08-28
 * @copyright Copyright (c) 2023 Yann Charbon. All right reserved.
 * This project is release under Apache-2.0 License.
 * 
 * This DHCP client is capable to work behind the Mbed OS Nanostack network stacks, such as Wi-SUN, Thread
 * or 6LoWPAN mesh. This allows to connect a standard PC behind such networks.
 * 
 * E.g. using Nanostack border router, it is possible to have the following setup :
 * 
 * .-----------------.      .-------------------------.      .------------------------.      .---------.
 * | Internet (IPv6) | <--> |  Nanostack BR (Wi-SUN)  | <--> |  Modified Router Node  | <--> |  Linux  |
 * '-----------------'      '-------------------------'      '------------------------'      '---------'
 *
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/route.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/icmp6.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>

#define SERVER_PORT 547
#define CLIENT_PORT 546
#define BUFFER_SIZE 1024

#define DHCPV6_MSG_TYPE_SOLICIT 1
#define DHCPV6_MSG_TYPE_RENEW 5
#define DHCPV6_MSG_TYPE_REPLY 7

#define OPTION_CLIENT_IDENTIFIER 1
#define OPTION_SERVER_IDENTIFIER 2
#define OPTION_IA_NA 3
#define OPTION_IA_ADDR 5
#define OPTION_OPTION_REQUEST 6
#define OPTION_ELAPSED_TIME 8
#define OPTION_RAPID_COMMIT 14
#define OPTION_DNS_SERVERS 23
#define OPTION_DOMAIN_SEARCH_LIST 24

#define SOCKET_RECV_TIMEOUT_SEC 10

/* List of known servers that should always be reachable to check if internet is accessible */
#define CONNECTIVITY_TEST_ADDRESSES_COUNT 3
static char *connectivity_test_addr_list[CONNECTIVITY_TEST_ADDRESSES_COUNT] = { "2a00:1450:400a:800::200e",
                                                                                "2606:2800:220:1:248:1893:25c8:1946",
                                                                                "2603:1020:201:10::10f" };

struct dhcp_client_context {
    int dhcp_sockfd;                        /* DHCP communication socket */
    int ping_sockfd;                        /* Connectivity test using ICMP ping socket */
    char iface_name[IFNAMSIZ];              /* Interface name (string) */
    uint8_t server_addr[16];                /* DHCP server address */
    char server_addr_str[40];               /* DHCP server address (string)*/
    uint8_t ia_addr[16];                    /* Assigned address from DHCP server for the client */
    char ia_addr_str[40];                   /* Assigned address from DHCP server for the client (string) */
    uint32_t ia_addr_preferred_lifetime;    /* Assigned address preferred lifetime */
    uint32_t ia_addr_valid_lifetime;        /* Assigned address maximum lifetime */
    uint8_t dns_server_addr[16];            /* DNS server address transmitted by DHCP server */
    char dns_server_addr_str[40];           /* DNS server address transmitted by DHCP server (string) */
    uint8_t server_duid[32];                /* DHCP server unique ID */
    uint8_t server_duid_len;                /* DHCP server unique ID length */
    uint8_t client_duid[32];                /* DHCP client unique ID */
    uint8_t client_duid_len;                /* DHCP client unique ID length */
    pthread_t connectivity_thread;          /* Connectivity thread checking internet availability thread handle*/
    int close_requested;                    /* Flag to tell threads that app must close */
    int address_configured;                 /* Flag to tell app components that a valid address has been added to interface */
};

static struct dhcp_client_context context = {
    0,
    0,
    {'\0'},
    {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
    {'\0'},
    {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
    {'\0'},
    0,
    0,
    {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
    {'\0'},
    {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
    0,
    {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
    0,
    0,
    0,
    0,
};

struct ping_pkt
{
    struct icmp6_hdr hdr;
    char msg[64-sizeof(struct icmp6_hdr)];
};

struct dhcpv6_message {
    uint8_t msg_type; // Message type (1 byte)
    uint8_t options[4096];
};

struct in6_ifreq {
    struct in6_addr addr;
    uint32_t        prefixlen;
    unsigned int    ifindex;
};

static uint8_t cur_transaction_id[3] = {0, 0, 0};

void randomize_array(uint8_t *array, int len) {
    int i;
    for (i = 0; i < len; i++) {
        array[i] = (uint8_t)rand();
    }
}

unsigned short checksum(void *b, int len) {    
    unsigned short *buf = b;
    unsigned int sum=0;
    unsigned short result;
 
    for ( sum = 0; len > 1; len -= 2 )
        sum += *buf++;
    if ( len == 1 )
        sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

int add_ipv6_addr(char *if_name, uint8_t *address) {
    struct ifreq ifr;
    struct in6_ifreq ifr6;
    int sockfd;
    int err;

    // Create IPv6 socket to perform the ioctl operations on
    sockfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_IP);

    // Copy the interface name to the ifreq struct
    strncpy(ifr.ifr_name, if_name, IFNAMSIZ);
    // Get the ifrindex of the interface
    err = ioctl(sockfd, SIOGIFINDEX, &ifr);
    if (err != 0) {
        perror("SIOGIFINDEX failed");
        close(sockfd);
        return 1;
    }

    // Prepare the in6_ifreq struct and set the address to the interface
    memcpy(&ifr6.addr, address, 16);
    ifr6.ifindex = ifr.ifr_ifindex;
    ifr6.prefixlen = 128;
    err = ioctl(sockfd, SIOCSIFADDR, &ifr6);

    if (err != 0) {
        perror("SIOCSIFADDR failed");
        close(sockfd);
        return 1;
    }

    printf("Successfully added address to interface\n");

    close(sockfd);
    return 0;
}

int set_iface_mtu(char *if_name, int mtu) {
    struct ifreq ifr;
    int sockfd;
    int err;

    // Create IPv6 socket to perform the ioctl operations on
    sockfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_IP);

    // Copy the interface name to the ifreq struct
    strncpy(ifr.ifr_name, if_name, IFNAMSIZ);
    // Get the ifrindex of the interface
    err = ioctl(sockfd, SIOGIFINDEX, &ifr);
    if (err != 0) {
        perror("SIOGIFINDEX failed");
        close(sockfd);
        return 1;
    }

    // Prepare the in6_ifreq struct and set the MTU to the interface
    ifr.ifr_mtu = mtu; 
    err = ioctl(sockfd, SIOCSIFMTU, (caddr_t)&ifr);

    if (err != 0) {
        perror("SIOCSIFMTU failed");
        close(sockfd);
        return 1;
    }

    printf("Successfully set MTU to %d on iface %s\n", mtu, if_name);

    close(sockfd);
    return 0;
}

int delete_ipv6_addr(char *if_name, uint8_t *address) {
    struct ifreq ifr;
    struct in6_ifreq ifr6;
    int sockfd;
    int err;

    // Create IPv6 socket to perform the ioctl operations on
    sockfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_IP);

    // Copy the interface name to the ifreq struct
    strncpy(ifr.ifr_name, if_name, IFNAMSIZ);
    // Get the ifrindex of the interface
    err = ioctl(sockfd, SIOGIFINDEX, &ifr);
    if (err != 0) {
        perror("SIOGIFINDEX failed");
        close(sockfd);
        return 1;
    }

    // Prepare the in6_ifreq struct and set the address to the interface
    memcpy(&ifr6.addr, address, 16);
    ifr6.ifindex = ifr.ifr_ifindex;
    ifr6.prefixlen = 128;
    err = ioctl(sockfd, SIOCDIFADDR, &ifr6);

    if (err != 0) {
        perror("SIOCDIFADDR failed");
        close(sockfd);
        return 1;
    }

    printf("Successfully deleted address from interface\n");

    close(sockfd);
    return 0;
}

int add_default_route(char *iface_name, uint8_t *gw_address) {
    int sockfd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if (sockfd == -1) {
        perror("socket");
        return 1;
    }

    struct in6_rtmsg route;
    memset(&route, 0, sizeof(struct in6_rtmsg));

    memcpy(&route.rtmsg_gateway, gw_address, 16);
    memset(&route.rtmsg_dst, 0, 16);  // Default route matches all addresses
    route.rtmsg_dst_len = 0;  // Prefix length for default route

    route.rtmsg_flags = RTF_UP | RTF_GATEWAY | RTF_DEFAULT;
    route.rtmsg_metric = 0;
    route.rtmsg_type = RTF_INTERFACE;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(struct ifreq));
    strncpy(ifr.ifr_name, iface_name, IFNAMSIZ);

    route.rtmsg_ifindex = if_nametoindex(ifr.ifr_name);

    if (ioctl(sockfd, SIOCADDRT, &route) == -1) {
        perror("SIOCADDRT failed");
        close(sockfd);
        return 1;
    }

    printf("Default IPv6 route set successfully.\n");

    close(sockfd);
}

int delete_default_route(char *iface_name, uint8_t *gw_address) {
    int sockfd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if (sockfd == -1) {
        perror("socket");
        return 1;
    }

    struct in6_rtmsg route;
    memset(&route, 0, sizeof(struct in6_rtmsg));

    memcpy(&route.rtmsg_gateway, gw_address, 16);
    memset(&route.rtmsg_dst, 0, 16);  // Default route matches all addresses
    route.rtmsg_dst_len = 0;  // Prefix length for default route

    route.rtmsg_flags = RTF_UP | RTF_GATEWAY | RTF_DEFAULT;
    route.rtmsg_metric = 0;
    route.rtmsg_type = RTF_INTERFACE;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(struct ifreq));
    strncpy(ifr.ifr_name, iface_name, IFNAMSIZ);

    route.rtmsg_ifindex = if_nametoindex(ifr.ifr_name);

    if (ioctl(sockfd, SIOCDELRT, &route) == -1) {
        perror("SIOCDELRT failed");
        close(sockfd);
        return 1;
    }

    printf("Default IPv6 route deleted successfully.\n");

    close(sockfd);
}


int add_dns_server(const char * addr) {
    FILE * f = NULL;
    unsigned char c;

    if (!(f = fopen("/etc/resolv.conf", "a+")) ) {
        printf("Could not open resolve.conf\n");
        return -1;
    }

    fseek(f, -1, SEEK_END);
    c = fgetc(f);   // Get last char

    fseek(f ,0, SEEK_END);
    // Make sure that the file is ending with a new-line
    if ( (c != '\r') && (c != '\n') ) {
        fprintf(f,"\n");
    }

    // Add nameserver to resolv.conf
    fprintf(f, "nameserver %s\n", addr);

    fclose(f);
    return 0;
}

int delete_dns_server(const char * addr) {
    FILE *input_file = fopen("/etc/resolv.conf", "r");
    if (input_file == NULL) {
        perror("Error opening /etc/resolv.conf for reading");
        return 1;
    }

    FILE *temp_file = fopen("temp.txt", "w");
    if (temp_file == NULL) {
        perror("Error creating temporary file");
        fclose(input_file);
        return 1;
    }

    char buffer[512];
    int line_found = 0;

    char nameserver_entry_line[100];
    sprintf(nameserver_entry_line, "nameserver %s\n", addr);

    while (fgets(buffer, sizeof(buffer), input_file) != NULL) {
        if (strcmp(buffer, nameserver_entry_line) == 0 && !line_found) {
            line_found = 1;
            continue; // Skip writing this line to temp file
        }
        fputs(buffer, temp_file);
    }

    fclose(input_file);
    fclose(temp_file);

    if (line_found) {
        if (remove("/etc/resolv.conf") == 0) {
            if (rename("temp.txt", "/etc/resolv.conf") != 0) {
                perror("Error renaming temporary file");
            }
            printf("Succesfully removed DNS server entry from /etc/resolv.conf\n");
        } else {
            perror("Error removing original file");
        }
    } else {
        remove("temp.txt"); // If line not found, discard temp file
        printf("Line not found in the file.\n");
    }

    return 0;
}

// Add a DHCPv6 option to a message
uint8_t *add_dhcpv6_option(uint8_t *ptr, uint16_t code, uint8_t *data, uint16_t len) {
    *((uint16_t *)ptr) = htons(code);
    ptr += 2;
    *((uint16_t *)ptr) = htons(len);
    ptr += 2;
    if (data != NULL) {
        memcpy(ptr, data, len);
        ptr += len;
    }
    return ptr;
}

// Initialize a DHCPv6 message
uint8_t *initialize_dhcpv6_message(struct dhcpv6_message *message) {
    memset(message, 0, sizeof(struct dhcpv6_message ));
    return message->options;
}

// Set the message type field in a DHCPv6 message
void set_message_type(struct dhcpv6_message *message, uint8_t type) {
    message->msg_type = type;
}

// Generate and set the transaction ID in a DHCPv6 message
void set_transaction_id(uint8_t *ptr) {
    randomize_array(cur_transaction_id, 3);
    memcpy(ptr, cur_transaction_id, 3);
}

// Add the Client Identifier option to a DHCPv6 message
uint8_t *add_client_id_option(uint8_t *ptr, int new_request) {
    if (new_request) {
        uint8_t duid[14];
        randomize_array(duid, 14);
        duid[0] = 0;
        duid[1] = 1;
        duid[2] = 0;
        duid[3] = 1;
        duid[4] = 0x2a;
        ptr = add_dhcpv6_option(ptr, OPTION_CLIENT_IDENTIFIER, duid, 14);
    } else {
        ptr = add_dhcpv6_option(ptr, OPTION_CLIENT_IDENTIFIER, context.client_duid, context.client_duid_len);
    }

    return ptr;
}

// Add the Server Identifier option to a DHCPv6 message
uint8_t *add_server_id_option(uint8_t *ptr) {
    ptr = add_dhcpv6_option(ptr, OPTION_CLIENT_IDENTIFIER, context.server_duid, context.server_duid_len);

    return ptr;
}

// Add the Identity Association for Non-temporary Addresses (IA_NA) option to a DHCPv6 message
uint8_t *add_ia_na_option(uint8_t *ptr, int include_ia_addr) {
    struct ia_na_option {
        uint8_t iaid[4];
        uint8_t t1[4];
        uint8_t t2[4];
    };

    struct ia_addr_option {
        uint8_t ip_addr[16];
        uint8_t t1[4];
        uint8_t t2[4];
    };

    struct ia_na_option ia_na;

    uint8_t iaid[4];
    randomize_array(ia_na.iaid, 4);
    memset(ia_na.t1, 0xff, 4);
    memset(ia_na.t2, 0xff, 4);

    ptr = add_dhcpv6_option(ptr, OPTION_IA_NA, (uint8_t *)&ia_na, sizeof(ia_na));

    if (include_ia_addr) {
        struct ia_addr_option ia_addr;

        memcpy(ia_addr.ip_addr, context.ia_addr, 16);
        memset(ia_addr.t1, 0xff, 4);
        memset(ia_addr.t2, 0xff, 4);

        ptr = add_dhcpv6_option(ptr, OPTION_IA_ADDR, (uint8_t *)&ia_addr, sizeof(ia_addr));
    }

    return ptr;
}

// Add the Rapid Commit option to a DHCPv6 message
uint8_t *add_rapid_commit_option(uint8_t *ptr) {
    ptr = add_dhcpv6_option(ptr, OPTION_RAPID_COMMIT, NULL, 0);
    return ptr;
}

// Add the Elapsed Time option to a DHCPv6 message
uint8_t *add_elapsed_time_option(uint8_t *ptr) {
    uint16_t elapsed_time = htons(0); // Elapsed time = 0
    ptr = add_dhcpv6_option(ptr, OPTION_ELAPSED_TIME, (uint8_t *)&elapsed_time, sizeof(elapsed_time));
    return ptr;
}

// Add the Option Request option to a DHCPv6 message
uint8_t *add_option_request_option(uint8_t *ptr) {
    uint16_t requested_options = htons(OPTION_DNS_SERVERS);
    ptr = add_dhcpv6_option(ptr, OPTION_OPTION_REQUEST, (uint8_t *)&requested_options, sizeof(requested_options));
    return ptr;
}

/**
 * From Mbed OS (libdhcpv6_solication_message_options_validate)
 * Solication Message Should Include Next Options:
 *  - DHCPV6_ELAPSED_TIME_OPTION
 *  - DHCPV6_CLIENT_ID_OPTION
 *  - DHCPV6_IDENTITY_ASSOCIATION_OPTION
 *  - DHCPV6_OPTION_REQUEST_OPTION
 * Optionally:
 *  - DHCPV6_OPTION_REQUEST_RAPID_COMMIT
 */
// Create and send a DHCPv6 Discover message
void send_dhcpv6_discover(int sockfd, struct sockaddr_in6 *server_addr) {
    struct dhcpv6_message message;
    uint8_t *ptr = initialize_dhcpv6_message(&message);

    set_message_type(&message, DHCPV6_MSG_TYPE_SOLICIT);
    set_transaction_id(ptr);
    ptr += 3;

    ptr = add_client_id_option(ptr, 1);
    ptr = add_ia_na_option(ptr, 0);
    ptr = add_rapid_commit_option(ptr);
    ptr = add_elapsed_time_option(ptr);
    ptr = add_option_request_option(ptr);

    printf("Sending SOLICIT to DHCP server (%ds timeout)\n", SOCKET_RECV_TIMEOUT_SEC);
    sendto(sockfd, &message, ptr - message.options + 1, 0,
        (struct sockaddr *)server_addr, sizeof(*server_addr));
}

// Create and send a DHCPv6 renew message
void send_dhcpv6_renew(int sockfd, struct sockaddr_in6 *server_addr) {
    struct dhcpv6_message message;
    uint8_t *ptr = initialize_dhcpv6_message(&message);

    set_message_type(&message, DHCPV6_MSG_TYPE_SOLICIT);
    set_transaction_id(ptr);
    ptr += 3;

    ptr = add_client_id_option(ptr, 0);
    ptr = add_server_id_option(ptr);
    ptr = add_ia_na_option(ptr, 1);
    ptr = add_rapid_commit_option(ptr);
    ptr = add_elapsed_time_option(ptr);

    printf("Sending RENEW to DHCP server (%ds timeout)\n", SOCKET_RECV_TIMEOUT_SEC);
    sendto(sockfd, &message, ptr - message.options + 1, 0,
        (struct sockaddr *)server_addr, sizeof(*server_addr));
}

int handle_incoming_packet(uint8_t *data, int len) {
    int ret = 0;
    uint8_t *ptr = data;

    if (*ptr++ != DHCPV6_MSG_TYPE_REPLY) {
        printf("Response is not REPLY. Dropping\n");
        return -1;
    }

    printf("Detected REPLY\n");

    if (memcmp(ptr, cur_transaction_id, 3) != 0) {
        printf("Transaction IDs do not match. Dropping\n");
        return -1;
    }
    ptr += 3;

    while (ptr - data < len) {
        if (ntohs(*((uint16_t*)ptr)) == OPTION_IA_NA) {
            printf("OPTION_IA_NA\n");
            ptr += 2;
            int option_len = ntohs(*((uint16_t*)ptr));
            ptr += 2;
            uint8_t *tmp_ptr = ptr;
            if (option_len > 12) {
                tmp_ptr += 12;
                // IA_NA is containing a sub-option which might be IA_ADDR
                while (tmp_ptr - ptr < option_len) {
                    if (ntohs(*((uint16_t*)tmp_ptr)) == OPTION_IA_ADDR) {
                        tmp_ptr += 2;
                        if (ntohs(*((uint16_t*)tmp_ptr)) == 24) {
                            tmp_ptr += 2;
                            // option contains IPv6 address, preferred lifetime, valid lifetime
                            uint8_t ipv6_addr_bytes[16];
                            memcpy(ipv6_addr_bytes, tmp_ptr, 16);
                            memcpy(context.ia_addr, ipv6_addr_bytes, 16);
                            inet_ntop(AF_INET6, ipv6_addr_bytes, context.ia_addr_str, 40);
                            printf("IA_ADDR %s\n", context.ia_addr_str);
                            tmp_ptr += 16;
                            context.ia_addr_preferred_lifetime = ntohl(*((uint32_t*)tmp_ptr));
                            printf("Preferred lifetime %u\n", context.ia_addr_preferred_lifetime);
                            tmp_ptr += 4;
                            context.ia_addr_valid_lifetime = ntohl(*((uint32_t*)tmp_ptr));
                            printf("Valid lifetime %u\n", context.ia_addr_valid_lifetime);
                            tmp_ptr += 4;

                            ret = add_ipv6_addr(context.iface_name, ipv6_addr_bytes);
                            //ret = ipaddr_add_or_del(ipv6_addr_string, "enp0s31f6", 128, preferred_lifetime, valid_lifetime, 1);
                            if (ret == 0) {
                                set_iface_mtu(context.iface_name, 1280);
                                add_default_route(context.iface_name, context.server_addr);
                                context.address_configured = 1;
                            }
                        } else {
                            tmp_ptr += ntohs(*((uint16_t*)tmp_ptr));
                        }
                    } else {
                        printf("Ignoring sub-option %d\n", ntohs(*((uint16_t*)tmp_ptr)));
                        // Ignore current option
                        ptr += 2;
                        printf("Skipping %d byte(s)\n", ntohs(*((uint16_t*)tmp_ptr)));
                        ptr += ntohs(*((uint16_t*)tmp_ptr)) + 2;
                    }
                }
                ptr = tmp_ptr;
            } else {
                ptr += option_len;
            }
        } else if (ntohs(*((uint16_t*)ptr)) == OPTION_DNS_SERVERS) {
            printf("OPTION_DNS_SERVERS\n");
            ptr += 2;
            if (ntohs(*((uint16_t*)ptr)) == 16) {
                ptr += 2;
                memcpy(context.dns_server_addr, ptr, 16);
                inet_ntop(AF_INET6, ptr, context.dns_server_addr_str, 40);
                printf("Adding DNS server %s to resolv.conf\n", context.dns_server_addr_str);
                add_dns_server(context.dns_server_addr_str);
            }
        } else if (ntohs(*((uint16_t*)ptr)) == OPTION_DOMAIN_SEARCH_LIST) {
            printf("OPTION_DOMAIN_SEARCH_LIST\n");
            ptr += 2;
            ptr += ntohs(*((uint16_t*)ptr)) + 2;
        } else if (ntohs(*((uint16_t*)ptr)) == OPTION_SERVER_IDENTIFIER) {
            printf("OPTION_SERVER_IDENTIFIER\n");
            ptr += 2;
            context.server_duid_len = ntohs(*((uint16_t*)ptr));
            printf("len=%d\n", context.server_duid_len);
            ptr += 2;
            memcpy(context.server_duid, ptr, context.server_duid_len);
            ptr += context.server_duid_len;
        } else if (ntohs(*((uint16_t*)ptr)) == OPTION_CLIENT_IDENTIFIER) {
            printf("OPTION_CLIENT_IDENTIFIER\n");
            ptr += 2;
            context.client_duid_len = ntohs(*((uint16_t*)ptr));
            ptr += 2;
            memcpy(context.client_duid, ptr, context.client_duid_len);
            ptr += context.client_duid_len;
        } else {
            printf("Ignoring option %d\n", ntohs(*((uint16_t*)ptr)));
            // Ignore current option
            ptr += 2;
            printf("Skipping %d byte(s)\n", ntohs(*((uint16_t*)ptr)));
            ptr += ntohs(*((uint16_t*)ptr)) + 2;
        }
    }
}

void clean_interface() {
    delete_dns_server(context.dns_server_addr_str);    
    delete_default_route(context.iface_name, context.server_addr);    
    delete_ipv6_addr(context.iface_name, context.ia_addr);

    memset(context.dns_server_addr_str, 0, sizeof(context.dns_server_addr_str));
    memset(context.server_addr, 0, sizeof(context.server_addr));
    memset(context.ia_addr, 0, sizeof(context.ia_addr));

    context.address_configured = 0;
}

void signal_int_handler(int signum) {
    context.close_requested = 1;

    clean_interface();

    close(context.dhcp_sockfd);

    if (context.ping_sockfd > -1) {
        close(context.ping_sockfd);
    }

    pthread_join(context.connectivity_thread, NULL);

    exit(signum);
}

int check_internet_connectivity () {
    struct sockaddr_in6 ping_target_addr;
    socklen_t addr_len = sizeof(ping_target_addr);
    struct ping_pkt ping_packet;
    int response_received = 0;

    // Open ICMP socket for connectivity check
    context.ping_sockfd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if (context.ping_sockfd == -1) {
        perror("Socket creation failed");
        return -1;
    }

    // Setting timeout for ping socket
    struct timeval tv;
    tv.tv_sec = SOCKET_RECV_TIMEOUT_SEC / 2;
    tv.tv_usec = 0;
    if (setsockopt(context.ping_sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv) == -1) {
        perror("Setting socket timeout failed");
        close(context.ping_sockfd);
        context.ping_sockfd = -1;
        return -1;
    }

    // Preparing ICMP packet
    memset(&ping_packet, 0, sizeof(ping_packet));

    ping_packet.hdr.icmp6_type = ICMP6_ECHO_REQUEST;
    ping_packet.hdr.icmp6_code = 0;
    ping_packet.hdr.icmp6_id = getpid();
    ping_packet.hdr.icmp6_seq = 0;
    ping_packet.hdr.icmp6_cksum = checksum(&ping_packet, sizeof(ping_packet));

    for (int i = 0; i < CONNECTIVITY_TEST_ADDRESSES_COUNT; i++) {
        // Set up server address        
        memset(&ping_target_addr, 0, sizeof(ping_target_addr));
        ping_target_addr.sin6_family = AF_INET6;
        inet_pton(AF_INET6, connectivity_test_addr_list[i], &ping_target_addr.sin6_addr);  // Replace with actual server address
        strcpy(ping_packet.msg, "CONNECTIVITY_TEST");

        if (sendto(context.ping_sockfd, &ping_packet, sizeof(ping_packet), 0,
            (struct sockaddr *)&ping_target_addr, sizeof(ping_target_addr)) <= 0) {
            printf("Could not send ICMP packet to %s. Trying next address. (%d)\n", connectivity_test_addr_list[i], errno);
            continue;
        }

        addr_len = sizeof(ping_target_addr);
        memset(ping_packet.msg, 0, sizeof(ping_packet.msg));

        // Receive response from server
        if (recvfrom(context.ping_sockfd, &ping_packet, sizeof(ping_packet), 0,
            (struct sockaddr *)&ping_target_addr, &addr_len) <= 0) {
            printf("Could not receive ICMP packet from %s. Trying next address.\n", connectivity_test_addr_list[i]);
            continue;
        }

        if (strcmp(ping_packet.msg, "CONNECTIVITY_TEST") != 0) {
            printf("Received payload is corrupted. Trying next address.\n");
            continue;
        }
        response_received = 1;
        break;
    }

    close(context.ping_sockfd);
    printf("Internet connectivity is %s\n", (response_received ? "UP" : "DOWN"));
    if (response_received) {
        return 0;
    }
    return -1;
}

int interruptable_sleep(int seconds) {
    int count = 0;
    while (count++ < seconds) {
        sleep(1);
        if (context.close_requested) {
            return -1;
        }
    }
    return 0;
}

void *connectivity_thread_task() {
    struct sockaddr_in6 server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];

    // Create socket
    context.dhcp_sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (context.dhcp_sockfd == -1) {
        perror("Socket creation failed");
        return NULL;
    }

    // Bind socket to a specific network interface
    if (setsockopt(context.dhcp_sockfd, SOL_SOCKET, SO_BINDTODEVICE, context.iface_name, strlen(context.iface_name)) == -1) {
        perror("Bind to interface failed");
        close(context.dhcp_sockfd);
        return NULL;
    }

    // Set up client address
    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sin6_family = AF_INET6;
    client_addr.sin6_port = htons(CLIENT_PORT);

    // Bind socket to client address
    if (bind(context.dhcp_sockfd, (struct sockaddr *)&client_addr, sizeof(client_addr)) == -1) {
        perror("Bind failed");
        close(context.dhcp_sockfd);
        return NULL;
    }

    // Add timeout
    struct timeval tv;
    tv.tv_sec = SOCKET_RECV_TIMEOUT_SEC;
    tv.tv_usec = 0;
    if (setsockopt(context.dhcp_sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv) == -1) {
        perror("Setting socket timeout failed");
        close(context.dhcp_sockfd);
        return NULL;
    }

    while (!context.close_requested) {
        if (check_internet_connectivity() != 0) {
            if (context.address_configured) {                
                clean_interface();
                printf("Previous configuration has been cleaned from interface.\n");
            }

            // Set up server address
            memset(&server_addr, 0, sizeof(server_addr));
            server_addr.sin6_family = AF_INET6;
            server_addr.sin6_port = htons(SERVER_PORT);
            inet_pton(AF_INET6, "ff02::1:2", &server_addr.sin6_addr);  // Replace with actual server address

            // Send DHCPv6 discover message
            send_dhcpv6_discover(context.dhcp_sockfd, &server_addr);

            addr_len = sizeof(client_addr);

            // Receive response from server
            ssize_t num_bytes_received = recvfrom(context.dhcp_sockfd, buffer, BUFFER_SIZE - 1, 0,
                                                (struct sockaddr *)&server_addr, &addr_len);
            if (num_bytes_received == -1) {
                printf("Receive failed. Retrying in 15 seconds\n");
                if (interruptable_sleep(15)) {
                    return NULL;
                }                
                continue;
            }

            memcpy(context.server_addr, &server_addr.sin6_addr, 16);
            inet_ntop(AF_INET6, &server_addr.sin6_addr, context.server_addr_str, 40);
            printf("Received response (%lu byte(s) from %s)\n", num_bytes_received, context.server_addr_str);

            for (int i = 0; i < num_bytes_received; i++) {
                printf("0x%02x ", ((uint8_t *)buffer)[i]);
            }
            printf("\n");

            handle_incoming_packet(buffer, num_bytes_received);  
        }

        printf("Waiting for 60 seconds\n");
        // Waiting for 60 seconds
        if (interruptable_sleep(60)) {
            return NULL;
        }
    }
}

int main(int argc, char *argv[]) {
    int ret;

    // Init random core
    srand(time(NULL));

    // Parse eventual parameters
    if (argc == 2) {
        strcpy(context.iface_name, argv[1]);
    } else {
        strcpy(context.iface_name, "enp0s31f6");
    }
    printf("Opening on interface %s\n", context.iface_name);

    ret = pthread_create(&context.connectivity_thread, NULL, connectivity_thread_task, NULL);

    signal(SIGINT, signal_int_handler);

    printf("Press CTRL+C to close\n");

    while(1) {
        sleep(1);
    }

    return 0;
}
