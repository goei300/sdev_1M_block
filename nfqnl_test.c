#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>
#include <stdbool.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

unsigned char* host_str = NULL;
bool ack = false;

FILE *txtFile =NULL;

unsigned char* get_http_start_address(unsigned char* buf) {
    int ip_header_len = (buf[0] & 0x0F) * 4;

    int tcp_header_len = ((buf[ip_header_len + 12] >> 4) & 0x0F) * 4;

    unsigned char* http_start = buf + ip_header_len + tcp_header_len;

    return http_start;
}

bool isHTTP(unsigned char* buf, int length) {
    unsigned char* http_start = get_http_start_address(buf);

    if (http_start - buf >= length) {
        return false;
    }

    const char* methods[] = {
        "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT"
    };

    for (int i = 0; i < sizeof(methods) / sizeof(methods[0]); i++) {
        if (strncmp((char*)http_start, methods[i], strlen(methods[i])) == 0) {
            return true;
        }
    }
    return false;
}

// 이진 탐색 함수
bool binarySearch(FILE *hSite, const unsigned char *site) {
    fseek(hSite, 0, SEEK_END);
    long fileSize = ftell(hSite);

    long left = 0, right = fileSize - 1;

    char buffer[105];

    while (left <= right) {
        long middle = left + (right - left) / 2;

        fseek(hSite, middle, SEEK_SET);
        fgets(buffer, sizeof(buffer), hSite);

        buffer[strcspn(buffer, "\n")] = '\0';

        int cmp = strcmp((const char *)site, buffer);

        if (cmp == 0) {
            return true;
        } else if (cmp < 0) {
            right = middle - 1;
        } else {
            left = middle + 1;
        }
    }

    // 탐색 실패
    return false;
}


bool isHost(unsigned char* site, FILE *hSite) {
    return binarySearch(hSite,site);
}

unsigned char* dump(unsigned char* buf, int size) {
    unsigned char* http_start = get_http_start_address(buf);
    int start_idx = 0;

    for (int i = 0; i < size - 1; i++) {
        if (http_start[i] == '\r' && http_start[i + 1] == '\n') {
            start_idx = i + 2;
            break;
        }
    }

    // Host 헤더 시작 위치로 이동
    http_start += start_idx + 6;

    if (host_str != NULL) {
        free(host_str); // 이전에 할당된 host_str 메모리 해제
    }

    host_str = malloc(256);
    if (!host_str) {
        return NULL;
    }

    int host_len = 0;
    while (http_start[host_len] != '\r' && http_start[host_len + 1] != '\n') {
        host_str[host_len] = http_start[host_len];
        host_len++;
    }
    host_str[host_len] = '\0';

    return host_str;
}

static u_int32_t print_pkt(struct nfq_data *tb) {
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark, ifi;
    int ret;
    unsigned char *data;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
    }

    hwph = nfq_get_packet_hw(tb);

    mark = nfq_get_nfmark(tb);

    ifi = nfq_get_indev(tb);

    ifi = nfq_get_outdev(tb);

    ifi = nfq_get_physindev(tb);

    ifi = nfq_get_physoutdev(tb);

    ret = nfq_get_payload(tb, &data);
    if (ret >= 0 && isHTTP(data, ret)) {
        host_str = dump(data, ret);
        ack = true;
    }

    fputc('\n', stdout);

    return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data) {
    u_int32_t id = print_pkt(nfa);

    if (ack) {
        for (int i = 0; i < arrSize; i++) {
            if (isHost(host_str, txtFile)) {
                printf("blocked! site : %s\n\n", host_str);
                free(host_str);
                ack = false;
                host_str = NULL;
                return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
            }
        }
    }

    ack = false;
    host_str = NULL;
    fseek(txtFile, 0, SEEK_SET);
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv) {
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    txtFile=fopen(argv[1],"r+");
	if(harmfulSite==NULL){
		printf("오류..;;;");
	}

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <site1> <site2> ... <siteN>\n", argv[0]);
        return 1;
    }

    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    qh = nfq_create_queue(h, 0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    nfq_destroy_queue(qh);
    nfq_close(h);

    return 0;
}