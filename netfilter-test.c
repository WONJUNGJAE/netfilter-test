#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#pragma pack(push, 1)
struct IpHdr {
	u_int8_t  ip_header_len:4, ver:4;
	u_int8_t  tos;
	u_int16_t tot_len;
	u_int16_t id;
	u_int16_t frag_off;
	u_int8_t  ttl;
	u_int8_t  protocol;
	u_int16_t check;
	u_int32_t saddr;
	u_int32_t daddr;
};

struct TcpHdr {
	u_int16_t sport;
	u_int16_t dport;
	u_int32_t seq;
	u_int32_t ack_seq;
	u_int8_t  tcp_header_len:4, res:4;
	u_int8_t  flags;
	u_int16_t window;
	u_int16_t check;
	u_int16_t urg_ptr;
};
#pragma pack(pop)

char block_host[256];

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	     struct nfq_data *nfa, void *data)
{
	unsigned char *packet;
	int len = nfq_get_payload(nfa, &packet);
	u_int32_t id = ntohl(nfq_get_msg_packet_hdr(nfa)->packet_id);

	if (len < 0)
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

	struct IpHdr *ip = (struct IpHdr *)packet;
	if (ip->protocol != 6)
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

	int ip_len = ip->ip_header_len * 4;
	struct TcpHdr *tcp = (struct TcpHdr *)(packet + ip_len);
	if (ntohs(tcp->dport) != 80)
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

	int tcp_len = tcp->tcp_header_len * 4;
	char *http = (char *)tcp + tcp_len;
	int http_len = len - ip_len - tcp_len;
	if (http_len <= 0)
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

	char *host_start = NULL;
	int i;
	for (i = 0; i < http_len - 6; i++) {
		if (memcmp(http + i, "Host: ", 6) == 0) {
			host_start = http + i + 6;
			break;
		}
	}

	if (host_start != NULL) {
		char host[256] = {0};
		int j = 0;
		while (host_start[j] != '\r' && host_start[j] != '\n' && host_start[j] != '\0' && j < 255)
			host[j] = host_start[j++];

		if (strcmp(host, block_host) == 0)
			return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	}

	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
	strncpy(block_host, argv[1], sizeof(block_host) - 1);

	system("iptables -F");
	system("iptables -A OUTPUT -j NFQUEUE --queue-num 0");
	system("iptables -A INPUT  -j NFQUEUE --queue-num 0");

	struct nfq_handle   *h  = nfq_open();
	nfq_unbind_pf(h, AF_INET);
	nfq_bind_pf(h, AF_INET);
	struct nfq_q_handle *qh = nfq_create_queue(h, 0, &cb, NULL);
	nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff);

	int fd = nfq_fd(h);
	char buf[4096];

	while (1) {
		int rv = recv(fd, buf, sizeof(buf), 0);
		if (rv >= 0)
			nfq_handle_packet(h, buf, rv);
	}

	nfq_destroy_queue(qh);
	nfq_close(h);
	system("iptables -F");
	return 0;
}
