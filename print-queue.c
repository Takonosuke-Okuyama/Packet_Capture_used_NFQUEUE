// queueに来たパケットの中身を表示するプログラム
// queue num 1

#include <stdio.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/pktbuff.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netdb.h>
#include <errno.h>

#define QUEUE_ID 1

int queue_system(struct nfq_q_handle *, struct nfgenmsg *, struct nfq_data *, void *);
void print_queue(struct nfqnl_msg_packet_hdr *header, const char *payload_buf, int len);

int main(void){
  struct nfq_handle *nfqh;
  struct nfq_q_handle *nfqqh;
  char buf[0x10000];
  int len, fd;

  nfqh = nfq_open();

  nfq_unbind_pf(nfqh, PF_INET);
  nfq_bind_pf(nfqh, PF_INET);

  nfqqh = nfq_create_queue(nfqh, QUEUE_ID, queue_system, NULL);

  nfq_set_mode(nfqqh, NFQNL_COPY_PACKET, sizeof(buf));

  fd = nfq_fd(nfqh);

  printf("---start packet capture---\n\n");
  while((len = read(fd, buf, sizeof(buf))) >= 0) {
    nfq_handle_packet(nfqh, buf, len);
  }

  nfq_unbind_pf(nfqh, PF_INET);
  nfq_close(nfqh);

  return 0;
}


int queue_system(struct nfq_q_handle *qh, struct nfgenmsg *msg, struct nfq_data *nfdata, void *data){
  struct nfqnl_msg_packet_hdr *header;
  char *payload;
  int len, container_number;
  struct pkt_buff *pkBuff;

  header = nfq_get_msg_packet_hdr(nfdata);
  len = nfq_get_payload(nfdata, (char **)&payload);

  pkBuff = pktb_alloc(PF_INET, payload, len, 0x1000);
  // THROW_IF_TRUE(pkBuff == nullptr, "Issue while pktb allocate.");

  print_queue(header , payload, len);
  printf("\n");

  pktb_free(pkBuff); // Don't forget to clean up
  return nfq_set_verdict(qh, ntohl(header->packet_id), NF_ACCEPT, 0, NULL);
}


void print_queue(struct nfqnl_msg_packet_hdr *header, const char *payload_buf, int len){
  int i;
  struct iphdr *ip;
  struct icmphdr *icmp;
  struct tcphdr *tcp;
  struct udphdr *udp;

  ip =  (struct iphdr *) payload_buf;
  printf("************iphdr size:%ld ************ \n", sizeof(struct iphdr));
  printf("version: %x, ihl: %x, tos: %02X,  tot_len: %04X, id: %04X \n", ip->version, ip->ihl, ip->tos, ip->tot_len, ip->id);
  printf("frag_off: %02X, ttl: %02X,  protocol: %02X check: %04X \n", ip->frag_off, ip->ttl, ip->protocol, ip->check);
  printf("srcx: %08X, dstx: %08X \n", ip->saddr, ip->daddr);

  if(ip->protocol == IPPROTO_ICMP){
    icmp = (struct icmphdr *)(payload_buf + sizeof(struct iphdr));
    printf("***********icmphdr size:%ld***********\n", sizeof(struct icmphdr));
    printf("type: %02X, code: %02x , checksum: %04X, id: %04X \n", icmp->type, icmp->code, icmp->checksum, icmp->un.echo.id);
    printf("sequence: %04X, gateway: %08X, __glibc_reserved: %04X, mtu: %04X\n", icmp->un.echo.sequence, icmp->un.gateway, icmp->un.frag.__glibc_reserved, icmp->un.frag.mtu);
  }else if(ip->protocol == IPPROTO_TCP){
    tcp = (struct tcphdr *)(payload_buf + sizeof(struct iphdr));
    printf("************tcphdr size:%ld*********** \n", sizeof(struct tcphdr));
    printf("*****sport: %04X, dport: %04X , th_seq: %08X, th_ack: %08X, th_x2: %X \n", tcp->th_sport, tcp->th_dport, tcp->th_seq, tcp->th_ack, tcp->th_x2);
    printf("*****th_off: %0X , th_flags: %02X, th_win: %04X, th_sum: %04X, th_urp: %04X \n", tcp->th_off, tcp->th_flags, tcp->th_win, tcp->th_sum, tcp->th_urp);
    printf("source: %04X, dest: %04X, seq: %08X, ack_seq: %08X \n", tcp->source, tcp->dest, tcp->seq, tcp->ack_seq);
    printf("doff: %01X , res1: %X, res2: %X \n", tcp->doff, tcp->res1, tcp->res2);
    printf("urg: %X, ack: %X, psh: %X, rst: %X, syn: %X, fin: %X \n", tcp->urg, tcp->ack, tcp->psh, tcp->rst, tcp->syn, tcp->fin);
    printf("window: %04X , check_sum: %04X, urg_pointa: %04X \n", tcp->window, tcp->check, tcp->urg_ptr);
  }else if(ip->protocol == IPPROTO_UDP){
    udp = (struct udphdr *)(payload_buf + sizeof(struct iphdr));
    printf("************udphdr size:%ld*********** \n", sizeof(struct udphdr));
    printf("*****uh_sport: %04X, uh_dport: %04X , uh_len: %04X, uh_sum: %04X \n", udp->uh_sport, udp->uh_dport, udp->uh_ulen, udp->uh_sum);
    printf("source: %04X, dest: %04X, len: %04X, check: %04X \n", udp->source, udp->dest, udp->len, udp->check);
  }


  printf("*********packet %d**********\n", len);
  for(i = 0; i < len; ++i) {
      printf("%02X ", (unsigned char)payload_buf[i]);
  if(((i+1)%20 == 0) && (i != 0))
    printf("\n");
  }
  printf("\n");
}
