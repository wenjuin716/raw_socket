#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <errno.h>

#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>

#define HOMEPLUG_MTYPE 0x88E1

#define VS_SW_VER 0xA000
#define VS_MMTYPE_MIN 0xA000 
#define VS_MMTYPE_MAX 0xBFFF

#define MMTYPE_REQ 0x0000
#define MMTYPE_CNF 0x0001

#if 0
#define ETHERMTU 1500

/*
 * Some basic Ethernet constants.
 */
#define ETHER_ADDR_LEN          6       /* length of an Ethernet address */
#define ETHER_TYPE_LEN          2       /* length of the Ethernet type field */
#define ETHER_CRC_LEN           4       /* length of the Ethernet CRC */
#define ETHER_HDR_LEN           (ETHER_ADDR_LEN*2+ETHER_TYPE_LEN)
#define ETHER_MIN_LEN           64      /* minimum frame len, including CRC */
#define ETHER_MAX_LEN           1518    /* maximum frame len, including CRC */
#define ETHER_MAX_LEN_JUMBO     9018    /* max jumbo frame len, including CRC */
#endif

uint8_t const localcast [ETHER_ADDR_LEN]={0x00,0xB0,0x52,0x00,0x00,0x01};

struct qualcomm_std
{
  unsigned char MMV;
  unsigned short MMTYPE;
  unsigned char OUI [ETHER_ADDR_LEN >> 1];
} __attribute__((packed));

int read_interface(char *interface, int *ifindex, unsigned char *arp)
{
  int fd;
  struct ifreq ifr;
  
  memset(&ifr, 0, sizeof(struct ifreq));
  if((fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) >= 0) {
    ifr.ifr_addr.sa_family = AF_INET;
    strcpy(ifr.ifr_name, interface);
    
    if (ioctl(fd, SIOCGIFINDEX, &ifr) == 0) {
      fprintf(stderr, "adapter index %d\n", ifr.ifr_ifindex);
      *ifindex = ifr.ifr_ifindex;
    } else {
      fprintf(stderr, "SIOCGIFINDEX failed!: %s\n", strerror(errno));
      return -1;
    }

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
      memcpy(arp, ifr.ifr_hwaddr.sa_data, 6);
      fprintf(stderr, "adapter hardware address %02x:%02x:%02x:%02x:%02x:%02x\n",
        arp[0], arp[1], arp[2], arp[3], arp[4], arp[5]);
    } else {
      fprintf(stderr, "SIOCGIFHWADDR failed!: %s\n", strerror(errno));
      return -1;
    }

  } else {
    fprintf(stderr, "socket failed!: %s\n", strerror(errno));
    return -1;
  }
  close(fd);
  return 0;
}

void sendpacket(int sk, unsigned char *mac){
  unsigned char message[256];
  unsigned int len=0;
//  struct ethhdr header;
//  struct qualcomm_std qca_hdr;

  struct __attribute__((packed)) vs_sw_ver_request
  {
    struct ethhdr header;
    struct qualcomm_std qca_hdr;
  }* request = (struct vs_sw_ver_request *) (message);

  memcpy(request->header.h_dest, localcast, sizeof(request->header.h_dest));
  memcpy(request->header.h_source, mac, sizeof(request->header.h_source));
  request->header.h_proto=htons(HOMEPLUG_MTYPE);

  request->qca_hdr.MMV=0x0;
  request->qca_hdr.MMTYPE=(VS_SW_VER | MMTYPE_REQ);
  request->qca_hdr.OUI[0]=0x00;
  request->qca_hdr.OUI[1]=0xB0;
  request->qca_hdr.OUI[2]=0x52;

  len=send(sk, message, (ETHER_MIN_LEN - ETHER_CRC_LEN), 0);
  if(len <= 0){
    fprintf(stderr, "send socket failed: %s\n", strerror(errno));
  }
}

int main(int argc, char **argv){

  int sk;
  struct sockaddr_ll sock;
  unsigned char mac[6];

  //sock=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
  sk=socket(AF_PACKET,SOCK_RAW,htons(HOMEPLUG_MTYPE));
  if(sk<0)
  {
    fprintf(stderr, "create socket failed: %s\n", strerror(errno));
    return -1;
  }

  sock.sll_family = AF_PACKET;
  sock.sll_protocol = htons(HOMEPLUG_MTYPE);
//  sock.sll_ifindex = ifindex;
  read_interface(argv[1], &sock.sll_ifindex, mac);
  if (bind(sk, (struct sockaddr *) &sock, sizeof(sock)) < 0) {
    fprintf(stderr, "bind call failed: %s\n", strerror(errno));
    close(sk);
    return -1;
  }

  fprintf(stderr, "ifname=%s, mac=%02x:%02x:%02x:%02x:%02x:%02x\n", argv[1], 
    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

  sendpacket(sk, mac);

  return 0;
}
