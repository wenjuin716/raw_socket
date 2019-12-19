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

#define ETHTYPE_HOMEPLUG_AV	0x88E1

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
      fprintf(stderr, "adapter hardware address %02x:%02x:%02x:%02x:%02x:%02x",
        arp[0], arp[1], arp[2], arp[3], arp[4], arp[5]);
    } else {
      fprintf(stderr, "SIOCGIFHWADDR failed!: %s", strerror(errno));
      return -1;
    }

  } else {
    fprintf(stderr, "socket failed!: %s\n", strerror(errno));
    return -1;
  }
  close(fd);
  return 0;
}

void sendpacket(int sk){
  struct ether_header header;
  struct qualcomm_std qca_header;

  
}

int main(int argc, char **argv){

  int sk;
  struct sockaddr_ll sock;
  unsigned char mac[6];

  //sock=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
  sk=socket(AF_PACKET,SOCK_RAW,htons(ETHTYPE_HOMEPLUG_AV));
  if(sk<0)
  {
    fprintf(stderr, "create socket failed: %s\n", strerror(errno));
    return -1;
  }

  sock.sll_family = AF_PACKET;
  sock.sll_protocol = htons(ETHTYPE_HOMEPLUG_AV);
//  sock.sll_ifindex = ifindex;
  read_interface(argv[1], &sock.sll_ifindex, mac);
  if (bind(sk, (struct sockaddr *) &sock, sizeof(sock)) < 0) {
    fprintf(stderr, "bind call failed: %s\n", strerror(errno));
    close(sk);
    return -1;
  }

  fprintf(stderr, "ifname=%s, mac=%02x:%02x:%02x:%02x:%02x:%02x\n", argv[1], 
    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

  return 0;
}
