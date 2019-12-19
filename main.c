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

#define SWAP16(i)  ( ((i<<8)&0xFF00) | (((uint16_t)i >> 8)&0x00FF ))

uint8_t const localcast [ETHER_ADDR_LEN]={0x00,0xB0,0x52,0x00,0x00,0x01};

struct __attribute__((packed)) qualcomm_std
{
  unsigned char MMV;
  unsigned short MMTYPE;
  unsigned char OUI [ETHER_ADDR_LEN >> 1];
};

typedef struct __attribute__((packed)) homeplug_fmi 
{
  uint8_t MMV;
  uint16_t MMTYPE;
#if 0 
  uint8_t FMID;
  uint8_t FMSN;
#else
  uint8_t FMSN;
  uint8_t FMID;
#endif
}homeplug_fmi;

typedef struct __attribute__((packed)) homeplug 
{
  struct ethhdr ethernet;
  struct homeplug_fmi homeplug;
  uint8_t content [ETHERMTU - sizeof (struct homeplug_fmi)];
}HOMEPLUG;

struct __attribute__((packed)) qualcomm_fmi 
{
  uint8_t MMV;
  uint16_t MMTYPE;
#if 0 
  uint8_t FMID;
  uint8_t FMSN;
#else
  uint8_t FMSN;
  uint8_t FMID;
#endif
  uint8_t OUI [ETHER_ADDR_LEN >> 1];
};

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

int UnwantedMessage (void const * memory, size_t extent, uint8_t MMV, uint16_t MMTYPE) 
{
//  extern const byte localcast [ETHER_ADDR_LEN];
  struct homeplug * homeplug = (struct homeplug *)(memory);
  fprintf(stderr, "dmac=%02x:%02x:%02x:%02x:%02x:%02x\n", 
    homeplug->ethernet.h_dest[0],
    homeplug->ethernet.h_dest[1],
    homeplug->ethernet.h_dest[2],
    homeplug->ethernet.h_dest[3],
    homeplug->ethernet.h_dest[4],
    homeplug->ethernet.h_dest[5]);
  fprintf(stderr, "smac=%02x:%02x:%02x:%02x:%02x:%02x\n", 
    homeplug->ethernet.h_source[0],
    homeplug->ethernet.h_source[1],
    homeplug->ethernet.h_source[2],
    homeplug->ethernet.h_source[3],
    homeplug->ethernet.h_source[4],
    homeplug->ethernet.h_source[5]);
  fprintf(stderr, "ethtype=0x%04x\n", homeplug->ethernet.h_proto);
  if (!extent){
    fprintf(stderr,"%s:%d extend is 0.\n",__FUNCTION__,__LINE__);
    return (-1);
  }
  if (extent < (ETHER_MIN_LEN - ETHER_CRC_LEN)){
    fprintf(stderr,"%s:%d extend is less than 60.\n",__FUNCTION__,__LINE__);
    return (-1);
  }
  if (extent > (ETHER_MAX_LEN)){
    fprintf(stderr,"%s:%d extend is larger than 1518.\n",__FUNCTION__,__LINE__);
    return (-1);
  }
  if (homeplug->ethernet.h_proto != htons (HOMEPLUG_MTYPE)){
    fprintf(stderr,"%s:%d eth type is not matched.\n",__FUNCTION__,__LINE__);
    return (-1);
  }
  if (homeplug->homeplug.MMV != MMV){
    fprintf(stderr,"%s:%d MMV is not matched.\n",__FUNCTION__,__LINE__);
    return (-1);
  }
  if (homeplug->homeplug.MMV == 0){
    struct qualcomm_std * qualcomm = (struct qualcomm_std *)(&homeplug->homeplug);
    if (SWAP16(qualcomm->MMTYPE) != MMTYPE){
  	  fprintf(stderr,"%s:%d MMTYPE is not matched.\n",__FUNCTION__,__LINE__);
  	  return (-1);
    }
    if ((MMTYPE < VS_MMTYPE_MIN) || (MMTYPE > VS_MMTYPE_MAX)){
    }
    else if (memcmp (localcast, qualcomm->OUI, sizeof (qualcomm->OUI))){
      fprintf(stderr,"%s:%d OUI is not matched.\n",__FUNCTION__,__LINE__);
      return (-1);
    }
  }
  if (homeplug->homeplug.MMV == 1){
    struct qualcomm_fmi * qualcomm = (struct qualcomm_fmi *)(&homeplug->homeplug);
  
#if FMI  
    static unsigned total = 0;
    static unsigned index = 0;
    static unsigned count = 0;  
#endif
  
    if (SWAP16(qualcomm->MMTYPE) != MMTYPE){		
  	  fprintf(stderr,"%s:%d MMTYPE is not matched.\n",__FUNCTION__,__LINE__);
  	  return (-1);
    }
  
#if FMI  
    index = qualcomm->FMID >> 0 & 0x0F;
    if (!index){
      total = qualcomm->FMID >> 4 & 0x0F;
      count = qualcomm->FMID >> 0 & 0x0F;
      if (memcmp (localcast, qualcomm->OUI, sizeof (qualcomm->OUI))){
        return (-1);
      }
    }
    if (index != count){
      return (-1);
    }
    if (count > total){  
      return (-1);
    }
    count++;
#endif  
  }
  return (0);
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
  request->qca_hdr.MMTYPE=SWAP16(VS_SW_VER | MMTYPE_REQ);
  request->qca_hdr.OUI[0]=0x00;
  request->qca_hdr.OUI[1]=0xB0;
  request->qca_hdr.OUI[2]=0x52;

  len=send(sk, message, (ETHER_MIN_LEN - ETHER_CRC_LEN), 0);
  if(len <= 0){
    fprintf(stderr, "send socket failed: %s\n", strerror(errno));
  }
}

int recvpacket(int sk){
  fd_set rfds;
  struct timeval tv;
  int retval;
  unsigned char message[256];
  unsigned int len=0;

  for(;;){
    /* recv homeplug response from raw socket . */
    FD_ZERO(&rfds);
    FD_SET(0, &rfds);

    /* Wait up to 0.5 seconds. */
    tv.tv_sec = 0;
    tv.tv_usec = 500000;	/* 0.5s */

    retval = select(1, &rfds, NULL, NULL, &tv);
    /* Don't rely on the value of tv now! */

    if (retval == -1){
      fprintf(stderr, "select failed: %s\n", strerror(errno));
      goto err;
    }else if (retval){
      printf("Data is available now.\n");
      /* FD_ISSET(0, &rfds) will be true. */
      memset(message, 0x0, sizeof(message));
      len=read(sk, message, sizeof(message));
      if(len>0){
        if(UnwantedMessage (message, len, 0, (VS_SW_VER | MMTYPE_CNF))){
          continue;
        }
      }
    }else{
       fprintf(stderr, "No data within %d.%d seconds.\n", tv.tv_sec, tv.tv_usec);
       goto err;
    }
  }
  return 0;
err:
  return -1;
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
  recvpacket(sk);

  return 0;
}
