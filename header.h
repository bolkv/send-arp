#ifdef __header
extern "C"{
#endif	
#include <stdint.h>
#ifdef __header
}
#endif

#define ARP_REQUEST 1
#define ARP_REPLY 2
#define PACKET_SIZE (sizeof(struct eth_header) + sizeof(struct arp_header))

struct eth_header{
	uint8_t dst_mac[6];
	uint8_t src_mac[6];
	uint16_t type;
};

struct arp_header{
	uint16_t hardware_type;
	uint16_t proto_type;
	uint8_t hardware_len;
	uint8_t proto_len;
	uint16_t opcode;
	uint8_t src_mac[6];
	uint8_t src_ip[4];
	uint8_t dst_mac[6];
	uint8_t dst_ip[4];

};
	
