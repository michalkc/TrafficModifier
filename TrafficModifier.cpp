/*PROJEKT OINS*/

/*STEGANOGRAFIA*/

//Michal Kocon
//Mateusz Chomiczewski

#include <winsock2.h>
#include <windows.h>
#include <iostream>
#include <fstream>

#include "windivert.h"

#define MAXBUF  0xFFFF

std::string filename;

void setHiddenMessage(PWINDIVERT_IPHDR ip_header, PWINDIVERT_TCPHDR tcp_header, UINT payload_len);
static DWORD passthru(LPVOID arg);

int __cdecl main(int argc, char **argv){
	int num_threads = 1;


	if (argc < 2) 
		filename = "antygona.txt";
	if (argc == 2)
		filename = argv[1];


	HANDLE handle, thread;
	handle = WinDivertOpen(
		"outbound && "              // Outbound traffic
		"ip && "                    // Only IPv4
	//	"tcp.SrcPort == 8000 &&"		// port 8000
		"tcp.SrcPort == 8000",		// port 8000
	//	"tcp.PayloadLength > 0",    // TCP data packets only
		WINDIVERT_LAYER_NETWORK, 0, 0
	);
	if (handle == INVALID_HANDLE_VALUE)
	{
		std::cerr << "error: failed to open the WinDivert device: " << GetLastError() << std::endl;
		exit(EXIT_FAILURE);
	}

	// Start the threads
	for (int i = 1; i < num_threads; i++){
		thread = CreateThread(NULL, 1, (LPTHREAD_START_ROUTINE)passthru,
			(LPVOID)handle, 0, NULL);
		if (thread == NULL){
			std::cerr << "error: failed to start a thread" << std::endl;
			exit(EXIT_FAILURE);
		}
	}

	// Main thread:
	passthru((LPVOID)handle);

	return 0;
}

static DWORD passthru(LPVOID arg){
	unsigned char packet[MAXBUF];
	UINT packet_len, payload_len;
	WINDIVERT_ADDRESS addr;
	HANDLE handle = (HANDLE)arg;
	PWINDIVERT_IPHDR ip_header;
	PWINDIVERT_TCPHDR tcp_header;
	
	bool addr_initialized = false;
	UINT32 dst_addr;
	// Main loop:
	while (true){
		// Read a matching packet.
		if (!WinDivertRecv(handle, packet, sizeof(packet), &addr, &packet_len)){
			std::cerr << "Message read error: " << GetLastError() << std::endl;
			continue;
		}
		
		WinDivertHelperParsePacket(packet, packet_len, &ip_header, NULL, NULL, NULL, &tcp_header, NULL, NULL, &payload_len);
		if (!addr_initialized) 
			dst_addr = ip_header->DstAddr; //get 1st connected addr as intercept server
		if (ip_header->DstAddr == dst_addr)	
			setHiddenMessage(ip_header, tcp_header, payload_len); //if ip addr matches, include hidden message

		// Re-inject the matching packet.
		if (!WinDivertSend(handle, packet, packet_len, &addr, NULL)){
			std::cerr << "Message send error: " << GetLastError() << std::endl;
			continue;
		}

	}
}
//hides message in tcp/ip packet
void setHiddenMessage(PWINDIVERT_IPHDR ip_header, PWINDIVERT_TCPHDR tcp_header, UINT payload_len) {
	static char byte; // byte from file
	static int bit_num = 8; // bit to write in byte
	static std::ifstream message; 
	static UINT16 id_difference = 0; //difference between actual and changed ip.id. This ensures 2 packets won't have the same id
	static UINT16 id_last = 0;

	if (bit_num == 8) {
		if (!message.is_open())
			message.open(filename.c_str() , std::ios::in | std::ios::binary);
		message.read(&byte, 1);
		bit_num = 0;

		if (message.eof()) { //loop writing hidden message from file
			message.close();
			message.open(filename.c_str(), std::ios::in | std::ios::binary);
		}

		if (!message.is_open()) {
			std::cerr << "Couldn't open file" << std::endl;
			exit(EXIT_FAILURE);
		}
	}
	if (payload_len == 0) { //when there is no payload, system often jumps with id num because of other transmission, so we got chance to synchroinize with it 
		UINT16 diff = ip_header->Id - id_last;
		if (diff >= id_difference) 
			id_difference = 0;
		else 
			id_difference -= diff;
	}
	else{
		if (bit_num < 8) {
			char bit = 0x01 & (byte >> bit_num);
			if (bit == 1) {
				++id_difference; // +2 to ip id when bit is set to 1
			}
			else {}
			++bit_num;
		}
	}

	//id field is saved backwards, so we need to add 1st byte of ipheader->id and 2nd byte of id_difference and vice versa
	unsigned char* id = reinterpret_cast<unsigned char*>(&(ip_header->Id));
	unsigned char* diff = reinterpret_cast<unsigned char*>(&id_difference);

	int test = id[1] + diff[0];
	if (test > 255) //carry bit
		++id[0];

	id[0] += diff[1];
	id[1] += diff[0];

	id_last = ip_header->Id;

}
