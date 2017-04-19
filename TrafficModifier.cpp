// ConsoleApplication2.cpp : Defines the entry point for the console application.
//

#include <WinSock2.h>
#include <Windows.h>
#include "windivert.h"
#include <iostream>
#include <fstream>
#include <cstdlib>


#include <cstring>


const int MAXBUF = 10000;
std::ifstream message;
UINT16 key;

void setHiddenMessage(PWINDIVERT_IPHDR ip_header, PWINDIVERT_TCPHDR tcp_header);
bool getTcpHandshake(PWINDIVERT_TCPHDR tcp_header, bool seed_initialized);

int main(){
	try {
		message.open("antygona.txt", std::ios::in);
	}
	catch (...) {
		std::cout << "Nie mozna otworzyc pliku antygona.txt";
		exit(1);
	}
	HANDLE handle;
	handle = WinDivertOpen(
		"outbound && "              // Outbound traffic only
		"ip && "                    // Only IPv4 supported
		"tcp.SrcPort == 8000",     // HTTP (port 80) only
//		"tcp.PayloadLength > 0",    // TCP data packets only
		WINDIVERT_LAYER_NETWORK, 404, 0
	);

	if (handle == INVALID_HANDLE_VALUE)
	{
		std::cout << "Error: " << GetLastError() << std::endl;
		system("pause");
		exit(1);
	}


	WINDIVERT_ADDRESS addr; // Packet address
	UINT8 packet[MAXBUF];    // Packet buffer
	UINT packetLen;
	PWINDIVERT_IPHDR ip_header;
	PWINDIVERT_TCPHDR tcp_header;
	PVOID payload;
	UINT payloadLen;

	// Main capture-modify-inject loop:

	bool seed_initialized = false;
	while (true)
	{
		if (!WinDivertRecv(handle, packet, sizeof(packet), &addr, &packetLen))
		{
			// Handle recv error
			continue;
		}
		
		

		if (!WinDivertHelperParsePacket(packet, packetLen, &ip_header, NULL, NULL, NULL, &tcp_header, NULL, NULL, NULL)) {
			
			if(seed_initialized) setHiddenMessage(ip_header, tcp_header);
			else seed_initialized = getTcpHandshake(tcp_header, seed_initialized);


			if (!WinDivertSend(handle, packet, packetLen, &addr, NULL))
			{
				std::cout << "Send error: " << GetLastError() << std::endl;
			}
			continue;
		}
	}
	return 0;
}

void setHiddenMessage(PWINDIVERT_IPHDR ip_header, PWINDIVERT_TCPHDR tcp_header) {
	std::cout << ip_header->Id << std::endl;
	//UINT16 ms;
	//message >> ms;
	//ms = ms ^ key ^ key;
	//ip_header->Id = ms;
}

bool getTcpHandshake(PWINDIVERT_TCPHDR tcp_header, bool seed_initialized) {
	if (tcp_header->Syn && tcp_header->Ack) {
		srand(tcp_header->SeqNum);
		key = rand();
		return true;
	}
	else return false;
}
