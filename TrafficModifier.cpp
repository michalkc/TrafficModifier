/*
* passthru.c
* (C) 2013, all rights reserved,
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU Lesser General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/*
* DESCRIPTION:
* This program does nothing except divert packets and re-inject them.  This is
* useful for performance testing.
*
* usage: netdump.exe windivert-filter num-threads
*/

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>

#include "windivert.h"

#define MAXBUF  0xFFFF


void setHiddenMessage(PWINDIVERT_IPHDR ip_header, PWINDIVERT_TCPHDR tcp_header);
bool getTcpHandshake(PWINDIVERT_TCPHDR tcp_header, bool seed_initialized);


std::ifstream message;
UINT16 key;


static DWORD passthru(LPVOID arg);

/*
* Entry.
*/
int __cdecl main(int argc, char **argv)
{
	int num_threads = 1;
	HANDLE handle, thread;


	// Divert traffic matching the filter:
	//handle = WinDivertOpen(argv[1], WINDIVERT_LAYER_NETWORK, 0, 0);
	handle = WinDivertOpen(
		"outbound && "              // Outbound traffic only
		"ip && "                    // Only IPv4 supported
		"tcp.SrcPort == 8000",     // HTTP (port 80) only
								   //"tcp.PayloadLength > 0",    // TCP data packets only
		WINDIVERT_LAYER_NETWORK, 0, 0
	);
	if (handle == INVALID_HANDLE_VALUE)
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
		{
			fprintf(stderr, "error: filter syntax error\n");
			exit(EXIT_FAILURE);
		}
		fprintf(stderr, "error: failed to open the WinDivert device (%d)\n",
			GetLastError());
		exit(EXIT_FAILURE);
	}

	// Start the threads
	for (int i = 1; i < num_threads; i++)
	{
		thread = CreateThread(NULL, 1, (LPTHREAD_START_ROUTINE)passthru,
			(LPVOID)handle, 0, NULL);
		if (thread == NULL)
		{
			fprintf(stderr, "error: failed to start passthru thread (%u)\n",
				GetLastError());
			exit(EXIT_FAILURE);
		}
	}

	// Main thread:
	passthru((LPVOID)handle);

	return 0;
}

// Passthru thread.
static DWORD passthru(LPVOID arg)
{
	unsigned char packet[MAXBUF];
	UINT packet_len;
	WINDIVERT_ADDRESS addr;
	HANDLE handle = (HANDLE)arg;
	PWINDIVERT_IPHDR ip_header;
	PWINDIVERT_TCPHDR tcp_header;
	message.open("antygona.txt", std::ios::in | std::ios::binary);
	// Main loop:
	while (TRUE)
	{
		// Read a matching packet.
		if (!WinDivertRecv(handle, packet, sizeof(packet), &addr, &packet_len))
		{
			fprintf(stderr, "warning: failed to read packet (%d)\n",
				GetLastError());
			continue;
		}
		WinDivertHelperParsePacket(packet, packet_len, &ip_header, NULL, NULL, NULL, &tcp_header, NULL, NULL, NULL);
		setHiddenMessage(ip_header, tcp_header);
		// Re-inject the matching packet.
			if (!WinDivertSend(handle, packet, packet_len, &addr, NULL))
			{
				fprintf(stderr, "warning: failed to reinject packet (%d)\n",
					GetLastError());
			}
			//for (int i = 0; i < packet_len; ++i) std::cout << packet[i];
			//std::cout << std::endl;
	}
}

void setHiddenMessage(PWINDIVERT_IPHDR ip_header, PWINDIVERT_TCPHDR tcp_header) {
	std::cout << std::hex << ip_header->Id;
	char buffer[2];
	message.read(buffer, 2);
	UINT16* ms;
	ms = (UINT16*)buffer;
	//*ms = *ms^ key ^ key;
	ip_header->Id = *ms;
	std::cout << std::hex << " -> " << ip_header->Id << std::endl;
}

bool getTcpHandshake(PWINDIVERT_TCPHDR tcp_header, bool seed_initialized) {
	if (tcp_header->Syn && tcp_header->Ack) {
		srand(tcp_header->SeqNum);
		key = rand();
		return true;
	}
	else return false;
}
