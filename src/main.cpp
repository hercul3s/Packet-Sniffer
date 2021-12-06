#pragma region include / define / variable ...
#include"Stdafx.h"
#include <memory>
#pragma endregion
#pragma region Entry
PacketsOps mPacketOps;
int main()
{	
	std::unique_ptr<BYTE[]> m_Data;
	UINT packet_len;
	constexpr INT16 priority = 0;
	WINDIVERT_ADDRESS addr;
	PWINDIVERT_IPHDR ip_header;
	PVOID tcpPayload = nullptr;
	UINT tcpPayloadLen = 0;
	
	const char* err_str;
	
	// Handle Divert
	const HANDLE handle = WinDivertOpen(FILTER_RULE, WINDIVERT_LAYER_NETWORK, priority, WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_FRAGMENTS);

#pragma region Divert traffic matching the filter
	if (handle == INVALID_HANDLE_VALUE)
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER &&
			!WinDivertHelperCompileFilter(FILTER_RULE, WINDIVERT_LAYER_NETWORK,
				NULL, 0, &err_str, NULL))
		{
			fprintf(stderr, "error: invalid filter \"%s\"\n", err_str);
			exit(EXIT_FAILURE);
		}
		fprintf(stderr, "error: failed to open the WinDivert device (%d)\n",
			GetLastError());
		exit(EXIT_FAILURE);
	}
#pragma endregion
#pragma region Max-out the packet queue:
	if (!WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_LENGTH,
		WINDIVERT_PARAM_QUEUE_LENGTH_MAX))
	{
		fprintf(stderr, "error: failed to set packet queue length (%d)\n",
			GetLastError());
		exit(EXIT_FAILURE);
	}
	if (!WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_TIME,
		WINDIVERT_PARAM_QUEUE_TIME_MAX))
	{
		fprintf(stderr, "error: failed to set packet queue time (%d)\n",
			GetLastError());
		exit(EXIT_FAILURE);
	}
	if (!WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_SIZE,
		WINDIVERT_PARAM_QUEUE_SIZE_MAX))
	{
		fprintf(stderr, "error: failed to set packet queue size (%d)\n",
			GetLastError());
		exit(EXIT_FAILURE);
	}
#pragma endregion

	// Main loop:
	while (TRUE)
	{
		unsigned char packet[MAXBUF];
		// Packet Read
		if (!WinDivertRecv(handle, packet, sizeof packet, &packet_len, &addr))
		{
			fprintf(stderr, "warning: failed to read packet (%lu)\n", GetLastError());
			continue;
		}

		// Packet Parse
		WinDivertHelperParsePacket
		(packet, packet_len, &ip_header, nullptr, nullptr, nullptr, nullptr, 
			nullptr, nullptr, &tcpPayload, &tcpPayloadLen, nullptr, nullptr);
	
		if (tcpPayload != nullptr)
		{
			char srcStr[INET6_ADDRSTRLEN + 1];
			WinDivertHelperFormatIPv4Address(ntohl(ip_header->SrcAddr), srcStr, sizeof srcStr);

			const int m_DataLen = static_cast<int>(tcpPayloadLen);	

			if (m_Data ==nullptr)
			{m_Data = std::make_unique<BYTE[]>(MAX_BUFFERSIZE);}
			
			memset(m_Data.get(), 0, m_DataLen);
			CopyMemory(m_Data.get(), tcpPayload, m_DataLen);
			//My Data Opr
			mPacketOps.DataCheckAndMerge(m_Data.get(), m_DataLen, srcStr); //here
						
			//use deleter & class hierarcy	
			//5.12.2021							
		}	
	}
}
#pragma endregion
