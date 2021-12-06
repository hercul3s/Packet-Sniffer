#pragma region include / define / variable ...
#include "PacketsOps.h"


//
BOOL isLsCryption, isGsCryption;
UINT i;
HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);
CJvCryption JV_Encryption;
CRijndael AES_Encryption;
SYSTEMTIME currentTime;
#pragma endregion

//void TxtLog(const char* fmt, ...)
//{
//	if (!fmt)	return;
//
//	char		text[4096];
//	va_list		ap;
//	va_start(ap, fmt);
//	vsprintf_s(text, fmt, ap);
//	va_end(ap);
//
//	TCHAR path[_MAX_PATH] = _T("");
//
//	SHGetFolderPath(nullptr, CSIDL_DESKTOP, nullptr, NULL, path);
//
//	strcat(path, "\\PacketLog.txt");
//	std::ofstream logfile(path, std::ios::app);
//	if (logfile.is_open() && text) {
//		logfile << text;
//	}
//	logfile.close();
//}

void LsCryptionKeyHandler(Packet& pkt)
{
	uint8 key[8];
	for (i = 0; i < 8; i++)
	{
		pkt >> key[i];
	}
	SetConsoleTextAttribute(console, FOREGROUND_RED);
	printf("[LSCryptionKey : %02llu]", sizeof key);
	for (i = 0; i < 8; i++)
	{
		printf("%hhX", key[i]);
	}
	printf("\n");
	JV_Encryption.JvInitialize(key);
}

void GsCryptionKeyHandler(Packet& pkt)
{
	uint8 idk, keySize;
	uint16 version;
	uint32 key[4] = { 0 };
	pkt >> idk >> version >> keySize;
	for (i = 0; i < 4; i++)
		pkt >> key[i];

	SetConsoleTextAttribute(console, FOREGROUND_RED);
	printf("[Game Version : %d]\n", version);
	printf("[GSCryptionKey : %02llu]", sizeof key);
	for (i = 0; i < 4; i++)
	{
		printf("%04X", key[i]);
	}
	printf("\n");
	AES_Encryption.RijndaelInitialize(reinterpret_cast<DWORD*>(key));
}

void PrintPacketTitle(int len, std::string src, SYSTEMTIME currentTime)
{
	SetConsoleTextAttribute(console, FOREGROUND_GREEN | FOREGROUND_RED);
	printf("Packet [Length=%u Owner=%s ---> Time=%d/%d/%d %d:%d:%d.%d]\n",//HERE
		len, src.c_str(), currentTime.wYear, currentTime.wMonth, currentTime.wDay,
		currentTime.wHour, currentTime.wMinute, currentTime.wSecond, currentTime.wMilliseconds);
	/*TxtLog("Packet [Length=%u Owner=%s ---> Time=%d/%d/%d %d:%d:%d.%d]\n",
		len, src.c_str(), currentTime.wYear, currentTime.wMonth, currentTime.wDay,
		currentTime.wHour, currentTime.wMinute, currentTime.wSecond, currentTime.wMilliseconds);*/

}

void PrintPacket(BYTE* packet, int len)
{
	if (packet[0] == WIZ_COMPRESS_PACKET)
	{
		SetConsoleTextAttribute(console, FOREGROUND_GREEN);
		printf("-----[%s / %s]-----\n", opCode(packet[0]), opCode(packet[14]));
		/*TxtLog("-----[%s / %s]-----\n", opCode(packet[0]), opCode(packet[14]));*/
	}
	else
	{
		SetConsoleTextAttribute(console, FOREGROUND_GREEN);
		printf("-----[%s]-----\n", opCode(packet[0]));
		//TxtLog("-----[%s]-----\n", opCode(packet[0]));
	}

	SetConsoleTextAttribute(console, FOREGROUND_GREEN | FOREGROUND_BLUE);
	for (i = 0; i < static_cast<unsigned>(len); i++)
	{
		if (i % 20 == 0)
		{
			printf("\n\t");
			//TxtLog("\n\t");
		}
		printf("%.2X", packet[i]);
		//TxtLog("%.2X", packet[i]);
	}
	SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_BLUE);
	for (i = 0; i < static_cast<unsigned>(len); i++)
	{
		if (i % 40 == 0)
		{
			printf("\n\t");
			//TxtLog("\n\t");
		}
		if (isprint(packet[i]))
		{
			putchar(packet[i]);
			//TxtLog("%c", packet[i]);
		}
		else
		{
			putchar('.');
			//TxtLog(".");
		}
	}
	putchar('\n');
	//TxtLog("\n");
}

bool FooterCheck(BYTE* pkt, int size)
{
	if (pkt[size - 2] == 0x55 && pkt[size - 1] == 0xAA)
	{
		return true;
	}
	return false;
}

bool HeaderCheck(BYTE* pkt)
{
	if (pkt[0] == 0xAA && pkt[1] == 0x55)
	{
		return true;
	}
	return false;
}

int RemoveHeaderAndResize(BYTE* pkt)
{

	if (pkt[0] == 0xAA && pkt[1] == 0x55)
	{
		const short reelSize = *reinterpret_cast<short*>(pkt + 2);
		if (reelSize > 0)
		{
			CopyMemory(pkt, pkt + 4, reelSize);
			return reelSize;
		}
	}
	else
	{
		printf("First Header Err.");
	}
	return -1;
}

void DecryptAndPrintOpr(BYTE* m_Data, SYSTEMTIME currentTime, std::string srcStr)
{
	int m_DataLen = RemoveHeaderAndResize(m_Data);

#ifdef CRYPTION

	if (m_Data[0] == LS_CRYPTION && m_DataLen == 0x01)
	{
		isLsCryption = FALSE;
		PrintPacketTitle(m_DataLen, srcStr, currentTime);
		PrintPacket(m_Data, m_DataLen);
		return;
	}

	if (m_Data[0] == LS_CRYPTION && m_DataLen == 0x09)
	{
		isLsCryption = TRUE;
		Packet pkt(m_Data[0], static_cast<size_t>(m_DataLen--));
		pkt.resize(m_DataLen);
		memcpy((void*)pkt.contents(), &m_Data[1], m_DataLen);
		LsCryptionKeyHandler(pkt);
		m_DataLen++;
		PrintPacketTitle(m_DataLen, srcStr, currentTime);
		PrintPacket(m_Data, m_DataLen);
		return;
	}

	if (m_Data[0] == WIZ_VERSION_CHECK && m_Data[1] == 0xFF && m_DataLen == 0x03)
	{
		isLsCryption = FALSE;
		isGsCryption = FALSE;
		PrintPacketTitle(m_DataLen, srcStr, currentTime);
		PrintPacket(m_Data, m_DataLen);
		return;
	}

	if (m_Data[0] == WIZ_VERSION_CHECK && m_Data[1] == 0 && m_DataLen == 0x16)
	{
		isGsCryption = TRUE;
		Packet pkt(m_Data[0], static_cast<size_t>(m_DataLen--));
		pkt.resize(m_DataLen);
		memcpy((void*)pkt.contents(), &m_Data[1], m_DataLen);
		GsCryptionKeyHandler(pkt);
		m_DataLen++;
		PrintPacketTitle(m_DataLen, srcStr, currentTime);
		PrintPacket(m_Data, m_DataLen);
		return;
	}

	if (isLsCryption == TRUE)
	{
		JV_Encryption.Cryption(m_Data, m_DataLen, false);
		m_DataLen -= 5;
		memcpy(&m_Data[0], &m_Data[5], m_DataLen);
		PrintPacketTitle(m_DataLen, srcStr, currentTime);
		PrintPacket(m_Data, m_DataLen);
		return;
	}

	if (isGsCryption == TRUE)
	{
		
		AES_Encryption.Cryption(m_Data, m_DataLen, false, m_Data);
		if (m_DataLen > 500)
		{
			if (m_Data[0] == WIZ_COMPRESS_PACKET)
			{

				const long inLen = *reinterpret_cast<long*>(m_Data + 1);
				const long outLen = *reinterpret_cast<long*>(m_Data + 5);				
					
				BYTE* out = new BYTE[outLen + BUFFERSIZETOLERANCE];
				m_DataLen = lzf_decompress(m_Data + 13, inLen, out, outLen);
				PrintPacketTitle(m_DataLen, srcStr, currentTime);
				PrintPacket(out, m_DataLen);
				delete []out;
				return;
			}

		}
		
		PrintPacketTitle(m_DataLen, srcStr, currentTime);
		PrintPacket(m_Data, m_DataLen);
		return;
	}

#endif
	PrintPacketTitle(m_DataLen, srcStr, currentTime);
	PrintPacket(m_Data, m_DataLen);
}

void PacketsOps::DataCheckAndMerge(BYTE* m_Data, int m_DataLen, std::string srcStr)
{
	
	if (HeaderCheck(m_Data))
	{
		//Normal Packet Print //AA 55 ------ 55 AA
		if (FooterCheck(m_Data, m_DataLen))
		{
			GetLocalTime(&currentTime);
			DecryptAndPrintOpr(m_Data, currentTime, srcStr); //Here
			return;
		}

		// Packet Merge Start //AA 55 -- --
		

		mergedPacketBuffer = static_cast<BYTE*>(malloc(MERGEDPACKETBUFFERSIZE * sizeof(BYTE)));
		CopyMemory(&mergedPacketBuffer[0], m_Data, m_DataLen);
		mergedPacketSize = m_DataLen;
		return;
	}
	if (FooterCheck(m_Data, m_DataLen))
	{
		// Packet Merge Finish And Print //-- -- 55 AA
		GetLocalTime(&currentTime);
		CopyMemory(&mergedPacketBuffer[mergedPacketSize], m_Data, m_DataLen);
		mergedPacketSize = mergedPacketSize + m_DataLen;
		DecryptAndPrintOpr(mergedPacketBuffer, currentTime, srcStr);
		mergedPacketSize = NULL;		
		free(mergedPacketBuffer);
		 //free
		return;
	}
	// Packet Merge To Be Continued // -- -- -- --
	CopyMemory(&mergedPacketBuffer[mergedPacketSize], m_Data, m_DataLen);
	mergedPacketSize = mergedPacketSize + m_DataLen;
}

