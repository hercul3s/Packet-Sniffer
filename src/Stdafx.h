#pragma once
#include <shlobj_core.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <iostream>
#include <iosfwd>
#include <fstream>
#include <tchar.h>
#include <pthread.h>
#include <memory>
#include "..\WinDivert\include\WinDivert.h"
#include "Cryption/RijndaelCryption.h"
#include "Cryption/JvCryption.h"
#include "Packet Opr/Packet.h"
#include "Packet Opr/PacketsDefine.h"
#include "Packet Opr/PacketsOps.h"
#include "Compression/Crc32.h"
#include "Compression/Lzf.h"
#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable : 4996)
//#pragma warning(disable : 4099)
//#pragma warning(disable : 4800)
#define ntohs(x)            WinDivertHelperNtohs(x)
#define ntohl(x)            WinDivertHelperNtohl(x)
#define MAXBUF              WINDIVERT_MTU_MAX
#define INET6_ADDRSTRLEN    45
#define MAX_MYDATA 1460
#define BUFFERSIZETOLERANCE 64*100
#define MAX_BUFFERSIZE 4*1000
#define MAX_DECOMPRESSBUFFERSIZE 1024*100
#define MERGEDPACKETBUFFERSIZE 1024*100

//#define TEST_FILTER_RULE_	"inbound and tcp.DstPort >= 15100 && tcp.DstPort <= 15110 && ip && (tcp.SrcPort == 15001 || tcp.DstPort == 15001)"
//#define FILTER_RULE			"tcp.Payload[-2] == 0x55 && tcp.Payload[-1] == 0xAA && tcp.Payload[0] == 0xAA && tcp.Payload[1] == 0x55"
//#define FILTER_RULE			"tcp.DstPort >= 15100 && tcp.DstPort <= 15110 || tcp.SrcPort >= 15100 && tcp.DstPort <= 15110"
#define FILTER_RULE			"tcp.DstPort == 15001 || tcp.SrcPort == 15001"
//#define FILTER_RULE			"tcp.Port == 15001 && tcp.Port == 15100"
#define CRYPTION FALSE


