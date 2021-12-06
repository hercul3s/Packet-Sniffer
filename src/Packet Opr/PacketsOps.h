#pragma once
#include "..\Stdafx.h"

class PacketsOps
{
public:
	void DataCheckAndMerge(BYTE* myData, int m_DataLen, std::string srcStr);
private:
	BYTE* mergedPacketBuffer;
	int mergedPacketSize = NULL;
};

