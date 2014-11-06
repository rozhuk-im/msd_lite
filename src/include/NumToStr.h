/*
 * Copyright (c) 2005 - 2012 Rozhuk Ivan <rozhuk.im@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */



#if !defined(AFX_NUMTOSTR__H__INCLUDED)
#define AFX_NUMTOSTR__H__INCLUDED


#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000


#ifdef _WINDOWS
	#define uint8_t		unsigned char
	#define uint16_t	WORD
	#define int32_t		LONG
	#define uint32_t	DWORD
	#define int64_t		LONGLONG
	#define uint64_t	DWORDLONG
	#define	size_t		SIZE_T
	#define	ssize_t		SSIZE_T
#else
#include <inttypes.h>
#endif

static const size_t Num2Len[] = {
	0,
	10,
	100,
	1000,
	10000,
	100000,
	1000000,
	10000000,
	100000000,
	1000000000,
	10000000000,
	100000000000,
	1000000000000,
	10000000000000
};


static inline size_t
UNumToStr(size_t dwNum, LPSTR pString, size_t dwStringLen) {
	size_t dwRet=0;
	size_t dwNumtm=1;

	do
	{
		pString++;// перемещаем указатель на следующую позицию
		dwStringLen--;// уменьшаем длинну
		dwNumtm*=10;
	}while(dwNum>dwNumtm && dwStringLen);
	(*pString--)=0;


	if (dwStringLen)
	{
		do
		{
			dwNumtm=dwNum;
			dwNum/=10;

			(*pString)=(unsigned char)(48+(dwNumtm-(dwNum*10)));
			pString--;// перемещаем указатель на следующую позицию
		}while(dwNum);
	}

return (dwRet);
}


static inline DWORD
UNumToStr32(DWORD dwNum,LPSTR pString,size_t dwStringLen) {
	DWORD dwRet=0;
	DWORD dwNumtm=1;

	do
	{
		pString++;// перемещаем указатель на следующую позицию
		dwStringLen--;// уменьшаем длинну
		dwNumtm*=10;
	}while(dwNum>dwNumtm && dwStringLen);
	(*pString--)=0;


	if (dwStringLen)
	{
		do
		{
			dwNumtm=dwNum;
			dwNum/=10;

			(*pString)=(unsigned char)(48+(dwNumtm-(dwNum*10)));
			pString--;// перемещаем указатель на следующую позицию
		}while(dwNum);
	}	

return (dwRet);
}


static inline DWORD
UNumToStr64(DWORDLONG dwNum,LPSTR pString,size_t dwStringLen) {
	DWORD dwRet=0;
	DWORDLONG dwNumtm=1;

	do
	{
		pString++;// перемещаем указатель на следующую позицию
		dwStringLen--;// уменьшаем длинну
		dwNumtm*=10;
	}while(dwNum>dwNumtm && dwStringLen);
	(*pString--)=0;


	if (dwStringLen)
	{
		do
		{
			dwNumtm=dwNum;
			dwNum/=10;

			(*pString)=(unsigned char)(48+(dwNumtm-(dwNum*10)));
			pString--;// перемещаем указатель на следующую позицию
		}while(dwNum);
	}

return (dwRet);
}




#endif // !defined(AFX_NUMTOSTR__H__INCLUDED)