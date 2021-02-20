/*
 * Copyright (c) 2016 Rozhuk Ivan <rozhuk.im@gmail.com>
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

 
// see
// http://specremont.su/pdf/gost_34_11_2012.pdf
// RFC 6986 - GOST R 34.11-2012: Hash Function
// RFC 2104 - HMAC
// TODO: SSE https://github.com/sjinks/php-stribog/blob/master/gost3411-2012-sse41.c



#ifndef __GOST3411_2012_H__INCLUDED__
#define __GOST3411_2012_H__INCLUDED__

#ifndef _WINDOWS
#	include <sys/param.h>
#	ifdef __linux__ /* Linux specific code. */
#		define _GNU_SOURCE /* See feature_test_macros(7) */
#		define __USE_GNU 1
#		include <endian.h>
#	else
#		include <sys/endian.h>
#	endif /* Linux specific code. */
#	include <sys/types.h>
#	include <string.h> /* bcopy, bzero, memcpy, memmove, memset, strerror... */
#	include <inttypes.h>
	static void *(*volatile gost3411_2012_memset_volatile)(void *, int, size_t) = memset;
#	define gost3411_2012_bzero(__mem, __size)	gost3411_2012_memset_volatile((__mem), 0x00, (__size))
#	define gost3411_2012_print(__fmt, args...)	fprintf(stdout, (__fmt), ##args)
#else
#	define uint8_t		unsigned char
#	define uint32_t		DWORD
#	define uint64_t		DWORDLONG
#	define size_t		SIZE_T
#	define gost3411_2012_bzero(__mem, __size)	SecureZeroMemory((__mem), (__size))
#	define gost3411_2012_print(__fmt, args...)
#endif

#if defined(_MSC_VER) || defined(__INTEL_COMPILER)
#	define GOST3411_2012_ALIGN(__n) __declspec(align(__n)) /* DECLSPEC_ALIGN() */
#else /* GCC/clang */
#	define GOST3411_2012_ALIGN(__n) __attribute__ ((aligned(__n)))
#endif

#if defined(_WINDOWS) && defined(UNICODE)
#	define gost3411_2012_hmac_get_digest_str gost3411_2012_hmac_get_digest_strW
#	define gost3411_2012_get_digest_str	gost3411_2012_get_digest_strW
#	define gost3411_2012_cvt_str		gost3411_2012_cvt_strW
#else
#	define gost3411_2012_hmac_get_digest_str gost3411_2012_hmac_get_digest_strA
#	define gost3411_2012_get_digest_str	gost3411_2012_get_digest_strA
#	define gost3411_2012_cvt_str		gost3411_2012_cvt_strA
#endif


/* Tunables. */
/* Define to use cmall tables but do more calculations. */
//#define GOST3411_2012_USE_SMALL_TABLES 1


/* HASH constants. */
#define GOST3411_2012_256_HASH_SIZE	32
#define GOST3411_2012_512_HASH_SIZE	64
#define GOST3411_2012_HASH_MAX_SIZE	GOST3411_2012_512_HASH_SIZE
#define GOST3411_2012_HASH_MAX_64CNT	(GOST3411_2012_HASH_MAX_SIZE / sizeof(uint64_t)) /* 8 */

#define GOST3411_2012_256_HASH_STR_SIZE	(GOST3411_2012_256_HASH_SIZE * 2)
#define GOST3411_2012_512_HASH_STR_SIZE	(GOST3411_2012_512_HASH_SIZE * 2)
#define GOST3411_2012_HASH_STR_MAX_SIZE	GOST3411_2012_512_HASH_STR_SIZE

#define GOST3411_2012_MSG_BLK_SIZE	64
#define GOST3411_2012_MSG_BLK_SIZE_MASK	(GOST3411_2012_MSG_BLK_SIZE - 1) /* 63 */
#define GOST3411_2012_MSG_BLK_BITS	(GOST3411_2012_MSG_BLK_SIZE * 8) /* 512 */
#define GOST3411_2012_MSG_BLK_64CNT	(GOST3411_2012_MSG_BLK_SIZE / sizeof(uint64_t)) /* 8 */
#define GOST3411_2012_ROUNDS_COUNT	12


/* Constants and tables. */
#ifndef GOST3411_2012_USE_SMALL_TABLES
static const GOST3411_2012_ALIGN(32) uint64_t gost3411_2012_Ax[GOST3411_2012_MSG_BLK_64CNT][256] = {
	{
		0xd01f715b5c7ef8e6ull, 0x16fa240980778325ull, 0xa8a42e857ee049c8ull,
		0x6ac1068fa186465bull, 0x6e417bd7a2e9320bull, 0x665c8167a437daabull,
		0x7666681aa89617f6ull, 0x4b959163700bdcf5ull, 0xf14be6b78df36248ull,
		0xc585bd689a625cffull, 0x9557d7fca67d82cbull, 0x89f0b969af6dd366ull,
		0xb0833d48749f6c35ull, 0xa1998c23b1ecbc7cull, 0x8d70c431ac02a736ull,
		0xd6dfbc2fd0a8b69eull, 0x37aeb3e551fa198bull, 0x0b7d128a40b5cf9cull,
		0x5a8f2008b5780cbcull, 0xedec882284e333e5ull, 0xd25fc177d3c7c2ceull,
		0x5e0f5d50b61778ecull, 0x1d873683c0c24cb9ull, 0xad040bcbb45d208cull,
		0x2f89a0285b853c76ull, 0x5732fff6791b8d58ull, 0x3e9311439ef6ec3full,
		0xc9183a809fd3c00full, 0x83adf3f5260a01eeull, 0xa6791941f4e8ef10ull,
		0x103ae97d0ca1cd5dull, 0x2ce948121dee1b4aull, 0x39738421dbf2bf53ull,
		0x093da2a6cf0cf5b4ull, 0xcd9847d89cbcb45full, 0xf9561c078b2d8ae8ull,
		0x9c6a755a6971777full, 0xbc1ebaa0712ef0c5ull, 0x72e61542abf963a6ull,
		0x78bb5fde229eb12eull, 0x14ba94250fceb90dull, 0x844d6697630e5282ull,
		0x98ea08026a1e032full, 0xf06bbea144217f5cull, 0xdb6263d11ccb377aull,
		0x641c314b2b8ee083ull, 0x320e96ab9b4770cfull, 0x1ee7deb986a96b85ull,
		0xe96cf57a878c47b5ull, 0xfdd6615f8842feb8ull, 0xc83862965601dd1bull,
		0x2ea9f83e92572162ull, 0xf876441142ff97fcull, 0xeb2c455608357d9dull,
		0x5612a7e0b0c9904cull, 0x6c01cbfb2d500823ull, 0x4548a6a7fa037a2dull,
		0xabc4c6bf388b6ef4ull, 0xbade77d4fdf8bebdull, 0x799b07c8eb4cac3aull,
		0x0c9d87e805b19cf0ull, 0xcb588aac106afa27ull, 0xea0c1d40c1e76089ull,
		0x2869354a1e816f1aull, 0xff96d17307fbc490ull, 0x9f0a9d602f1a5043ull,
		0x96373fc6e016a5f7ull, 0x5292dab8b3a6e41cull, 0x9b8ae0382c752413ull,
		0x4f15ec3b7364a8a5ull, 0x3fb349555724f12bull, 0xc7c50d4415db66d7ull,
		0x92b7429ee379d1a7ull, 0xd37f99611a15dfdaull, 0x231427c05e34a086ull,
		0xa439a96d7b51d538ull, 0xb403401077f01865ull, 0xdda2aea5901d7902ull,
		0x0a5d4a9c8967d288ull, 0xc265280adf660f93ull, 0x8bb0094520d4e94eull,
		0x2a29856691385532ull, 0x42a833c5bf072941ull, 0x73c64d54622b7eb2ull,
		0x07e095624504536cull, 0x8a905153e906f45aull, 0x6f6123c16b3b2f1full,
		0xc6e55552dc097bc3ull, 0x4468feb133d16739ull, 0xe211e7f0c7398829ull,
		0xa2f96419f7879b40ull, 0x19074bdbc3ad38e9ull, 0xf4ebc3f9474e0b0cull,
		0x43886bd376d53455ull, 0xd8028beb5aa01046ull, 0x51f23282f5cdc320ull,
		0xe7b1c2be0d84e16dull, 0x081dfab006dee8a0ull, 0x3b33340d544b857bull,
		0x7f5bcabc679ae242ull, 0x0edd37c48a08a6d8ull, 0x81ed43d9a9b33bc6ull,
		0xb1a3655ebd4d7121ull, 0x69a1eeb5e7ed6167ull, 0xf6ab73d5c8f73124ull,
		0x1a67a3e185c61fd5ull, 0x2dc91004d43c065eull, 0x0240b02c8fb93a28ull,
		0x90f7f2b26cc0eb8full, 0x3cd3a16f114fd617ull, 0xaae49ea9f15973e0ull,
		0x06c0cd748cd64e78ull, 0xda423bc7d5192a6eull, 0xc345701c16b41287ull,
		0x6d2193ede4821537ull, 0xfcf639494190e3acull, 0x7c3b228621f1c57eull,
		0xfb16ac2b0494b0c0ull, 0xbf7e529a3745d7f9ull, 0x6881b6a32e3f7c73ull,
		0xca78d2bad9b8e733ull, 0xbbfe2fc2342aa3a9ull, 0x0dbddffecc6381e4ull,
		0x70a6a56e2440598eull, 0xe4d12a844befc651ull, 0x8c509c2765d0ba22ull,
		0xee8c6018c28814d9ull, 0x17da7c1f49a59e31ull, 0x609c4c1328e194d3ull,
		0xb3e3d57232f44b09ull, 0x91d7aaa4a512f69bull, 0x0ffd6fd243dabbccull,
		0x50d26a943c1fde34ull, 0x6be15e9968545b4full, 0x94778fea6faf9fdfull,
		0x2b09dd7058ea4826ull, 0x677cd9716de5c7bfull, 0x49d5214fffb2e6ddull,
		0x0360e83a466b273cull, 0x1fc786af4f7b7691ull, 0xa0b9d435783ea168ull,
		0xd49f0c035f118cb6ull, 0x01205816c9d21d14ull, 0xac2453dd7d8f3d98ull,
		0x545217cc3f70aa64ull, 0x26b4028e9489c9c2ull, 0xdec2469fd6765e3eull,
		0x04807d58036f7450ull, 0xe5f17292823ddb45ull, 0xf30b569b024a5860ull,
		0x62dcfc3fa758aefbull, 0xe84cad6c4e5e5aa1ull, 0xccb81fce556ea94bull,
		0x53b282ae7a74f908ull, 0x1b47fbf74c1402c1ull, 0x368eebf39828049full,
		0x7afbeff2ad278b06ull, 0xbe5e0a8cfe97caedull, 0xcfd8f7f413058e77ull,
		0xf78b2bc301252c30ull, 0x4d555c17fcdd928dull, 0x5f2f05467fc565f8ull,
		0x24f4b2a21b30f3eaull, 0x860dd6bbecb768aaull, 0x4c750401350f8f99ull,
		0x0000000000000000ull, 0xecccd0344d312ef1ull, 0xb5231806be220571ull,
		0xc105c030990d28afull, 0x653c695de25cfd97ull, 0x159acc33c61ca419ull,
		0xb89ec7f872418495ull, 0xa9847693b73254dcull, 0x58cf90243ac13694ull,
		0x59efc832f3132b80ull, 0x5c4fed7c39ae42c4ull, 0x828dabe3efd81cfaull,
		0xd13f294d95ace5f2ull, 0x7d1b7a90e823d86aull, 0xb643f03cf849224dull,
		0x3df3f979d89dcb03ull, 0x7426d836272f2ddeull, 0xdfe21e891fa4432aull,
		0x3a136c1b9d99986full, 0xfa36f43dcd46add4ull, 0xc025982650df35bbull,
		0x856d3e81aadc4f96ull, 0xc4a5e57e53b041ebull, 0x4708168b75ba4005ull,
		0xaf44bbe73be41aa4ull, 0x971767d029c4b8e3ull, 0xb9be9feebb939981ull,
		0x215497ecd18d9aaeull, 0x316e7e91dd2c57f3ull, 0xcef8afe2dad79363ull,
		0x3853dc371220a247ull, 0x35ee03c9de4323a3ull, 0xe6919aa8c456fc79ull,
		0xe05157dc4880b201ull, 0x7bdbb7e464f59612ull, 0x127a59518318f775ull,
		0x332ecebd52956ddbull, 0x8f30741d23bb9d1eull, 0xd922d3fd93720d52ull,
		0x7746300c61440ae2ull, 0x25d4eab4d2e2eefeull, 0x75068020eefd30caull,
		0x135a01474acaea61ull, 0x304e268714fe4ae7ull, 0xa519f17bb283c82cull,
		0xdc82f6b359cf6416ull, 0x5baf781e7caa11a8ull, 0xb2c38d64fb26561dull,
		0x34ce5bdf17913eb7ull, 0x5d6fb56af07c5fd0ull, 0x182713cd0a7f25fdull,
		0x9e2ac576e6c84d57ull, 0x9aaab82ee5a73907ull, 0xa3d93c0f3e558654ull,
		0x7e7b92aaae48ff56ull, 0x872d8ead256575beull, 0x41c8dbfff96c0e7dull,
		0x99ca5014a3cc1e3bull, 0x40e883e930be1369ull, 0x1ca76e95091051adull,
		0x4e35b42dbab6b5b1ull, 0x05a0254ecabd6944ull, 0xe1710fca8152af15ull,
		0xf22b0e8dcb984574ull, 0xb763a82a319b3f59ull, 0x63fca4296e8ab3efull,
		0x9d4a2d4ca0a36a6bull, 0xe331bfe60eeb953dull, 0xd5bf541596c391a2ull,
		0xf5cb9bef8e9c1618ull, 0x46284e9dbc685d11ull, 0x2074cffa185f87baull,
		0xbd3ee2b6b8fcedd1ull, 0xae64e3f1f23607b0ull, 0xfeb68965ce29d984ull,
		0x55724fdaf6a2b770ull, 0x29496d5cd753720eull, 0xa75941573d3af204ull,
		0x8e102c0bea69800aull, 0x111ab16bc573d049ull, 0xd7ffe439197aab8aull,
		0xefac380e0b5a09cdull, 0x48f579593660fbc9ull, 0x22347fd697e6bd92ull,
		0x61bc1405e13389c7ull, 0x4ab5c975b9d9c1e1ull, 0x80cd1bcf606126d2ull,
		0x7186fd78ed92449aull, 0x93971a882aabccb3ull, 0x88d0e17f66bfce72ull,
		0x27945a985d5bd4d6ull
	}, {
		0xde553f8c05a811c8ull, 0x1906b59631b4f565ull, 0x436e70d6b1964ff7ull,
		0x36d343cb8b1e9d85ull, 0x843dfacc858aab5aull, 0xfdfc95c299bfc7f9ull,
		0x0f634bdea1d51fa2ull, 0x6d458b3b76efb3cdull, 0x85c3f77cf8593f80ull,
		0x3c91315fbe737cb2ull, 0x2148b03366ace398ull, 0x18f8b8264c6761bfull,
		0xc830c1c495c9fb0full, 0x981a76102086a0aaull, 0xaa16012142f35760ull,
		0x35cc54060c763cf6ull, 0x42907d66cc45db2dull, 0x8203d44b965af4bcull,
		0x3d6f3cefc3a0e868ull, 0xbc73ff69d292bda7ull, 0x8722ed0102e20a29ull,
		0x8f8185e8cd34deb7ull, 0x9b0561dda7ee01d9ull, 0x5335a0193227fad6ull,
		0xc9cecc74e81a6fd5ull, 0x54f5832e5c2431eaull, 0x99e47ba05d553470ull,
		0xf7bee756acd226ceull, 0x384e05a5571816fdull, 0xd1367452a47d0e6aull,
		0xf29fde1c386ad85bull, 0x320c77316275f7caull, 0xd0c879e2d9ae9ab0ull,
		0xdb7406c69110ef5dull, 0x45505e51a2461011ull, 0xfc029872e46c5323ull,
		0xfa3cb6f5f7bc0cc5ull, 0x031f17cd8768a173ull, 0xbd8df2d9af41297dull,
		0x9d3b4f5ab43e5e3full, 0x4071671b36feee84ull, 0x716207e7d3e3b83dull,
		0x48d20ff2f9283a1aull, 0x27769eb4757cbc7eull, 0x5c56ebc793f2e574ull,
		0xa48b474f9ef5dc18ull, 0x52cbada94ff46e0cull, 0x60c7da982d8199c6ull,
		0x0e9d466edc068b78ull, 0x4eec2175eaf865fcull, 0x550b8e9e21f7a530ull,
		0x6b7ba5bc653fec2bull, 0x5eb7f1ba6949d0ddull, 0x57ea94e3db4c9099ull,
		0xf640eae6d101b214ull, 0xdd4a284182c0b0bbull, 0xff1d8fbf6304f250ull,
		0xb8accb933bf9d7e8ull, 0xe8867c478eb68c4dull, 0x3f8e2692391bddc1ull,
		0xcb2fd60912a15a7cull, 0xaec935dbab983d2full, 0xf55ffd2b56691367ull,
		0x80e2ce366ce1c115ull, 0x179bf3f8edb27e1dull, 0x01fe0db07dd394daull,
		0xda8a0b76ecc37b87ull, 0x44ae53e1df9584cbull, 0xb310b4b77347a205ull,
		0xdfab323c787b8512ull, 0x3b511268d070b78eull, 0x65e6e3d2b9396753ull,
		0x6864b271e2574d58ull, 0x259784c98fc789d7ull, 0x02e11a7dfabb35a9ull,
		0x8841a6dfa337158bull, 0x7ade78c39b5dcdd0ull, 0xb7cf804d9a2cc84aull,
		0x20b6bd831b7f7742ull, 0x75bd331d3a88d272ull, 0x418f6aab4b2d7a5eull,
		0xd9951cbb6babdaf4ull, 0xb6318dfde7ff5c90ull, 0x1f389b112264aa83ull,
		0x492c024284fbaec0ull, 0xe33a0363c608f9a0ull, 0x2688930408af28a4ull,
		0xc7538a1a341ce4adull, 0x5da8e677ee2171aeull, 0x8c9e92254a5c7fc4ull,
		0x63d8cd55aae938b5ull, 0x29ebd8daa97a3706ull, 0x959827b37be88aa1ull,
		0x1484e4356adadf6eull, 0xa7945082199d7d6bull, 0xbf6ce8a455fa1cd4ull,
		0x9cc542eac9edcae5ull, 0x79c16f0e1c356ca3ull, 0x89bfab6fdee48151ull,
		0xd4174d1830c5f0ffull, 0x9258048415eb419dull, 0x6139d72850520d1cull,
		0x6a85a80c18ec78f1ull, 0xcd11f88e0171059aull, 0xcceff53e7ca29140ull,
		0xd229639f2315af19ull, 0x90b91ef9ef507434ull, 0x5977d28d074a1be1ull,
		0x311360fce51d56b9ull, 0xc093a92d5a1f2f91ull, 0x1a19a25bb6dc5416ull,
		0xeb996b8a09de2d3eull, 0xfee3820f1ed7668aull, 0xd7085ad5b7ad518cull,
		0x7fff41890fe53345ull, 0xec5948bd67dde602ull, 0x2fd5f65dbaaa68e0ull,
		0xa5754affe32648c2ull, 0xf8ddac880d07396cull, 0x6fa491468c548664ull,
		0x0c7c5c1326bdbed1ull, 0x4a33158f03930fb3ull, 0x699abfc19f84d982ull,
		0xe4fa2054a80b329cull, 0x6707f9af438252faull, 0x08a368e9cfd6d49eull,
		0x47b1442c58fd25b8ull, 0xbbb3dc5ebc91769bull, 0x1665fe489061eac7ull,
		0x33f27a811fa66310ull, 0x93a609346838d547ull, 0x30ed6d4c98cec263ull,
		0x1dd9816cd8df9f2aull, 0x94662a03063b1e7bull, 0x83fdd9fbeb896066ull,
		0x7b207573e68e590aull, 0x5f49fc0a149a4407ull, 0x343259b671a5a82cull,
		0xfbc2bb458a6f981full, 0xc272b350a0a41a38ull, 0x3aaf1fd8ada32354ull,
		0x6cbb868b0b3c2717ull, 0xa2b569c88d2583feull, 0xf180c9d1bf027928ull,
		0xaf37386bd64ba9f5ull, 0x12bacab2790a8088ull, 0x4c0d3b0810435055ull,
		0xb2eeb9070e9436dfull, 0xc5b29067cea7d104ull, 0xdcb425f1ff132461ull,
		0x4f122cc5972bf126ull, 0xac282fa651230886ull, 0xe7e537992f6393efull,
		0xe61b3a2952b00735ull, 0x709c0a57ae302ce7ull, 0xe02514ae416058d3ull,
		0xc44c9dd7b37445deull, 0x5a68c5408022ba92ull, 0x1c278cdca50c0bf0ull,
		0x6e5a9cf6f18712beull, 0x86dce0b17f319ef3ull, 0x2d34ec2040115d49ull,
		0x4bcd183f7e409b69ull, 0x2815d56ad4a9a3dcull, 0x24698979f2141d0dull,
		0x0000000000000000ull, 0x1ec696a15fb73e59ull, 0xd86b110b16784e2eull,
		0x8e7f8858b0e74a6dull, 0x063e2e8713d05fe6ull, 0xe2c40ed3bbdb6d7aull,
		0xb1f1aeca89fc97acull, 0xe1db191e3cb3cc09ull, 0x6418ee62c4eaf389ull,
		0xc6ad87aa49cf7077ull, 0xd6f65765ca7ec556ull, 0x9afb6c6dda3d9503ull,
		0x7ce05644888d9236ull, 0x8d609f95378feb1eull, 0x23a9aa4e9c17d631ull,
		0x6226c0e5d73aac6full, 0x56149953a69f0443ull, 0xeeb852c09d66d3abull,
		0x2b0ac2a753c102afull, 0x07c023376e03cb3cull, 0x2ccae1903dc2c993ull,
		0xd3d76e2f5ec63bc3ull, 0x9e2458973356ff4cull, 0xa66a5d32644ee9b1ull,
		0x0a427294356de137ull, 0x783f62be61e6f879ull, 0x1344c70204d91452ull,
		0x5b96c8f0fdf12e48ull, 0xa90916ecc59bf613ull, 0xbe92e5142829880eull,
		0x727d102a548b194eull, 0x1be7afebcb0fc0ccull, 0x3e702b2244c8491bull,
		0xd5e940a84d166425ull, 0x66f9f41f3e51c620ull, 0xabe80c913f20c3baull,
		0xf07ec461c2d1edf2ull, 0xf361d3ac45b94c81ull, 0x0521394a94b8fe95ull,
		0xadd622162cf09c5cull, 0xe97871f7f3651897ull, 0xf4a1f09b2bba87bdull,
		0x095d6559b2054044ull, 0x0bbc7f2448be75edull, 0x2af4cf172e129675ull,
		0x157ae98517094bb4ull, 0x9fda55274e856b96ull, 0x914713499283e0eeull,
		0xb952c623462a4332ull, 0x74433ead475b46a8ull, 0x8b5eb112245fb4f8ull,
		0xa34b6478f0f61724ull, 0x11a5dd7ffe6221fbull, 0xc16da49d27ccbb4bull,
		0x76a224d0bde07301ull, 0x8aa0bca2598c2022ull, 0x4df336b86d90c48full,
		0xea67663a740db9e4ull, 0xef465f70e0b54771ull, 0x39b008152acb8227ull,
		0x7d1e5bf4f55e06ecull, 0x105bd0cf83b1b521ull, 0x775c2960c033e7dbull,
		0x7e014c397236a79full, 0x811cc386113255cfull, 0xeda7450d1a0e72d8ull,
		0x5889df3d7a998f3bull, 0x2e2bfbedc779fc3aull, 0xce0eef438619a4e9ull,
		0x372d4e7bf6cd095full, 0x04df34fae96b6a4full, 0xf923a13870d4adb6ull,
		0xa1aa7e050a4d228dull, 0xa8f71b5cb84862c9ull, 0xb52e9a306097fde3ull,
		0x0d8251a35b6e2a0bull, 0x2257a7fee1c442ebull, 0x73831d9a29588d94ull,
		0x51d4ba64c89ccf7full, 0x502ab7d4b54f5ba5ull, 0x97793dce8153bf08ull,
		0xe5042de4d5d8a646ull, 0x9687307efc802bd2ull, 0xa05473b5779eb657ull,
		0xb4d097801d446939ull, 0xcff0e2f3fbca3033ull, 0xc38cbee0dd778ee2ull,
		0x464f499c252eb162ull, 0xcad1dbb96f72cea6ull, 0xba4dd1eec142e241ull,
		0xb00fa37af42f0376ull
	}, {
		0xcce4cd3aa968b245ull, 0x089d5484e80b7fafull, 0x638246c1b3548304ull,
		0xd2fe0ec8c2355492ull, 0xa7fbdf7ff2374eeeull, 0x4df1600c92337a16ull,
		0x84e503ea523b12fbull, 0x0790bbfd53ab0c4aull, 0x198a780f38f6ea9dull,
		0x2ab30c8f55ec48cbull, 0xe0f7fed6b2c49db5ull, 0xb6ecf3f422cadbdcull,
		0x409c9a541358df11ull, 0xd3ce8a56dfde3fe3ull, 0xc3e9224312c8c1a0ull,
		0x0d6dfa58816ba507ull, 0xddf3e1b179952777ull, 0x04c02a42748bb1d9ull,
		0x94c2abff9f2decb8ull, 0x4f91752da8f8acf4ull, 0x78682befb169bf7bull,
		0xe1c77a48af2ff6c4ull, 0x0c5d7ec69c80ce76ull, 0x4cc1e4928fd81167ull,
		0xfeed3d24d9997b62ull, 0x518bb6dfc3a54a23ull, 0x6dbf2d26151f9b90ull,
		0xb5bc624b05ea664full, 0xe86aaa525acfe21aull, 0x4801ced0fb53a0beull,
		0xc91463e6c00868edull, 0x1027a815cd16fe43ull, 0xf67069a0319204cdull,
		0xb04ccc976c8abce7ull, 0xc0b9b3fc35e87c33ull, 0xf380c77c58f2de65ull,
		0x50bb3241de4e2152ull, 0xdf93f490435ef195ull, 0xf1e0d25d62390887ull,
		0xaf668bfb1a3c3141ull, 0xbc11b251f00a7291ull, 0x73a5eed47e427d47ull,
		0x25bee3f6ee4c3b2eull, 0x43cc0beb34786282ull, 0xc824e778dde3039cull,
		0xf97d86d98a327728ull, 0xf2b043e24519b514ull, 0xe297ebf7880f4b57ull,
		0x3a94a49a98fab688ull, 0x868516cb68f0c419ull, 0xeffa11af0964ee50ull,
		0xa4ab4ec0d517f37dull, 0xa9c6b498547c567aull, 0x8e18424f80fbbbb6ull,
		0x0bcdc53bcf2bc23cull, 0x137739aaea3643d0ull, 0x2c1333ec1bac2ff0ull,
		0x8d48d3f0a7db0625ull, 0x1e1ac3f26b5de6d7ull, 0xf520f81f16b2b95eull,
		0x9f0f6ec450062e84ull, 0x0130849e1deb6b71ull, 0xd45e31ab8c7533a9ull,
		0x652279a2fd14e43full, 0x3209f01e70f1c927ull, 0xbe71a770cac1a473ull,
		0x0e3d6be7a64b1894ull, 0x7ec8148cff29d840ull, 0xcb7476c7fac3be0full,
		0x72956a4a63a91636ull, 0x37f95ec21991138full, 0x9e3fea5a4ded45f5ull,
		0x7b38ba50964902e8ull, 0x222e580bbde73764ull, 0x61e253e0899f55e6ull,
		0xfc8d2805e352ad80ull, 0x35994be3235ac56dull, 0x09add01af5e014deull,
		0x5e8659a6780539c6ull, 0xb17c48097161d796ull, 0x026015213acbd6e2ull,
		0xd1ae9f77e515e901ull, 0xb7dc776a3f21b0adull, 0xaba6a1b96eb78098ull,
		0x9bcf4486248d9f5dull, 0x582666c536455efdull, 0xfdbdac9bfeb9c6f1ull,
		0xc47999be4163cdeaull, 0x765540081722a7efull, 0x3e548ed8ec710751ull,
		0x3d041f67cb51bac2ull, 0x7958af71ac82d40aull, 0x36c9da5c047a78feull,
		0xed9a048e33af38b2ull, 0x26ee7249c96c86bdull, 0x900281bdeba65d61ull,
		0x11172c8bd0fd9532ull, 0xea0abf73600434f8ull, 0x42fc8f75299309f3ull,
		0x34a9cf7d3eb1ae1cull, 0x2b838811480723baull, 0x5ce64c8742ceef24ull,
		0x1adae9b01fd6570eull, 0x3c349bf9d6bad1b3ull, 0x82453c891c7b75c0ull,
		0x97923a40b80d512bull, 0x4a61dbf1c198765cull, 0xb48ce6d518010d3eull,
		0xcfb45c858e480fd6ull, 0xd933cbf30d1e96aeull, 0xd70ea014ab558e3aull,
		0xc189376228031742ull, 0x9262949cd16d8b83ull, 0xeb3a3bed7def5f89ull,
		0x49314a4ee6b8cbcfull, 0xdcc3652f647e4c06ull, 0xda635a4c2a3e2b3dull,
		0x470c21a940f3d35bull, 0x315961a157d174b4ull, 0x6672e81dda3459acull,
		0x5b76f77a1165e36eull, 0x445cb01667d36ec8ull, 0xc5491d205c88a69bull,
		0x456c34887a3805b9ull, 0xffddb9bac4721013ull, 0x99af51a71e4649bfull,
		0xa15be01cbc7729d5ull, 0x52db2760e485f7b0ull, 0x8c78576eba306d54ull,
		0xae560f6507d75a30ull, 0x95f22f6182c687c9ull, 0x71c5fbf54489aba5ull,
		0xca44f259e728d57eull, 0x88b87d2ccebbdc8dull, 0xbab18d32be4a15aaull,
		0x8be8ec93e99b611eull, 0x17b713e89ebdf209ull, 0xb31c5d284baa0174ull,
		0xeeca9531148f8521ull, 0xb8d198138481c348ull, 0x8988f9b2d350b7fcull,
		0xb9e11c8d996aa839ull, 0x5a4673e40c8e881full, 0x1687977683569978ull,
		0xbf4123eed72acf02ull, 0x4ea1f1b3b513c785ull, 0xe767452be16f91ffull,
		0x7505d1b730021a7cull, 0xa59bca5ec8fc980cull, 0xad069eda20f7e7a3ull,
		0x38f4b1bba231606aull, 0x60d2d77e94743e97ull, 0x9affc0183966f42cull,
		0x248e6768f3a7505full, 0xcdd449a4b483d934ull, 0x87b59255751baf68ull,
		0x1bea6d2e023d3c7full, 0x6b1f12455b5ffcabull, 0x743555292de9710dull,
		0xd8034f6d10f5fddfull, 0xc6198c9f7ba81b08ull, 0xbb8109aca3a17edbull,
		0xfa2d1766ad12cabbull, 0xc729080166437079ull, 0x9c5fff7b77269317ull,
		0x0000000000000000ull, 0x15d706c9a47624ebull, 0x6fdf38072fd44d72ull,
		0x5fb6dd3865ee52b7ull, 0xa33bf53d86bcff37ull, 0xe657c1b5fc84fa8eull,
		0xaa962527735cebe9ull, 0x39c43525bfda0b1bull, 0x204e4d2a872ce186ull,
		0x7a083ece8ba26999ull, 0x554b9c9db72efbfaull, 0xb22cd9b656416a05ull,
		0x96a2bedea5e63a5aull, 0x802529a826b0a322ull, 0x8115ad363b5bc853ull,
		0x8375b81701901eb1ull, 0x3069e53f4a3a1fc5ull, 0xbd2136cfede119e0ull,
		0x18bafc91251d81ecull, 0x1d4a524d4c7d5b44ull, 0x05f0aedc6960daa8ull,
		0x29e39d3072ccf558ull, 0x70f57f6b5962c0d4ull, 0x989fd53903ad22ceull,
		0xf84d024797d91c59ull, 0x547b1803aac5908bull, 0xf0d056c37fd263f6ull,
		0xd56eb535919e58d8ull, 0x1c7ad6d351963035ull, 0x2e7326cd2167f912ull,
		0xac361a443d1c8cd2ull, 0x697f076461942a49ull, 0x4b515f6fdc731d2dull,
		0x8ad8680df4700a6full, 0x41ac1eca0eb3b460ull, 0x7d988533d80965d3ull,
		0xa8f6300649973d0bull, 0x7765c4960ac9cc9eull, 0x7ca801adc5e20ea2ull,
		0xdea3700e5eb59ae4ull, 0xa06b6482a19c42a4ull, 0x6a2f96db46b497daull,
		0x27def6d7d487edccull, 0x463ca5375d18b82aull, 0xa6cb5be1efdc259full,
		0x53eba3fef96e9cc1ull, 0xce84d81b93a364a7ull, 0xf4107c810b59d22full,
		0x333974806d1aa256ull, 0x0f0def79bba073e5ull, 0x231edc95a00c5c15ull,
		0xe437d494c64f2c6cull, 0x91320523f64d3610ull, 0x67426c83c7df32ddull,
		0x6eefbc99323f2603ull, 0x9d6f7be56acdf866ull, 0x5916e25b2bae358cull,
		0x7ff89012e2c2b331ull, 0x035091bf2720bd93ull, 0x561b0d22900e4669ull,
		0x28d319ae6f279e29ull, 0x2f43a2533c8c9263ull, 0xd09e1be9f8fe8270ull,
		0xf740ed3e2c796fbcull, 0xdb53ded237d5404cull, 0x62b2c25faebfe875ull,
		0x0afd41a5d2c0a94dull, 0x6412fd3ce0ff8f4eull, 0xe3a76f6995e42026ull,
		0x6c8fa9b808f4f0e1ull, 0xc2d9a6dd0f23aad1ull, 0x8f28c6d19d10d0c7ull,
		0x85d587744fd0798aull, 0xa20b71a39b579446ull, 0x684f83fa7c7f4138ull,
		0xe507500adba4471dull, 0x3f640a46f19a6c20ull, 0x1247bd34f7dd28a1ull,
		0x2d23b77206474481ull, 0x93521002cc86e0f2ull, 0x572b89bc8de52d18ull,
		0xfb1d93f8b0f9a1caull, 0xe95a2ecc4724896bull, 0x3ba420048511ddf9ull,
		0xd63e248ab6bee54bull, 0x5dd6c8195f258455ull, 0x06a03f634e40673bull,
		0x1f2a476c76b68da6ull, 0x217ec9b49ac78af7ull, 0xecaa80102e4453c3ull,
		0x14e78257b99d4f9aull
	}, {
		0x20329b2cc87bba05ull, 0x4f5eb6f86546a531ull, 0xd4f44775f751b6b1ull,
		0x8266a47b850dfa8bull, 0xbb986aa15a6ca985ull, 0xc979eb08f9ae0f99ull,
		0x2da6f447a2375ea1ull, 0x1e74275dcd7d8576ull, 0xbc20180a800bc5f8ull,
		0xb4a2f701b2dc65beull, 0xe726946f981b6d66ull, 0x48e6c453bf21c94cull,
		0x42cad9930f0a4195ull, 0xefa47b64aacccd20ull, 0x71180a8960409a42ull,
		0x8bb3329bf6a44e0cull, 0xd34c35de2d36daccull, 0xa92f5b7cbc23dc96ull,
		0xb31a85aa68bb09c3ull, 0x13e04836a73161d2ull, 0xb24dfc4129c51d02ull,
		0x8ae44b70b7da5acdull, 0xe671ed84d96579a7ull, 0xa4bb3417d66f3832ull,
		0x4572ab38d56d2de8ull, 0xb1b47761ea47215cull, 0xe81c09cf70aba15dull,
		0xffbdb872ce7f90acull, 0xa8782297fd5dc857ull, 0x0d946f6b6a4ce4a4ull,
		0xe4df1f4f5b995138ull, 0x9ebc71edca8c5762ull, 0x0a2c1dc0b02b88d9ull,
		0x3b503c115d9d7b91ull, 0xc64376a8111ec3a2ull, 0xcec199a323c963e4ull,
		0xdc76a87ec58616f7ull, 0x09d596e073a9b487ull, 0x14583a9d7d560dafull,
		0xf4c6dc593f2a0cb4ull, 0xdd21d19584f80236ull, 0x4a4836983ddde1d3ull,
		0xe58866a41ae745f9ull, 0xf591a5b27e541875ull, 0x891dc05074586693ull,
		0x5b068c651810a89eull, 0xa30346bc0c08544full, 0x3dbf3751c684032dull,
		0x2a1e86ec785032dcull, 0xf73f5779fca830eaull, 0xb60c05ca30204d21ull,
		0x0cc316802b32f065ull, 0x8770241bdd96be69ull, 0xb861e18199ee95dbull,
		0xf805cad91418fcd1ull, 0x29e70dccbbd20e82ull, 0xc7140f435060d763ull,
		0x0f3a9da0e8b0cc3bull, 0xa2543f574d76408eull, 0xbd7761e1c175d139ull,
		0x4b1f4f737ca3f512ull, 0x6dc2df1f2fc137abull, 0xf1d05c3967b14856ull,
		0xa742bf3715ed046cull, 0x654030141d1697edull, 0x07b872abda676c7dull,
		0x3ce84eba87fa17ecull, 0xc1fb0403cb79afdfull, 0x3e46bc7105063f73ull,
		0x278ae987121cd678ull, 0xa1adb4778ef47cd0ull, 0x26dd906c5362c2b9ull,
		0x05168060589b44e2ull, 0xfbfc41f9d79ac08full, 0x0e6de44ba9ced8faull,
		0x9feb08068bf243a3ull, 0x7b341749d06b129bull, 0x229c69e74a87929aull,
		0xe09ee6c4427c011bull, 0x5692e30e725c4c3aull, 0xda99a33e5e9f6e4bull,
		0x353dd85af453a36bull, 0x25241b4c90e0fee7ull, 0x5de987258309d022ull,
		0xe230140fc0802984ull, 0x93281e86a0c0b3c6ull, 0xf229d719a4337408ull,
		0x6f6c2dd4ad3d1f34ull, 0x8ea5b2fbae3f0aeeull, 0x8331dd90c473ee4aull,
		0x346aa1b1b52db7aaull, 0xdf8f235e06042aa9ull, 0xcc6f6b68a1354b7bull,
		0x6c95a6f46ebf236aull, 0x52d31a856bb91c19ull, 0x1a35ded6d498d555ull,
		0xf37eaef2e54d60c9ull, 0x72e181a9a3c2a61cull, 0x98537aad51952fdeull,
		0x16f6c856ffaa2530ull, 0xd960281e9d1d5215ull, 0x3a0745fa1ce36f50ull,
		0x0b7b642bf1559c18ull, 0x59a87eae9aec8001ull, 0x5e100c05408bec7cull,
		0x0441f98b19e55023ull, 0xd70dcc5534d38aefull, 0x927f676de1bea707ull,
		0x9769e70db925e3e5ull, 0x7a636ea29115065aull, 0x468b201816ef11b6ull,
		0xab81a9b73edff409ull, 0xc0ac7de88a07bb1eull, 0x1f235eb68c0391b7ull,
		0x6056b074458dd30full, 0xbe8eeac102f7ed67ull, 0xcd381283e04b5fbaull,
		0x5cbefecec277c4e3ull, 0xd21b4c356c48ce0dull, 0x1019c31664b35d8cull,
		0x247362a7d19eea26ull, 0xebe582efb3299d03ull, 0x02aef2cb82fc289full,
		0x86275df09ce8aaa8ull, 0x28b07427faac1a43ull, 0x38a9b7319e1f47cfull,
		0xc82e92e3b8d01b58ull, 0x06ef0b409b1978bcull, 0x62f842bfc771fb90ull,
		0x9904034610eb3b1full, 0xded85ab5477a3e68ull, 0x90d195a663428f98ull,
		0x5384636e2ac708d8ull, 0xcbd719c37b522706ull, 0xae9729d76644b0ebull,
		0x7c8c65e20a0c7ee6ull, 0x80c856b007f1d214ull, 0x8c0b40302cc32271ull,
		0xdbcedad51fe17a8aull, 0x740e8ae938dbdea0ull, 0xa615c6dc549310adull,
		0x19cc55f6171ae90bull, 0x49b1bdb8fe5fdd8dull, 0xed0a89af2830e5bfull,
		0x6a7aadb4f5a65bd6ull, 0x7e22972988f05679ull, 0xf952b3325566e810ull,
		0x39fecedadf61530eull, 0x6101c99f04f3c7ceull, 0x2e5f7f6761b562ffull,
		0xf08725d226cf5c97ull, 0x63af3b54860fef51ull, 0x8ff2cb10ef411e2full,
		0x884ab9bb35267252ull, 0x4df04433e7ba8daeull, 0x9afd8866d3690741ull,
		0x66b9bb34de94abb3ull, 0x9baaf18d92171380ull, 0x543c11c5f0a064a5ull,
		0x17a1b1bdbed431f1ull, 0xb5f58eeaf3a2717full, 0xc355f6c849858740ull,
		0xec5df044694ef17eull, 0xd83751f5dc6346d4ull, 0xfc4433520dfdacf2ull,
		0x0000000000000000ull, 0x5a51f58e596ebc5full, 0x3285aaf12e34cf16ull,
		0x8d5c39db6dbd36b0ull, 0x12b731dde64f7513ull, 0x94906c2d7aa7dfbbull,
		0x302b583aacc8e789ull, 0x9d45facd090e6b3cull, 0x2165e2c78905aec4ull,
		0x68d45f7f775a7349ull, 0x189b2c1d5664fdcaull, 0xe1c99f2f030215daull,
		0x6983269436246788ull, 0x8489af3b1e148237ull, 0xe94b702431d5b59cull,
		0x33d2d31a6f4adbd7ull, 0xbfd9932a4389f9a6ull, 0xb0e30e8aab39359dull,
		0xd1e2c715afcaf253ull, 0x150f43763c28196eull, 0xc4ed846393e2eb3dull,
		0x03f98b20c3823c5eull, 0xfd134ab94c83b833ull, 0x556b682eb1de7064ull,
		0x36c4537a37d19f35ull, 0x7559f30279a5ca61ull, 0x799ae58252973a04ull,
		0x9c12832648707ffdull, 0x78cd9c6913e92ec5ull, 0x1d8dac7d0effb928ull,
		0x439da0784e745554ull, 0x413352b3cc887dcbull, 0xbacf134a1b12bd44ull,
		0x114ebafd25cd494dull, 0x2f08068c20cb763eull, 0x76a07822ba27f63full,
		0xeab2fb04f25789c2ull, 0xe3676de481fe3d45ull, 0x1b62a73d95e6c194ull,
		0x641749ff5c68832cull, 0xa5ec4dfc97112cf3ull, 0xf6682e92bdd6242bull,
		0x3f11c59a44782bb2ull, 0x317c21d1edb6f348ull, 0xd65ab5be75ad9e2eull,
		0x6b2dd45fb4d84f17ull, 0xfaab381296e4d44eull, 0xd0b5befeeeb4e692ull,
		0x0882ef0b32d7a046ull, 0x512a91a5a83b2047ull, 0x963e9ee6f85bf724ull,
		0x4e09cf132438b1f0ull, 0x77f701c9fb59e2feull, 0x7ddb1c094b726a27ull,
		0x5f4775ee01f5f8bdull, 0x9186ec4d223c9b59ull, 0xfeeac1998f01846dull,
		0xac39db1ce4b89874ull, 0xb75b7c21715e59e0ull, 0xafc0503c273aa42aull,
		0x6e3b543fec430bf5ull, 0x704f7362213e8e83ull, 0x58ff0745db9294c0ull,
		0x67eec2df9feabf72ull, 0xa0facd9ccf8a6811ull, 0xb936986ad890811aull,
		0x95c715c63bd9cb7aull, 0xca8060283a2c33c7ull, 0x507de84ee9453486ull,
		0x85ded6d05f6a96f6ull, 0x1cdad5964f81ade9ull, 0xd5a33e9eb62fa270ull,
		0x40642b588df6690aull, 0x7f75eec2c98e42b8ull, 0x2cf18dace3494a60ull,
		0x23cb100c0bf9865bull, 0xeef3028febb2d9e1ull, 0x4425d2d394133929ull,
		0xaad6d05c7fa1e0c8ull, 0xad6ea2f7a5c68cb5ull, 0xc2028f2308fb9381ull,
		0x819f2f5b468fc6d5ull, 0xc5bafd88d29cfffcull, 0x47dc59f357910577ull,
		0x2b49ff07392e261dull, 0x57c59ae5332258fbull, 0x73b6f842e2bcb2ddull,
		0xcf96e04862b77725ull, 0x4ca73dd8a6c4996full, 0x015779eb417e14c1ull,
		0x37932a9176af8bf4ull
	}, {
		0x190a2c9b249df23eull, 0x2f62f8b62263e1e9ull, 0x7a7f754740993655ull,
		0x330b7ba4d5564d9full, 0x4c17a16a46672582ull, 0xb22f08eb7d05f5b8ull,
		0x535f47f40bc148ccull, 0x3aec5d27d4883037ull, 0x10ed0a1825438f96ull,
		0x516101f72c233d17ull, 0x13cc6f949fd04eaeull, 0x739853c441474bfdull,
		0x653793d90d3f5b1bull, 0x5240647b96b0fc2full, 0x0c84890ad27623e0ull,
		0xd7189b32703aaea3ull, 0x2685de3523bd9c41ull, 0x99317c5b11bffefaull,
		0x0d9baa854f079703ull, 0x70b93648fbd48ac5ull, 0xa80441fce30bc6beull,
		0x7287704bdc36ff1eull, 0xb65384ed33dc1f13ull, 0xd36417343ee34408ull,
		0x39cd38ab6e1bf10full, 0x5ab861770a1f3564ull, 0x0ebacf09f594563bull,
		0xd04572b884708530ull, 0x3cae9722bdb3af47ull, 0x4a556b6f2f5cbaf2ull,
		0xe1704f1f76c4bd74ull, 0x5ec4ed7144c6dfcfull, 0x16afc01d4c7810e6ull,
		0x283f113cd629ca7aull, 0xaf59a8761741ed2dull, 0xeed5a3991e215facull,
		0x3bf37ea849f984d4ull, 0xe413e096a56ce33cull, 0x2c439d3a98f020d1ull,
		0x637559dc6404c46bull, 0x9e6c95d1e5f5d569ull, 0x24bb9836045fe99aull,
		0x44efa466dac8ecc9ull, 0xc6eab2a5c80895d6ull, 0x803b50c035220cc4ull,
		0x0321658cba93c138ull, 0x8f9ebc465dc7ee1cull, 0xd15a5137190131d3ull,
		0x0fa5ec8668e5e2d8ull, 0x91c979578d1037b1ull, 0x0642ca05693b9f70ull,
		0xefca80168350eb4full, 0x38d21b24f36a45ecull, 0xbeab81e1af73d658ull,
		0x8cbfd9cae7542f24ull, 0xfd19cc0d81f11102ull, 0x0ac6430fbb4dbc90ull,
		0x1d76a09d6a441895ull, 0x2a01573ff1cbbfa1ull, 0xb572e161894fde2bull,
		0x8124734fa853b827ull, 0x614b1fdf43e6b1b0ull, 0x68ac395c4238cc18ull,
		0x21d837bfd7f7b7d2ull, 0x20c714304a860331ull, 0x5cfaab726324aa14ull,
		0x74c5ba4eb50d606eull, 0xf3a3030474654739ull, 0x23e671bcf015c209ull,
		0x45f087e947b9582aull, 0xd8bd77b418df4c7bull, 0xe06f6c90ebb50997ull,
		0x0bd96080263c0873ull, 0x7e03f9410e40dcfeull, 0xb8e94be4c6484928ull,
		0xfb5b0608e8ca8e72ull, 0x1a2b49179e0e3306ull, 0x4e29e76961855059ull,
		0x4f36c4e6fcf4e4baull, 0x49740ee395cf7bcaull, 0xc2963ea386d17f7dull,
		0x90d65ad810618352ull, 0x12d34c1b02a1fa4dull, 0xfa44258775bb3a91ull,
		0x18150f14b9ec46ddull, 0x1491861e6b9a653dull, 0x9a1019d7ab2c3fc2ull,
		0x3668d42d06fe13d7ull, 0xdcc1fbb25606a6d0ull, 0x969490dd795a1c22ull,
		0x3549b1a1bc6dd2efull, 0xc94f5e23a0ed770eull, 0xb9f6686b5b39fdcbull,
		0xc4d4f4a6efeae00dull, 0xe732851a1fff2204ull, 0x94aad6de5eb869f9ull,
		0x3f8ff2ae07206e7full, 0xfe38a9813b62d03aull, 0xa7a1ad7a8bee2466ull,
		0x7b6056c8dde882b6ull, 0x302a1e286fc58ca7ull, 0x8da0fa457a259bc7ull,
		0xb3302b64e074415bull, 0x5402ae7eff8b635full, 0x08f8050c9cafc94bull,
		0xae468bf98a3059ceull, 0x88c355cca98dc58full, 0xb10e6d67c7963480ull,
		0xbad70de7e1aa3cf3ull, 0xbfb4a26e320262bbull, 0xcb711820870f02d5ull,
		0xce12b7a954a75c9dull, 0x563ce87dd8691684ull, 0x9f73b65e7884618aull,
		0x2b1e74b06cba0b42ull, 0x47cec1ea605b2df1ull, 0x1c698312f735ac76ull,
		0x5fdbcefed9b76b2cull, 0x831a354c8fb1cdfcull, 0x820516c312c0791full,
		0xb74ca762aeadabf0ull, 0xfc06ef821c80a5e1ull, 0x5723cbf24518a267ull,
		0x9d4df05d5f661451ull, 0x588627742dfd40bfull, 0xda8331b73f3d39a0ull,
		0x17b0e392d109a405ull, 0xf965400bcf28fba9ull, 0x7c3dbf4229a2a925ull,
		0x023e460327e275dbull, 0x6cd0b55a0ce126b3ull, 0xe62da695828e96e7ull,
		0x42ad6e63b3f373b9ull, 0xe50cc319381d57dfull, 0xc5cbd729729b54eeull,
		0x46d1e265fd2a9912ull, 0x6428b056904eeff8ull, 0x8be23040131e04b7ull,
		0x6709d5da2add2ec0ull, 0x075de98af44a2b93ull, 0x8447dcc67bfbe66full,
		0x6616f655b7ac9a23ull, 0xd607b8bded4b1a40ull, 0x0563af89d3a85e48ull,
		0x3db1b4ad20c21ba4ull, 0x11f22997b8323b75ull, 0x292032b34b587e99ull,
		0x7f1cdace9331681dull, 0x8e819fc9c0b65affull, 0xa1e3677fe2d5bb16ull,
		0xcd33d225ee349da5ull, 0xd9a2543b85aef898ull, 0x795e10cbfa0af76dull,
		0x25a4bbb9992e5d79ull, 0x78413344677b438eull, 0xf0826688cef68601ull,
		0xd27b34bba392f0ebull, 0x551d8df162fad7bcull, 0x1e57c511d0d7d9adull,
		0xdeffbdb171e4d30bull, 0xf4feea8e802f6caaull, 0xa480c8f6317de55eull,
		0xa0fc44f07fa40ff5ull, 0x95b5f551c3c9dd1aull, 0x22f952336d6476eaull,
		0x0000000000000000ull, 0xa6be8ef5169f9085ull, 0xcc2cf1aa73452946ull,
		0x2e7ddb39bf12550aull, 0xd526dd3157d8db78ull, 0x486b2d6c08becf29ull,
		0x9b0f3a58365d8b21ull, 0xac78cdfaadd22c15ull, 0xbc95c7e28891a383ull,
		0x6a927f5f65dab9c3ull, 0xc3891d2c1ba0cb9eull, 0xeaa92f9f50f8b507ull,
		0xcf0d9426c9d6e87eull, 0xca6e3baf1a7eb636ull, 0xab25247059980786ull,
		0x69b31ad3df4978fbull, 0xe2512a93cc577c4cull, 0xff278a0ea61364d9ull,
		0x71a615c766a53e26ull, 0x89dc764334fc716cull, 0xf87a638452594f4aull,
		0xf2bc208be914f3daull, 0x8766b94ac1682757ull, 0xbbc82e687cdb8810ull,
		0x626a7a53f9757088ull, 0xa2c202f358467a2eull, 0x4d0882e5db169161ull,
		0x09e7268301de7da8ull, 0xe897699c771ac0dcull, 0xc8507dac3d9cc3edull,
		0xc0a878a0a1330aa6ull, 0x978bb352e42ba8c1ull, 0xe9884a13ea6b743full,
		0x279afdbabecc28a2ull, 0x047c8c064ed9eaabull, 0x507e2278b15289f4ull,
		0x599904fbb08cf45cull, 0xbd8ae46d15e01760ull, 0x31353da7f2b43844ull,
		0x8558ff49e68a528cull, 0x76fbfc4d92ef15b5ull, 0x3456922e211c660cull,
		0x86799ac55c1993b4ull, 0x3e90d1219a51da9cull, 0x2d5cbeb505819432ull,
		0x982e5fd48cce4a19ull, 0xdb9c1238a24c8d43ull, 0xd439febecaa96f9bull,
		0x418c0bef0960b281ull, 0x158ea591f6ebd1deull, 0x1f48e69e4da66d4eull,
		0x8afd13cf8e6fb054ull, 0xf5e1c9011d5ed849ull, 0xe34e091c5126c8afull,
		0xad67ee7530a398f6ull, 0x43b24dec2e82c75aull, 0x75da99c1287cd48dull,
		0x92e81cdb3783f689ull, 0xa3dd217cc537cecdull, 0x60543c50de970553ull,
		0x93f73f54aaf2426aull, 0xa91b62737e7a725dull, 0xf19d4507538732e2ull,
		0x77e4dfc20f9ea156ull, 0x7d229ccdb4d31dc6ull, 0x1b346a98037f87e5ull,
		0xedf4c615a4b29e94ull, 0x4093286094110662ull, 0xb0114ee85ae78063ull,
		0x6ff1d0d6b672e78bull, 0x6dcf96d591909250ull, 0xdfe09e3eec9567e8ull,
		0x3214582b4827f97cull, 0xb46dc2ee143e6ac8ull, 0xf6c0ac8da7cd1971ull,
		0xebb60c10cd8901e4ull, 0xf7df8f023abcad92ull, 0x9c52d3d2c217a0b2ull,
		0x6b8d5cd0f8ab0d20ull, 0x3777f7a29b8fa734ull, 0x011f238f9d71b4e3ull,
		0xc1b75b2f3c42be45ull, 0x5de588fdfe551ef7ull, 0x6eeef3592b035368ull,
		0xaa3a07ffc4e9b365ull, 0xecebe59a39c32a77ull, 0x5ba742f8976e8187ull,
		0x4b4a48e0b22d0e11ull, 0xddded83dcb771233ull, 0xa59feb79ac0c51bdull,
		0xc7f5912a55792135ull
	}, {
		0x6d6ae04668a9b08aull, 0x3ab3f04b0be8c743ull, 0xe51e166b54b3c908ull,
		0xbe90a9eb35c2f139ull, 0xb2c7066637f2bec1ull, 0xaa6945613392202cull,
		0x9a28c36f3b5201ebull, 0xddce5a93ab536994ull, 0x0e34133ef6382827ull,
		0x52a02ba1ec55048bull, 0xa2f88f97c4b2a177ull, 0x8640e513ca2251a5ull,
		0xcdf1d36258137622ull, 0xfe6cb708dedf8ddbull, 0x8a174a9ec8121e5dull,
		0x679896036b81560eull, 0x59ed033395795feeull, 0x1dd778ab8b74edafull,
		0xee533ef92d9f926dull, 0x2a8c79baf8a8d8f5ull, 0x6bcf398e69b119f6ull,
		0xe20491742fafdd95ull, 0x276488e0809c2aecull, 0xea955b82d88f5cceull,
		0x7102c63a99d9e0c4ull, 0xf9763017a5c39946ull, 0x429fa2501f151b3dull,
		0x4659c72bea05d59eull, 0x984b7fdccf5a6634ull, 0xf742232953fbb161ull,
		0x3041860e08c021c7ull, 0x747bfd9616cd9386ull, 0x4bb1367192312787ull,
		0x1b72a1638a6c44d3ull, 0x4a0e68a6e8359a66ull, 0x169a5039f258b6caull,
		0xb98a2ef44edee5a4ull, 0xd9083fe85e43a737ull, 0x967f6ce239624e13ull,
		0x8874f62d3c1a7982ull, 0x3c1629830af06e3full, 0x9165ebfd427e5a8eull,
		0xb5dd81794ceeaa5cull, 0x0de8f15a7834f219ull, 0x70bd98ede3dd5d25ull,
		0xaccc9ca9328a8950ull, 0x56664eda1945ca28ull, 0x221db34c0f8859aeull,
		0x26dbd637fa98970dull, 0x1acdffb4f068f932ull, 0x4585254f64090fa0ull,
		0x72de245e17d53afaull, 0x1546b25d7c546cf4ull, 0x207e0ffffb803e71ull,
		0xfaaad2732bcf4378ull, 0xb462dfae36ea17bdull, 0xcf926fd1ac1b11fdull,
		0xe0672dc7dba7ba4aull, 0xd3fa49ad5d6b41b3ull, 0x8ba81449b216a3bcull,
		0x14f9ec8a0650d115ull, 0x40fc1ee3eb1d7ce2ull, 0x23a2ed9b758ce44full,
		0x782c521b14fddc7eull, 0x1c68267cf170504eull, 0xbcf31558c1ca96e6ull,
		0xa781b43b4ba6d235ull, 0xf6fd7dfe29ff0c80ull, 0xb0a4bad5c3fad91eull,
		0xd199f51ea963266cull, 0x414340349119c103ull, 0x5405f269ed4dadf7ull,
		0xabd61bb649969dcdull, 0x6813dbeae7bdc3c8ull, 0x65fb2ab09f8931d1ull,
		0xf1e7fae152e3181dull, 0xc1a67cef5a2339daull, 0x7a4feea8e0f5bba1ull,
		0x1e0b9acf05783791ull, 0x5b8ebf8061713831ull, 0x80e53cdbcb3af8d9ull,
		0x7e898bd315e57502ull, 0xc6bcfbf0213f2d47ull, 0x95a38e86b76e942dull,
		0x092e94218d243cbaull, 0x8339debf453622e7ull, 0xb11be402b9fe64ffull,
		0x57d9100d634177c9ull, 0xcc4e8db52217cbc3ull, 0x3b0cae9c71ec7aa2ull,
		0xfb158ca451cbfe99ull, 0x2b33276d82ac6514ull, 0x01bf5ed77a04bde1ull,
		0xc5601994af33f779ull, 0x75c4a3416cc92e67ull, 0xf3844652a6eb7fc2ull,
		0x3487e375fdd0ef64ull, 0x18ae430704609eedull, 0x4d14efb993298efbull,
		0x815a620cb13e4538ull, 0x125c354207487869ull, 0x9eeea614ce42cf48ull,
		0xce2d3106d61fac1cull, 0xbbe99247bad6827bull, 0x071a871f7b1c149dull,
		0x2e4a1cc10db81656ull, 0x77a71ff298c149b8ull, 0x06a5d9c80118a97cull,
		0xad73c27e488e34b1ull, 0x443a7b981e0db241ull, 0xe3bbcfa355ab6074ull,
		0x0af276450328e684ull, 0x73617a896dd1871bull, 0x58525de4ef7de20full,
		0xb7be3dcab8e6cd83ull, 0x19111dd07e64230cull, 0x842359a03e2a367aull,
		0x103f89f1f3401fb6ull, 0xdc710444d157d475ull, 0xb835702334da5845ull,
		0x4320fc876511a6dcull, 0xd026abc9d3679b8dull, 0x17250eee885c0b2bull,
		0x90dab52a387ae76full, 0x31fed8d972c49c26ull, 0x89cba8fa461ec463ull,
		0x2ff5421677bcabb7ull, 0x396f122f85e41d7dull, 0xa09b332430bac6a8ull,
		0xc888e8ced7070560ull, 0xaeaf201ac682ee8full, 0x1180d7268944a257ull,
		0xf058a43628e7a5fcull, 0xbd4c4b8fbbce2b07ull, 0xa1246df34abe7b49ull,
		0x7d5569b79be9af3cull, 0xa9b5a705bd9efa12ull, 0xdb6b835baa4bc0e8ull,
		0x05793bac8f147342ull, 0x21c1512881848390ull, 0xfdb0556c50d357e5ull,
		0x613d4fcb6a99ff72ull, 0x03dce2648e0cda3eull, 0xe949b9e6568386f0ull,
		0xfc0f0bbb2ad7ea04ull, 0x6a70675913b5a417ull, 0x7f36d5046fe1c8e3ull,
		0x0c57af8d02304ff8ull, 0x32223abdfcc84618ull, 0x0891caf6f720815bull,
		0xa63eeaec31a26fd4ull, 0x2507345374944d33ull, 0x49d28ac266394058ull,
		0xf5219f9aa7f3d6beull, 0x2d96fea583b4cc68ull, 0x5a31e1571b7585d0ull,
		0x8ed12fe53d02d0feull, 0xdfade6205f5b0e4bull, 0x4cabb16ee92d331aull,
		0x04c6657bf510cea3ull, 0xd73c2cd6a87b8f10ull, 0xe1d87310a1a307abull,
		0x6cd5be9112ad0d6bull, 0x97c032354366f3f2ull, 0xd4e0ceb22677552eull,
		0x0000000000000000ull, 0x29509bde76a402cbull, 0xc27a9e8bd42fe3e4ull,
		0x5ef7842cee654b73ull, 0xaf107ecdbc86536eull, 0x3fcacbe784fcb401ull,
		0xd55f90655c73e8cfull, 0xe6c2f40fdabf1336ull, 0xe8f6e7312c873b11ull,
		0xeb2a0555a28be12full, 0xe4a148bc2eb774e9ull, 0x9b979db84156bc0aull,
		0x6eb60222e6a56ab4ull, 0x87ffbbc4b026ec44ull, 0xc703a5275b3b90a6ull,
		0x47e699fc9001687full, 0x9c8d1aa73a4aa897ull, 0x7cea3760e1ed12ddull,
		0x4ec80ddd1d2554c5ull, 0x13e36b957d4cc588ull, 0x5d2b66486069914dull,
		0x92b90999cc7280b0ull, 0x517cc9c56259deb5ull, 0xc937b619ad03b881ull,
		0xec30824ad997f5b2ull, 0xa45d565fc5aa080bull, 0xd6837201d27f32f1ull,
		0x635ef3789e9198adull, 0x531f75769651b96aull, 0x4f77530a6721e924ull,
		0x486dd4151c3dfdb9ull, 0x5f48dafb9461f692ull, 0x375b011173dc355aull,
		0x3da9775470f4d3deull, 0x8d0dcd81b30e0ac0ull, 0x36e45fc609d888bbull,
		0x55baacbe97491016ull, 0x8cb29356c90ab721ull, 0x76184125e2c5f459ull,
		0x99f4210bb55edbd5ull, 0x6f095cf59ca1d755ull, 0x9f51f8c3b44672a9ull,
		0x3538bda287d45285ull, 0x50c39712185d6354ull, 0xf23b1885dcefc223ull,
		0x79930ccc6ef9619full, 0xed8fdc9da3934853ull, 0xcb540aaa590bdf5eull,
		0x5c94389f1a6d2cacull, 0xe77daad8a0bbaed7ull, 0x28efc5090ca0bf2aull,
		0xbf2ff73c4fc64cd8ull, 0xb37858b14df60320ull, 0xf8c96ec0dfc724a7ull,
		0x828680683f329f06ull, 0x941cd051cd6a29ccull, 0xc3c5c05cae2b5e05ull,
		0xb601631dc2e27062ull, 0xc01922382027843bull, 0x24b86a840e90f0d2ull,
		0xd245177a276ffc52ull, 0x0f8b4de98c3c95c6ull, 0x3e759530fef809e0ull,
		0x0b4d2892792c5b65ull, 0xc4df4743d5374a98ull, 0xa5e20888bfaeb5eaull,
		0xba56cc90c0d23f9aull, 0x38d04cf8ffe0a09cull, 0x62e1adafe495254cull,
		0x0263bcb3f40867dfull, 0xcaeb547d230f62bfull, 0x6082111c109d4293ull,
		0xdad4dd8cd04f7d09ull, 0xefec602e579b2f8cull, 0x1fb4c4187f7c8a70ull,
		0xffd3e9dfa4db303aull, 0x7bf0b07f9af10640ull, 0xf49ec14dddf76b5full,
		0x8f6e713247066d1full, 0x339d646a86ccfbf9ull, 0x64447467e58d8c30ull,
		0x2c29a072f9b07189ull, 0xd8b7613f24471ad6ull, 0x6627c8d41185ebefull,
		0xa347d140beb61c96ull, 0xde12b8f7255fb3aaull, 0x9d324470404e1576ull,
		0x9306574eb6763d51ull, 0xa80af9d2c79a47f3ull, 0x859c0777442e8b9bull,
		0x69ac853d9db97e29ull
	}, {
		0xc3407dfc2de6377eull, 0x5b9e93eea4256f77ull, 0xadb58fdd50c845e0ull,
		0x5219ff11a75bed86ull, 0x356b61cfd90b1de9ull, 0xfb8f406e25abe037ull,
		0x7a5a0231c0f60796ull, 0x9d3cd216e1f5020bull, 0x0c6550fb6b48d8f3ull,
		0xf57508c427ff1c62ull, 0x4ad35ffa71cb407dull, 0x6290a2da1666aa6dull,
		0xe284ec2349355f9full, 0xb3c307c53d7c84ecull, 0x05e23c0468365a02ull,
		0x190bac4d6c9ebfa8ull, 0x94bbbee9e28b80faull, 0xa34fc777529cb9b5ull,
		0xcc7b39f095bcd978ull, 0x2426addb0ce532e3ull, 0x7e79329312ce4fc7ull,
		0xab09a72eebec2917ull, 0xf8d15499f6b9d6c2ull, 0x1a55b8babf8c895dull,
		0xdb8add17fb769a85ull, 0xb57f2f368658e81bull, 0x8acd36f18f3f41f6ull,
		0x5ce3b7bba50f11d3ull, 0x114dcc14d5ee2f0aull, 0xb91a7fcded1030e8ull,
		0x81d5425fe55de7a1ull, 0xb6213bc1554adeeeull, 0x80144ef95f53f5f2ull,
		0x1e7688186db4c10cull, 0x3b912965db5fe1bcull, 0xc281715a97e8252dull,
		0x54a5d7e21c7f8171ull, 0x4b12535ccbc5522eull, 0x1d289cefbea6f7f9ull,
		0x6ef5f2217d2e729eull, 0xe6a7dc819b0d17ceull, 0x1b94b41c05829b0eull,
		0x33d7493c622f711eull, 0xdcf7f942fa5ce421ull, 0x600fba8b7f7a8ecbull,
		0x46b60f011a83988eull, 0x235b898e0dcf4c47ull, 0x957ab24f588592a9ull,
		0x4354330572b5c28cull, 0xa5f3ef84e9b8d542ull, 0x8c711e02341b2d01ull,
		0x0b1874ae6a62a657ull, 0x1213d8e306fc19ffull, 0xfe6d7c6a4d9dba35ull,
		0x65ed868f174cd4c9ull, 0x88522ea0e6236550ull, 0x899322065c2d7703ull,
		0xc01e690bfef4018bull, 0x915982ed8abddaf8ull, 0xbe675b98ec3a4e4cull,
		0xa996bf7f82f00db1ull, 0xe1daf8d49a27696aull, 0x2effd5d3dc8986e7ull,
		0xd153a51f2b1a2e81ull, 0x18caa0ebd690adfbull, 0x390e3134b243c51aull,
		0x2778b92cdff70416ull, 0x029f1851691c24a6ull, 0x5e7cafeacc133575ull,
		0xfa4e4cc89fa5f264ull, 0x5a5f9f481e2b7d24ull, 0x484c47ab18d764dbull,
		0x400a27f2a1a7f479ull, 0xaeeb9b2a83da7315ull, 0x721c626879869734ull,
		0x042330a2d2384851ull, 0x85f672fd3765aff0ull, 0xba446b3a3e02061dull,
		0x73dd6ecec3888567ull, 0xffac70ccf793a866ull, 0xdfa9edb5294ed2d4ull,
		0x6c6aea7014325638ull, 0x834a5a0e8c41c307ull, 0xcdba35562fb2cb2bull,
		0x0ad97808d06cb404ull, 0x0f3b440cb85aee06ull, 0xe5f9c876481f213bull,
		0x98deee1289c35809ull, 0x59018bbfcd394bd1ull, 0xe01bf47220297b39ull,
		0xde68e1139340c087ull, 0x9fa3ca4788e926adull, 0xbb85679c840c144eull,
		0x53d8f3b71d55ffd5ull, 0x0da45c5dd146caa0ull, 0x6f34fe87c72060cdull,
		0x57fbc315cf6db784ull, 0xcee421a1fca0fddeull, 0x3d2d0196607b8d4bull,
		0x642c8a29ad42c69aull, 0x14aff010bdd87508ull, 0xac74837beac657b3ull,
		0x3216459ad821634dull, 0x3fb219c70967a9edull, 0x06bc28f3bb246cf7ull,
		0xf2082c9126d562c6ull, 0x66b39278c45ee23cull, 0xbd394f6f3f2878b9ull,
		0xfd33689d9e8f8cc0ull, 0x37f4799eb017394full, 0x108cc0b26fe03d59ull,
		0xda4bd1b1417888d6ull, 0xb09d1332ee6eb219ull, 0x2f3ed975668794b4ull,
		0x58c0871977375982ull, 0x7561463d78ace990ull, 0x09876cff037e82f1ull,
		0x7fb83e35a8c05d94ull, 0x26b9b58a65f91645ull, 0xef20b07e9873953full,
		0x3148516d0b3355b8ull, 0x41cb2b541ba9e62aull, 0x790416c613e43163ull,
		0xa011d380818e8f40ull, 0x3a5025c36151f3efull, 0xd57095bdf92266d0ull,
		0x498d4b0da2d97688ull, 0x8b0c3a57353153a5ull, 0x21c491df64d368e1ull,
		0x8f2f0af5e7091bf4ull, 0x2da1c1240f9bb012ull, 0xc43d59a92ccc49daull,
		0xbfa6573e56345c1full, 0x828b56a8364fd154ull, 0x9a41f643e0df7cafull,
		0xbcf843c985266aeaull, 0x2b1de9d7b4bfdce5ull, 0x20059d79dedd7ab2ull,
		0x6dabe6d6ae3c446bull, 0x45e81bf6c991ae7bull, 0x6351ae7cac68b83eull,
		0xa432e32253b6c711ull, 0xd092a9b991143cd2ull, 0xcac711032e98b58full,
		0xd8d4c9e02864ac70ull, 0xc5fc550f96c25b89ull, 0xd7ef8dec903e4276ull,
		0x67729ede7e50f06full, 0xeac28c7af045cf3dull, 0xb15c1f945460a04aull,
		0x9cfddeb05bfb1058ull, 0x93c69abce3a1fe5eull, 0xeb0380dc4a4bdd6eull,
		0xd20db1e8f8081874ull, 0x229a8528b7c15e14ull, 0x44291750739fbc28ull,
		0xd3ccbd4e42060a27ull, 0xf62b1c33f4ed2a97ull, 0x86a8660ae4779905ull,
		0xd62e814a2a305025ull, 0x477703a7a08d8addull, 0x7b9b0e977af815c5ull,
		0x78c51a60a9ea2330ull, 0xa6adfb733aaae3b7ull, 0x97e5aa1e3199b60full,
		0x0000000000000000ull, 0xf4b404629df10e31ull, 0x5564db44a6719322ull,
		0x9207961a59afec0dull, 0x9624a6b88b97a45cull, 0x363575380a192b1cull,
		0x2c60cd82b595a241ull, 0x7d272664c1dc7932ull, 0x7142769faa94a1c1ull,
		0xa1d0df263b809d13ull, 0x1630e841d4c451aeull, 0xc1df65ad44fa13d8ull,
		0x13d2d445bcf20bacull, 0xd915c546926abe23ull, 0x38cf3d92084dd749ull,
		0xe766d0272103059dull, 0xc7634d5effde7f2full, 0x077d2455012a7ea4ull,
		0xedbfa82ff16fb199ull, 0xaf2a978c39d46146ull, 0x42953fa3c8bbd0dfull,
		0xcb061da59496a7dcull, 0x25e7a17db6eb20b0ull, 0x34aa6d6963050fbaull,
		0xa76cf7d580a4f1e4ull, 0xf7ea10954ee338c4ull, 0xfcf2643b24819e93ull,
		0xcf252d0746aeef8dull, 0x4ef06f58a3f3082cull, 0x563acfb37563a5d7ull,
		0x5086e740ce47c920ull, 0x2982f186dda3f843ull, 0x87696aac5e798b56ull,
		0x5d22bb1d1f010380ull, 0x035e14f7d31236f5ull, 0x3cec0d30da759f18ull,
		0xf3c920379cdb7095ull, 0xb8db736b571e22bbull, 0xdd36f5e44052f672ull,
		0xaac8ab8851e23b44ull, 0xa857b3d938fe1fe2ull, 0x17f1e4e76eca43fdull,
		0xec7ea4894b61a3caull, 0x9e62c6e132e734feull, 0xd4b1991b432c7483ull,
		0x6ad6c283af163acfull, 0x1ce9904904a8e5aaull, 0x5fbda34c761d2726ull,
		0xf910583f4cb7c491ull, 0xc6a241f845d06d7cull, 0x4f3163fe19fd1a7full,
		0xe99c988d2357f9c8ull, 0x8eee06535d0709a7ull, 0x0efa48aa0254fc55ull,
		0xb4be23903c56fa48ull, 0x763f52caabbedf65ull, 0xeee1bcd8227d876cull,
		0xe345e085f33b4dccull, 0x3e731561b369bbbeull, 0x2843fd2067adea10ull,
		0x2adce5710eb1ceb6ull, 0xb7e03767ef44ccbdull, 0x8db012a48e153f52ull,
		0x61ceb62dc5749c98ull, 0xe85d942b9959eb9bull, 0x4c6f7709caef2c8aull,
		0x84377e5b8d6bbda3ull, 0x30895dcbb13d47ebull, 0x74a04a9bc2a2fbc3ull,
		0x6b17ce251518289cull, 0xe438c4d0f2113368ull, 0x1fb784bed7bad35full,
		0x9b80fae55ad16efcull, 0x77fe5e6c11b0cd36ull, 0xc858095247849129ull,
		0x08466059b97090a2ull, 0x01c10ca6ba0e1253ull, 0x6988d6747c040c3aull,
		0x6849dad2c60a1e69ull, 0x5147ebe67449db73ull, 0xc99905f4fd8a837aull,
		0x991fe2b433cd4a5aull, 0xf09734c04fc94660ull, 0xa28ecbd1e892abe6ull,
		0xf1563866f5c75433ull, 0x4dae7baf70e13ed9ull, 0x7ce62ac27bd26b61ull,
		0x70837a39109ab392ull, 0x90988e4b30b3c8abull, 0xb2020b63877296bfull,
		0x156efcb607d6675bull
	}, {
		0xe63f55ce97c331d0ull, 0x25b506b0015bba16ull, 0xc8706e29e6ad9ba8ull,
		0x5b43d3775d521f6aull, 0x0bfa3d577035106eull, 0xab95fc172afb0e66ull,
		0xf64b63979e7a3276ull, 0xf58b4562649dad4bull, 0x48f7c3dbae0c83f1ull,
		0xff31916642f5c8c5ull, 0xcbb048dc1c4a0495ull, 0x66b8f83cdf622989ull,
		0x35c130e908e2b9b0ull, 0x7c761a61f0b34fa1ull, 0x3601161cf205268dull,
		0x9e54ccfe2219b7d6ull, 0x8b7d90a538940837ull, 0x9cd403588ea35d0bull,
		0xbc3c6fea9ccc5b5aull, 0xe5ff733b6d24aeedull, 0xceed22de0f7eb8d2ull,
		0xec8581cab1ab545eull, 0xb96105e88ff8e71dull, 0x8ca03501871a5eadull,
		0x76ccce65d6db2a2full, 0x5883f582a7b58057ull, 0x3f7be4ed2e8adc3eull,
		0x0fe7be06355cd9c9ull, 0xee054e6c1d11be83ull, 0x1074365909b903a6ull,
		0x5dde9f80b4813c10ull, 0x4a770c7d02b6692cull, 0x5379c8d5d7809039ull,
		0xb4067448161ed409ull, 0x5f5e5026183bd6cdull, 0xe898029bf4c29df9ull,
		0x7fb63c940a54d09cull, 0xc5171f897f4ba8bcull, 0xa6f28db7b31d3d72ull,
		0x2e4f3be7716eaa78ull, 0x0d6771a099e63314ull, 0x82076254e41bf284ull,
		0x2f0fd2b42733df98ull, 0x5c9e76d3e2dc49f0ull, 0x7aeb569619606cdbull,
		0x83478b07b2468764ull, 0xcfadcb8d5923cd32ull, 0x85dac7f05b95a41eull,
		0xb5469d1b4043a1e9ull, 0xb821ecbbd9a592fdull, 0x1b8e0b0e798c13c8ull,
		0x62a57b6d9a0be02eull, 0xfcf1b793b81257f8ull, 0x9d94ea0bd8fe28ebull,
		0x4cea408aeb654a56ull, 0x23284a47e888996cull, 0x2d8f1d128b893545ull,
		0xf4cbac3132c0d8abull, 0xbd7c86b9ca912ebaull, 0x3a268eef3dbe6079ull,
		0xf0d62f6077a9110cull, 0x2735c916ade150cbull, 0x89fd5f03942ee2eaull,
		0x1acee25d2fd16628ull, 0x90f39bab41181bffull, 0x430dfe8cde39939full,
		0xf70b8ac4c8274796ull, 0x1c53aeaac6024552ull, 0x13b410acf35e9c9bull,
		0xa532ab4249faa24full, 0x2b1251e5625a163full, 0xd7e3e676da4841c7ull,
		0xa7b264e4e5404892ull, 0xda8497d643ae72d3ull, 0x861ae105a1723b23ull,
		0x38a6414991048aa4ull, 0x6578dec92585b6b4ull, 0x0280cfa6acbaeaddull,
		0x88bdb650c273970aull, 0x9333bd5ebbff84c2ull, 0x4e6a8f2c47dfa08bull,
		0x321c954db76cef2aull, 0x418d312a72837942ull, 0xb29b38bfffcdf773ull,
		0x6c022c38f90a4c07ull, 0x5a033a240b0f6a8aull, 0x1f93885f3ce5da6full,
		0xc38a537e96988bc6ull, 0x39e6a81ac759ff44ull, 0x29929e43cee0fce2ull,
		0x40cdd87924de0ca2ull, 0xe9d8ebc8a29fe819ull, 0x0c2798f3cfbb46f4ull,
		0x55e484223e53b343ull, 0x4650948ecd0d2fd8ull, 0x20e86cb2126f0651ull,
		0x6d42c56baf5739e7ull, 0xa06fc1405ace1e08ull, 0x7babbfc54f3d193bull,
		0x424d17df8864e67full, 0xd8045870ef14980eull, 0xc6d7397c85ac3781ull,
		0x21a885e1443273b1ull, 0x67f8116f893f5c69ull, 0x24f5efe35706cff6ull,
		0xd56329d076f2ab1aull, 0x5e1eb9754e66a32dull, 0x28d2771098bd8902ull,
		0x8f6013f47dfdc190ull, 0x17a993fdb637553cull, 0xe0a219397e1012aaull,
		0x786b9930b5da8606ull, 0x6e82e39e55b0a6daull, 0x875a0856f72f4ec3ull,
		0x3741ff4fa458536dull, 0xac4859b3957558fcull, 0x7ef6d5c75c09a57cull,
		0xc04a758b6c7f14fbull, 0xf9acdd91ab26ebbfull, 0x7391a467c5ef9668ull,
		0x335c7c1ee1319acaull, 0xa91533b18641e4bbull, 0xe4bf9a683b79db0dull,
		0x8e20faa72ba0b470ull, 0x51f907737b3a7ae4ull, 0x2268a314bed5ec8cull,
		0xd944b123b949edeeull, 0x31dcb3b84d8b7017ull, 0xd3fe65279f218860ull,
		0x097af2f1dc8ffab3ull, 0x9b09a6fc312d0b91ull, 0xcc6ded78a3c4520full,
		0x3481d9ba5ebfcc50ull, 0x4f2a667f1182d56bull, 0xdfd9fdd4509ace94ull,
		0x26752045fbbc252bull, 0xbffc491f662bc467ull, 0xdd593272fc202449ull,
		0x3cbbc218d46d4303ull, 0x91b372f817456e1full, 0x681faf69bc6385a0ull,
		0xb686bbeebaa43ed4ull, 0x1469b5084cd0ca01ull, 0x98c98009cbca94acull,
		0x6438379a73d8c354ull, 0xc2caba2dc0c5fe26ull, 0x3e3b0dbe78d7a9deull,
		0x50b9ee202d670f04ull, 0x4590b27b37eab0e5ull, 0x6025b4cb36b10af3ull,
		0xfb2c1237079c0162ull, 0xa12f28130c936be8ull, 0x4b37e52e54eb1cccull,
		0x083a1ba28ad28f53ull, 0xc10a9cd83a22611bull, 0x9f1425ad7444c236ull,
		0x069d4cf7e9d3237aull, 0xedc56899e7f621beull, 0x778c273680865fcfull,
		0x309c5aeb1bd605f7ull, 0x8de0dc52d1472b4dull, 0xf8ec34c2fd7b9e5full,
		0xea18cd3d58787724ull, 0xaad515447ca67b86ull, 0x9989695a9d97e14cull,
		0x0000000000000000ull, 0xf196c63321f464ecull, 0x71116bc169557cb5ull,
		0xaf887f466f92c7c1ull, 0x972e3e0ffe964d65ull, 0x190ec4a8d536f915ull,
		0x95aef1a9522ca7b8ull, 0xdc19db21aa7d51a9ull, 0x94ee18fa0471d258ull,
		0x8087adf248a11859ull, 0xc457f6da2916dd5cull, 0xfa6cfb6451c17482ull,
		0xf256e0c6db13fbd1ull, 0x6a9f60cf10d96f7dull, 0x4daaa9d9bd383fb6ull,
		0x03c026f5fae79f3dull, 0xde99148706c7bb74ull, 0x2a52b8b6340763dfull,
		0x6fc20acd03edd33aull, 0xd423c08320afdefaull, 0xbbe1ca4e23420dc0ull,
		0x966ed75ca8cb3885ull, 0xeb58246e0e2502c4ull, 0x055d6a021334bc47ull,
		0xa47242111fa7d7afull, 0xe3623fcc84f78d97ull, 0x81c744a11efc6db9ull,
		0xaec8961539cfb221ull, 0xf31609958d4e8e31ull, 0x63e5923ecc5695ceull,
		0x47107ddd9b505a38ull, 0xa3afe7b5a0298135ull, 0x792b7063e387f3e6ull,
		0x0140e953565d75e0ull, 0x12f4f9ffa503e97bull, 0x750ce8902c3cb512ull,
		0xdbc47e8515f30733ull, 0x1ed3610c6ab8af8full, 0x5239218681dde5d9ull,
		0xe222d69fd2aaf877ull, 0xfe71783514a8bd25ull, 0xcaf0a18f4a177175ull,
		0x61655d9860ec7f13ull, 0xe77fbc9dc19e4430ull, 0x2ccff441ddd440a5ull,
		0x16e97aaee06a20dcull, 0xa855dae2d01c915bull, 0x1d1347f9905f30b2ull,
		0xb7c652bdecf94b34ull, 0xd03e43d265c6175dull, 0xfdb15ec0ee4f2218ull,
		0x57644b8492e9599eull, 0x07dda5a4bf8e569aull, 0x54a46d71680ec6a3ull,
		0x5624a2d7c4b42c7eull, 0xbebca04c3076b187ull, 0x7d36f332a6ee3a41ull,
		0x3b6667bc6be31599ull, 0x695f463aea3ef040ull, 0xad08b0e0c3282d1cull,
		0xb15b1e4a052a684eull, 0x44d05b2861b7c505ull, 0x15295c5b1a8dbfe1ull,
		0x744c01c37a61c0f2ull, 0x59c31cd1f1e8f5b7ull, 0xef45a73f4b4ccb63ull,
		0x6bdf899c46841a9dull, 0x3dfb2b4b823036e3ull, 0xa2ef0ee6f674f4d5ull,
		0x184e2dfb836b8cf5ull, 0x1134df0a5fe47646ull, 0xbaa1231d751f7820ull,
		0xd17eaa81339b62bdull, 0xb01bf71953771daeull, 0x849a2ea30dc8d1feull,
		0x705182923f080955ull, 0x0ea757556301ac29ull, 0x041d83514569c9a7ull,
		0x0abad4042668658eull, 0x49b72a88f851f611ull, 0x8a3d79f66ec97dd7ull,
		0xcd2d042bf59927efull, 0xc930877ab0f0ee48ull, 0x9273540deda2f122ull,
		0xc797d02fd3f14261ull, 0xe1e2f06a284d674aull, 0xd2be8c74c97cfd80ull,
		0x9a494faf67707e71ull, 0xb3dbd1eca9908293ull, 0x72d14d3493b2e388ull,
		0xd6a30f258c153427ull
	}
};
#else
/* Nonlinear Bijections of Binary Vector Sets - SBOX. */
static const GOST3411_2012_ALIGN(32) uint8_t gost3411_2012_sbox[256] = {
	0xfc, 0xee, 0xdd, 0x11, 0xcf, 0x6e, 0x31, 0x16,
	0xfb, 0xc4, 0xfa, 0xda, 0x23, 0xc5, 0x04, 0x4d,
	0xe9, 0x77, 0xf0, 0xdb, 0x93, 0x2e, 0x99, 0xba,
	0x17, 0x36, 0xf1, 0xbb, 0x14, 0xcd, 0x5f, 0xc1,
	0xf9, 0x18, 0x65, 0x5a, 0xe2, 0x5c, 0xef, 0x21,
	0x81, 0x1c, 0x3c, 0x42, 0x8b, 0x01, 0x8e, 0x4f,
	0x05, 0x84, 0x02, 0xae, 0xe3, 0x6a, 0x8f, 0xa0,
	0x06, 0x0b, 0xed, 0x98, 0x7f, 0xd4, 0xd3, 0x1f,
	0xeb, 0x34, 0x2c, 0x51, 0xea, 0xc8, 0x48, 0xab,
	0xf2, 0x2a, 0x68, 0xa2, 0xfd, 0x3a, 0xce, 0xcc,
	0xb5, 0x70, 0x0e, 0x56, 0x08, 0x0c, 0x76, 0x12,
	0xbf, 0x72, 0x13, 0x47, 0x9c, 0xb7, 0x5d, 0x87,
	0x15, 0xa1, 0x96, 0x29, 0x10, 0x7b, 0x9a, 0xc7,
	0xf3, 0x91, 0x78, 0x6f, 0x9d, 0x9e, 0xb2, 0xb1,
	0x32, 0x75, 0x19, 0x3d, 0xff, 0x35, 0x8a, 0x7e,
	0x6d, 0x54, 0xc6, 0x80, 0xc3, 0xbd, 0x0d, 0x57,
	0xdf, 0xf5, 0x24, 0xa9, 0x3e, 0xa8, 0x43, 0xc9,
	0xd7, 0x79, 0xd6, 0xf6, 0x7c, 0x22, 0xb9, 0x03,
	0xe0, 0x0f, 0xec, 0xde, 0x7a, 0x94, 0xb0, 0xbc,
	0xdc, 0xe8, 0x28, 0x50, 0x4e, 0x33, 0x0a, 0x4a,
	0xa7, 0x97, 0x60, 0x73, 0x1e, 0x00, 0x62, 0x44,
	0x1a, 0xb8, 0x38, 0x82, 0x64, 0x9f, 0x26, 0x41,
	0xad, 0x45, 0x46, 0x92, 0x27, 0x5e, 0x55, 0x2f,
	0x8c, 0xa3, 0xa5, 0x7d, 0x69, 0xd5, 0x95, 0x3b,
	0x07, 0x58, 0xb3, 0x40, 0x86, 0xac, 0x1d, 0xf7,
	0x30, 0x37, 0x6b, 0xe4, 0x88, 0xd9, 0xe7, 0x89,
	0xe1, 0x1b, 0x83, 0x49, 0x4c, 0x3f, 0xf8, 0xfe,
	0x8d, 0x53, 0xaa, 0x90, 0xca, 0xd8, 0x85, 0x61,
	0x20, 0x71, 0x67, 0xa4, 0x2d, 0x2b, 0x09, 0x5b,
	0xcb, 0x9b, 0x25, 0xd0, 0xbe, 0xe5, 0x6c, 0x52,
	0x59, 0xa6, 0x74, 0xd2, 0xe6, 0xf4, 0xb4, 0xc0,
	0xd1, 0x66, 0xaf, 0xc2, 0x39, 0x4b, 0x63, 0xb6
};

/* Byte Permutation. Tau table/macro. */
#if 1
#define GOST3411_2012_TAU(__n)	(((__n) << 3 | (__n) >> 3) & 0x3f)
#else
#define GOST3411_2012_TAU(__n)	(gost3411_2012_tau[(__n)])
static const GOST3411_2012_ALIGN(32) uint8_t gost3411_2012_tau[64] = {
	0,  8, 16, 24, 32, 40, 48, 56,
	1,  9, 17, 25, 33, 41, 49, 57,
	2, 10, 18, 26, 34, 42, 50, 58,
	3, 11, 19, 27, 35, 43, 51, 59,
	4, 12, 20, 28, 36, 44, 52, 60,
	5, 13, 21, 29, 37, 45, 53, 61,
	6, 14, 22, 30, 38, 46, 54, 62,
	7, 15, 23, 31, 39, 47, 55, 63
};
#endif

/* Linear Transformations of Binary Vector Sets. */
static const GOST3411_2012_ALIGN(32) uint64_t gost3411_2012_A[64] = {
	0x8e20faa72ba0b470ull, 0x47107ddd9b505a38ull, 0xad08b0e0c3282d1cull, 0xd8045870ef14980eull,
	0x6c022c38f90a4c07ull, 0x3601161cf205268dull, 0x1b8e0b0e798c13c8ull, 0x83478b07b2468764ull,
	0xa011d380818e8f40ull, 0x5086e740ce47c920ull, 0x2843fd2067adea10ull, 0x14aff010bdd87508ull,
	0x0ad97808d06cb404ull, 0x05e23c0468365a02ull, 0x8c711e02341b2d01ull, 0x46b60f011a83988eull,
	0x90dab52a387ae76full, 0x486dd4151c3dfdb9ull, 0x24b86a840e90f0d2ull, 0x125c354207487869ull,
	0x092e94218d243cbaull, 0x8a174a9ec8121e5dull, 0x4585254f64090fa0ull, 0xaccc9ca9328a8950ull,
	0x9d4df05d5f661451ull, 0xc0a878a0a1330aa6ull, 0x60543c50de970553ull, 0x302a1e286fc58ca7ull,
	0x18150f14b9ec46ddull, 0x0c84890ad27623e0ull, 0x0642ca05693b9f70ull, 0x0321658cba93c138ull,
	0x86275df09ce8aaa8ull, 0x439da0784e745554ull, 0xafc0503c273aa42aull, 0xd960281e9d1d5215ull,
	0xe230140fc0802984ull, 0x71180a8960409a42ull, 0xb60c05ca30204d21ull, 0x5b068c651810a89eull,
	0x456c34887a3805b9ull, 0xac361a443d1c8cd2ull, 0x561b0d22900e4669ull, 0x2b838811480723baull,
	0x9bcf4486248d9f5dull, 0xc3e9224312c8c1a0ull, 0xeffa11af0964ee50ull, 0xf97d86d98a327728ull,
	0xe4fa2054a80b329cull, 0x727d102a548b194eull, 0x39b008152acb8227ull, 0x9258048415eb419dull,
	0x492c024284fbaec0ull, 0xaa16012142f35760ull, 0x550b8e9e21f7a530ull, 0xa48b474f9ef5dc18ull,
	0x70a6a56e2440598eull, 0x3853dc371220a247ull, 0x1ca76e95091051adull, 0x0edd37c48a08a6d8ull,
	0x07e095624504536cull, 0x8d70c431ac02a736ull, 0xc83862965601dd1bull, 0x641c314b2b8ee083ull
};
#endif /* GOST3411_2012_USE_TABLES */

/* Iteration Constants. */
static const GOST3411_2012_ALIGN(32) uint64_t gost3411_2012_C[GOST3411_2012_ROUNDS_COUNT][GOST3411_2012_MSG_BLK_64CNT] = {
	{
		0xdd806559f2a64507ull, 0x05767436cc744d23ull,
		0xa2422a08a460d315ull, 0x4b7ce09192676901ull,
		0x714eb88d7585c4fcull, 0x2f6a76432e45d016ull,
		0xebcb2f81c0657c1full, 0xb1085bda1ecadae9ull
	}, {
		0xe679047021b19bb7ull, 0x55dda21bd7cbcd56ull,
		0x5cb561c2db0aa7caull, 0x9ab5176b12d69958ull,
		0x61d55e0f16b50131ull, 0xf3feea720a232b98ull,
		0x4fe39d460f70b5d7ull, 0x6fa3b58aa99d2f1aull
	}, {
		0x991e96f50aba0ab2ull, 0xc2b6f443867adb31ull,
		0xc1c93a376062db09ull, 0xd3e20fe490359eb1ull,
		0xf2ea7514b1297b7bull, 0x06f15e5f529c1f8bull,
		0x0a39fc286a3d8435ull, 0xf574dcac2bce2fc7ull
	}, {
		0x220cbebc84e3d12eull, 0x3453eaa193e837f1ull,
		0xd8b71333935203beull, 0xa9d72c82ed03d675ull,
		0x9d721cad685e353full, 0x488e857e335c3c7dull,
		0xf948e1a05d71e4ddull, 0xef1fdfb3e81566d2ull
	}, {
		0x601758fd7c6cfe57ull, 0x7a56a27ea9ea63f5ull,
		0xdfff00b723271a16ull, 0xbfcd1747253af5a3ull,
		0x359e35d7800fffbdull, 0x7f151c1f1686104aull,
		0x9a3f410c6ca92363ull, 0x4bea6bacad474799ull
	}, {
		0xfa68407a46647d6eull, 0xbf71c57236904f35ull,
		0x0af21f66c2bec6b6ull, 0xcffaa6b71c9ab7b4ull,
		0x187f9ab49af08ec6ull, 0x2d66c4f95142a46cull,
		0x6fa4c33b7a3039c0ull, 0xae4faeae1d3ad3d9ull
	}, {
		0x8886564d3a14d493ull, 0x3517454ca23c4af3ull,
		0x06476983284a0504ull, 0x0992abc52d822c37ull,
		0xd3473e33197a93c9ull, 0x399ec6c7e6bf87c9ull,
		0x51ac86febf240954ull, 0xf4c70e16eeaac5ecull
	}, {
		0xa47f0dd4bf02e71eull, 0x36acc2355951a8d9ull,
		0x69d18d2bd1a5c42full, 0xf4892bcb929b0690ull,
		0x89b4443b4ddbc49aull, 0x4eb7f8719c36de1eull,
		0x03e7aa020c6e4141ull, 0x9b1f5b424d93c9a7ull
	}, {
		0x7261445183235adbull, 0x0e38dc92cb1f2a60ull,
		0x7b2b8a9aa6079c54ull, 0x800a440bdbb2ceb1ull,
		0x3cd955b7e00d0984ull, 0x3a7d3a1b25894224ull,
		0x944c9ad8ec165fdeull, 0x378f5a541631229bull
	}, {
		0x74b4c7fb98459cedull, 0x3698fad1153bb6c3ull,
		0x7a1e6c303b7652f4ull, 0x9fe76702af69334bull,
		0x1fffe18a1b336103ull, 0x8941e71cff8a78dbull,
		0x382ae548b2e4f3f3ull, 0xabbedea680056f52ull
	}, {
		0x6bcaa4cd81f32d1bull, 0xdea2594ac06fd85dull,
		0xefbacd1d7d476e98ull, 0x8a1d71efea48b9caull,
		0x2001802114846679ull, 0xd8fa6bbbebab0761ull,
		0x3002c6cd635afe94ull, 0x7bcd9ed0efc889fbull
	}, {
		0x48bc924af11bd720ull, 0xfaf417d5d9b21b99ull,
		0xe71da4aa88e12852ull, 0x5d80ef9d1891cc86ull,
		0xf82012d430219f9bull, 0xcda43c32bcdf1d77ull,
		0xd21380b00449b17aull, 0x378ee767f11631baull
	}
};


/* Macro */
#define GOST3411_2012_XOR2_512(__dst, __a, __b) {			\
	((uint64_t*)(__dst))[0] = (((const uint64_t*)(__a))[0] ^ ((const uint64_t*)(__b))[0]); \
	((uint64_t*)(__dst))[1] = (((const uint64_t*)(__a))[1] ^ ((const uint64_t*)(__b))[1]); \
	((uint64_t*)(__dst))[2] = (((const uint64_t*)(__a))[2] ^ ((const uint64_t*)(__b))[2]); \
	((uint64_t*)(__dst))[3] = (((const uint64_t*)(__a))[3] ^ ((const uint64_t*)(__b))[3]); \
	((uint64_t*)(__dst))[4] = (((const uint64_t*)(__a))[4] ^ ((const uint64_t*)(__b))[4]); \
	((uint64_t*)(__dst))[5] = (((const uint64_t*)(__a))[5] ^ ((const uint64_t*)(__b))[5]); \
	((uint64_t*)(__dst))[6] = (((const uint64_t*)(__a))[6] ^ ((const uint64_t*)(__b))[6]); \
	((uint64_t*)(__dst))[7] = (((const uint64_t*)(__a))[7] ^ ((const uint64_t*)(__b))[7]); \
}
#define GOST3411_2012_XOR4_512(__dst, __a, __b, __c) {			\
	((uint64_t*)(__dst))[0] ^= (((const uint64_t*)(__a))[0] ^ ((const uint64_t*)(__b))[0] ^ ((const uint64_t*)(__c))[0]); \
	((uint64_t*)(__dst))[1] ^= (((const uint64_t*)(__a))[1] ^ ((const uint64_t*)(__b))[1] ^ ((const uint64_t*)(__c))[1]); \
	((uint64_t*)(__dst))[2] ^= (((const uint64_t*)(__a))[2] ^ ((const uint64_t*)(__b))[2] ^ ((const uint64_t*)(__c))[2]); \
	((uint64_t*)(__dst))[3] ^= (((const uint64_t*)(__a))[3] ^ ((const uint64_t*)(__b))[3] ^ ((const uint64_t*)(__c))[3]); \
	((uint64_t*)(__dst))[4] ^= (((const uint64_t*)(__a))[4] ^ ((const uint64_t*)(__b))[4] ^ ((const uint64_t*)(__c))[4]); \
	((uint64_t*)(__dst))[5] ^= (((const uint64_t*)(__a))[5] ^ ((const uint64_t*)(__b))[5] ^ ((const uint64_t*)(__c))[5]); \
	((uint64_t*)(__dst))[6] ^= (((const uint64_t*)(__a))[6] ^ ((const uint64_t*)(__b))[6] ^ ((const uint64_t*)(__c))[6]); \
	((uint64_t*)(__dst))[7] ^= (((const uint64_t*)(__a))[7] ^ ((const uint64_t*)(__b))[7] ^ ((const uint64_t*)(__c))[7]); \
}


/* This structure will hold context information for the GOST3411_2012 hashing operation. */
typedef struct gost3411_2012_ctx_s {
	size_t hash_size; /* hash size being used. */
	size_t buffer_usage; /* Data size in buffer. */
	GOST3411_2012_ALIGN(32) uint64_t hash[GOST3411_2012_HASH_MAX_64CNT]; /* Message Digest. */
	GOST3411_2012_ALIGN(32) uint64_t counter[GOST3411_2012_MSG_BLK_64CNT]; /* Counter: count processed data len. */
	GOST3411_2012_ALIGN(32) uint64_t sigma[GOST3411_2012_MSG_BLK_64CNT]; /* EPSILON / Sigma / Summ: summ512 all blocks. */
	GOST3411_2012_ALIGN(32) uint64_t buffer[GOST3411_2012_MSG_BLK_64CNT]; /* Input buffer: message blocks. */
	GOST3411_2012_ALIGN(32) uint64_t kbuf[GOST3411_2012_MSG_BLK_64CNT]; /* Temp buf for round key. */
	GOST3411_2012_ALIGN(32) uint64_t tbuf[GOST3411_2012_MSG_BLK_64CNT]; /* Temp buf for gost3411_2012_transform() (g_N(), g_0()). */
	GOST3411_2012_ALIGN(32) uint64_t sbuf[GOST3411_2012_MSG_BLK_64CNT]; /* Temp buf for SLP(). */
} gost3411_2012_ctx_t, *gost3411_2012_ctx_p;

typedef struct hmac_gost3411_2012_ctx_s {
	gost3411_2012_ctx_t ctx;
	GOST3411_2012_ALIGN(32) uint64_t k_opad[GOST3411_2012_MSG_BLK_64CNT]; /* outer padding - key XORd with opad. */
} hmac_gost3411_2012_ctx_t, *hmac_gost3411_2012_ctx_p;



/*
 *  gost3411_2012_init
 *
 *  Description:
 *      This function will initialize the gost3411_2012_ctx in preparation
 *      for computing a new GOST3411_2012 message digest.
 */
static inline void
gost3411_2012_init(size_t bits, gost3411_2012_ctx_p ctx) {

	memset(ctx, 0, sizeof(gost3411_2012_ctx_t));
	/* Load magic initialization constants. */
	switch (bits) {
	case 256:
	case GOST3411_2012_256_HASH_SIZE:
		ctx->hash_size = GOST3411_2012_256_HASH_SIZE;
		memset(&ctx->hash, 0x01, GOST3411_2012_HASH_MAX_SIZE); /* IV. */
		break;
	case 512:
	case GOST3411_2012_512_HASH_SIZE:
	default:
		ctx->hash_size = GOST3411_2012_512_HASH_SIZE;
		/* IV - all zeros. */
		break;
	}
}


static inline void
gost3411_2012_addmod512(uint64_t *a, const uint64_t *b) {
	register size_t i;
	register uint64_t ai, tm, crr = 0;

	for (i = 0; i < GOST3411_2012_MSG_BLK_64CNT; i ++) {
		tm = b[i];
		ai = (a[i] + crr);
		crr = ((ai < crr) ? 1 : 0);
		if (0 != tm) {
			ai += tm;
			if (ai < tm) {
				crr = 1;
			}
		}
		a[i] = ai;
	}
}

static inline void
gost3411_2012_addmod512_digit(uint64_t *a, const uint64_t b) {
	register size_t i;

	a[0] += b;
	if (a[0] >= b)
		return;
	for (i = 1; i < GOST3411_2012_MSG_BLK_64CNT; i ++) {
		a[i] ++;
		if (1 <= a[i])
			return;
	}
}



//#define GOST3411_2012_SSE 1
#define GOST3411_2012_AVX256 1

static inline void
prefetch(const void *ptr, size_t size) {
	register size_t i;

#pragma unroll
	for (i = 0; i < size; i += 32) {
		_mm_prefetch((((const char*)ptr) + i), 3);
	}
}




#if !defined(GOST3411_2012_SSE) && !defined(GOST3411_2012_AVX256)
/* i7-4770K CPU @ 3.50GHz
 * GCC:		18165865000
 * clang 3.8:	12587445000
 * clang 3.7:	12578230000
 * clang 3.6:	12580010000
 * clang 3.4:	18437637000
 * 
 * Intel(R) Core(TM)2 Duo CPU     E8400  @ 3.00GHz (2999.72-MHz K8-class CPU)
 * GCC:		20985366000
 * clang 3.8:	20455546000
 * clang 3.7:	20429535000
 * clang 3.6:	20440563000
 * clang 3.4:	23087971000
 * 
 * AMD Athlon(tm) 5350 APU with Radeon(tm) R3      (2050.04-MHz K8-class CPU)
 * GCC:		42101289000
 * clang 3.8:	33698184000
 * clang 3.7:	33705547000
 * clang 3.6:	34427690000
 * clang 3.4:	42143289000
 */
static inline void
gost3411_2012_XSLP(gost3411_2012_ctx_p ctx, uint64_t *dst,
    const uint64_t *a, const uint64_t *b) {
#ifndef GOST3411_2012_USE_SMALL_TABLES
	register size_t i;

	/* X(). */
	GOST3411_2012_XOR2_512(ctx->sbuf, a, b);
	/* SLP(). */
#pragma unroll
	for (i = 0; i < GOST3411_2012_MSG_BLK_64CNT; i ++) {
		dst[i]  = gost3411_2012_Ax[0][(ctx->sbuf[0] >> (i << 3)) & 0xff];
		dst[i] ^= gost3411_2012_Ax[1][(ctx->sbuf[1] >> (i << 3)) & 0xff];
		dst[i] ^= gost3411_2012_Ax[2][(ctx->sbuf[2] >> (i << 3)) & 0xff];
		dst[i] ^= gost3411_2012_Ax[3][(ctx->sbuf[3] >> (i << 3)) & 0xff];
		dst[i] ^= gost3411_2012_Ax[4][(ctx->sbuf[4] >> (i << 3)) & 0xff];
		dst[i] ^= gost3411_2012_Ax[5][(ctx->sbuf[5] >> (i << 3)) & 0xff];
		dst[i] ^= gost3411_2012_Ax[6][(ctx->sbuf[6] >> (i << 3)) & 0xff];
		dst[i] ^= gost3411_2012_Ax[7][(ctx->sbuf[7] >> (i << 3)) & 0xff];
	}
#else
	register size_t i, j;
	register uint64_t c, val;

	/* X(). */
	GOST3411_2012_XOR2_512(dst, a, b);

	/* PS(). */
	/* Byte Permutation + SBox transformation. */
#pragma unroll
	for (i = 0; i < GOST3411_2012_MSG_BLK_SIZE; i ++) {
		((uint8_t*)ctx->sbuf)[GOST3411_2012_TAU(i)] = gost3411_2012_sbox[((uint8_t*)dst)[i]];
	}

	/* L(). */
#ifdef __clang__ /* Better for: clang */
#pragma unroll
	for (i = 0; i < GOST3411_2012_MSG_BLK_64CNT; i ++) {
		c = 0;
		val = ctx->sbuf[i];
#pragma unroll
		for (j = 0; j < 64; j ++) {
			if (val & 0x8000000000000000ull) {
				c ^= gost3411_2012_A[j];
			}
			val = (val << 1);
		}
		dst[i] = c;
	}
#else /* Better for: GCC */
#pragma unroll
	for (i = 0; i < GOST3411_2012_MSG_BLK_64CNT; i ++) {
		c = 0;
#pragma unroll
		for (j = 0; j < 8; j ++) {
			val = (ctx->sbuf[i] >> (8 * (7 - j)));
			if (val & 0x80)
				c ^= gost3411_2012_A[(j * 8) + 0];
			if (val & 0x40)
				c ^= gost3411_2012_A[(j * 8) + 1];
			if (val & 0x20)
				c ^= gost3411_2012_A[(j * 8) + 2];
			if (val & 0x10)
				c ^= gost3411_2012_A[(j * 8) + 3];
			if (val & 0x08)
				c ^= gost3411_2012_A[(j * 8) + 4];
			if (val & 0x04)
				c ^= gost3411_2012_A[(j * 8) + 5];
			if (val & 0x02)
				c ^= gost3411_2012_A[(j * 8) + 6];
			if (val & 0x01)
				c ^= gost3411_2012_A[(j * 8) + 7];
		}
		dst[i] = c;
	}
#endif
#endif
}

/*
 * gost3411_2012_transform
 *
 * Description:
 *   This function will process the next 512 bits of the message
 *   stored in the Message_Block array.
 */
static inline void
gost3411_2012_transform(gost3411_2012_ctx_p ctx, const uint64_t *block) {
	size_t i;

	gost3411_2012_XSLP(ctx, ctx->kbuf, ctx->hash, ctx->counter); /* HASH design deffect here. */
	/* E(). */
	gost3411_2012_XSLP(ctx, ctx->tbuf, ctx->kbuf, block);
	gost3411_2012_XSLP(ctx, ctx->kbuf, ctx->kbuf, gost3411_2012_C[0]);
	for (i = 1; i < GOST3411_2012_ROUNDS_COUNT; i ++) {
		gost3411_2012_XSLP(ctx, ctx->tbuf, ctx->tbuf, ctx->kbuf);
		/* KeySchedule: next K. */
		gost3411_2012_XSLP(ctx, ctx->kbuf, ctx->kbuf, gost3411_2012_C[i]);
	}
	/* Final XOR. */
	GOST3411_2012_XOR4_512(ctx->hash, block, ctx->tbuf, ctx->kbuf);
}
#endif
#ifdef GOST3411_2012_SSE

#	include <xmmintrin.h> /* SSE */
#	include <emmintrin.h> /* SSE2 */
#	include <pmmintrin.h> /* SSE3 */
#	include <tmmintrin.h> /* SSSE3 */
#	include <smmintrin.h> /* SSE4.1 */


/* i7-4770K CPU @ 3.50GHz
 * GCC:		8693607000
 * clang 3.8:	9146352000
 * clang 3.7:	9138075000
 * clang 3.6:	9095312000
 * clang 3.4:	9117496000
 * 
 * Intel(R) Core(TM)2 Duo CPU     E8400  @ 3.00GHz (2999.72-MHz K8-class CPU)
 * GCC:		12014954000
 * clang 3.8:	11996137000
 * clang 3.7:	11974808000
 * clang 3.6:	12000445000
 * clang 3.4:	13126167000
 * 
 * AMD Athlon(tm) 5350 APU with Radeon(tm) R3      (2050.04-MHz K8-class CPU)
 * GCC:		21371450000
 * clang 3.8:	21478268000
 * clang 3.7:	21455894000
 * clang 3.6:	21519213000
 * clang 3.4:	22903030000
 */

#define GOST3411_2012_SSE_LOAD(__ptr, __xmm0, __xmm1, __xmm2, __xmm3) {	\
	__xmm0 = _mm_load_si128(&(__ptr)[0]);				\
	__xmm1 = _mm_load_si128(&(__ptr)[1]);				\
	__xmm2 = _mm_load_si128(&(__ptr)[2]);				\
	__xmm3 = _mm_load_si128(&(__ptr)[3]);				\
}
#define GOST3411_2012_SSE_STREAM_LOAD(__ptr, __xmm0, __xmm1, __xmm2, __xmm3) {	\
	__xmm0 = _mm_stream_load_si128(&(__ptr)[0]);			\
	__xmm1 = _mm_stream_load_si128(&(__ptr)[1]);			\
	__xmm2 = _mm_stream_load_si128(&(__ptr)[2]);			\
	__xmm3 = _mm_stream_load_si128(&(__ptr)[3]);			\
}
#define GOST3411_2012_SSE_LOADU(__ptr, __xmm0, __xmm1, __xmm2, __xmm3) { \
	__xmm0 = _mm_loadu_si128(&(__ptr)[0]);				\
	__xmm1 = _mm_loadu_si128(&(__ptr)[1]);				\
	__xmm2 = _mm_loadu_si128(&(__ptr)[2]);				\
	__xmm3 = _mm_loadu_si128(&(__ptr)[3]);				\
}
#define GOST3411_2012_SSE_STORE(__ptr, __xmm0, __xmm1, __xmm2, __xmm3) { \
	_mm_store_si128(&(__ptr)[0], __xmm0);				\
	_mm_store_si128(&(__ptr)[1], __xmm1);				\
	_mm_store_si128(&(__ptr)[2], __xmm2);				\
	_mm_store_si128(&(__ptr)[3], __xmm3);				\
}
#define GOST3411_2012_SSE_XOR2_512(__dxmm0, __dxmm1, __dxmm2, __dxmm3,	\
    __axmm0, __axmm1, __axmm2, __axmm3,					\
    __bxmm0, __bxmm1, __bxmm2, __bxmm3) { 				\
	__dxmm0 = _mm_xor_si128(__axmm0, __bxmm0);			\
	__dxmm1 = _mm_xor_si128(__axmm1, __bxmm1);			\
	__dxmm2 = _mm_xor_si128(__axmm2, __bxmm2);			\
	__dxmm3 = _mm_xor_si128(__axmm3, __bxmm3);			\
}

#define GOST3411_2012_SSE_SLP_ROUND2(__dxmm, row,			\
    __xmm0, __xmm1, __xmm2, __xmm3) {					\
	register uint64_t r0, r1;					\
									\
	r0  = gost3411_2012_Ax[0][_mm_extract_epi8(__xmm0, (row + 0))]; \
	r1  = gost3411_2012_Ax[0][_mm_extract_epi8(__xmm0, (row + 1))]; \
									\
	r0 ^= gost3411_2012_Ax[1][_mm_extract_epi8(__xmm0, (row + 8))]; \
	r1 ^= gost3411_2012_Ax[1][_mm_extract_epi8(__xmm0, (row + 9))]; \
									\
	r0 ^= gost3411_2012_Ax[2][_mm_extract_epi8(__xmm1, (row + 0))]; \
	r1 ^= gost3411_2012_Ax[2][_mm_extract_epi8(__xmm1, (row + 1))]; \
									\
	r0 ^= gost3411_2012_Ax[3][_mm_extract_epi8(__xmm1, (row + 8))]; \
	r1 ^= gost3411_2012_Ax[3][_mm_extract_epi8(__xmm1, (row + 9))]; \
									\
	r0 ^= gost3411_2012_Ax[4][_mm_extract_epi8(__xmm2, (row + 0))]; \
	r1 ^= gost3411_2012_Ax[4][_mm_extract_epi8(__xmm2, (row + 1))]; \
									\
	r0 ^= gost3411_2012_Ax[5][_mm_extract_epi8(__xmm2, (row + 8))]; \
	r1 ^= gost3411_2012_Ax[5][_mm_extract_epi8(__xmm2, (row + 9))]; \
									\
	r0 ^= gost3411_2012_Ax[6][_mm_extract_epi8(__xmm3, (row + 0))]; \
	r1 ^= gost3411_2012_Ax[6][_mm_extract_epi8(__xmm3, (row + 1))]; \
									\
	r0 ^= gost3411_2012_Ax[7][_mm_extract_epi8(__xmm3, (row + 8))]; \
	r1 ^= gost3411_2012_Ax[7][_mm_extract_epi8(__xmm3, (row + 9))]; \
									\
	__dxmm = _mm_set_epi64x(r1, r0);				\
}

#define GOST3411_2012_SSE_SLP_(__dxmm0, __dxmm1, __dxmm2, __dxmm3,	\
    __xmm0, __xmm1, __xmm2, __xmm3) {					\
	GOST3411_2012_SSE_SLP_ROUND2(__dxmm0, 0,			\
	    __xmm0, __xmm1, __xmm2, __xmm3);				\
	GOST3411_2012_SSE_SLP_ROUND2(__dxmm1, 2,			\
	    __xmm0, __xmm1, __xmm2, __xmm3);				\
	GOST3411_2012_SSE_SLP_ROUND2(__dxmm2, 4,			\
	    __xmm0, __xmm1, __xmm2, __xmm3);				\
	GOST3411_2012_SSE_SLP_ROUND2(__dxmm3, 6,			\
	    __xmm0, __xmm1, __xmm2, __xmm3);				\
}

#define GOST3411_2012_SSE_SLP(__dxmm0, __dxmm1, __dxmm2, __dxmm3,	\
    __xmm0, __xmm1, __xmm2, __xmm3) {					\
	register uint64_t r0, r1;					\
	register uint64_t t0, t1;					\
	register uint64_t y0, y1;					\
	register uint64_t v0, v1;					\
	GOST3411_2012_ALIGN(16) uint8_t idxarr[16];			\
									\
	_mm_store_si128((__m128i*)(void*)&idxarr[ 0], __xmm0);		\
									\
	r0  = gost3411_2012_Ax[0][idxarr[ 0]]; 	\
	r1  = gost3411_2012_Ax[0][idxarr[ 1]]; 	\
	t0  = gost3411_2012_Ax[0][idxarr[ 2]]; 	\
	t1  = gost3411_2012_Ax[0][idxarr[ 3]]; 	\
	y0  = gost3411_2012_Ax[0][idxarr[ 4]]; 	\
	y1  = gost3411_2012_Ax[0][idxarr[ 5]]; 	\
	v0  = gost3411_2012_Ax[0][idxarr[ 6]]; 	\
	v1  = gost3411_2012_Ax[0][idxarr[ 7]]; 	\
									\
	r0 ^= gost3411_2012_Ax[1][idxarr[ 8]];	\
	r1 ^= gost3411_2012_Ax[1][idxarr[ 9]];	\
	t0 ^= gost3411_2012_Ax[1][idxarr[10]];	\
	t1 ^= gost3411_2012_Ax[1][idxarr[11]];	\
	y0 ^= gost3411_2012_Ax[1][idxarr[12]];	\
	y1 ^= gost3411_2012_Ax[1][idxarr[13]];	\
	v0 ^= gost3411_2012_Ax[1][idxarr[14]];	\
	v1 ^= gost3411_2012_Ax[1][idxarr[15]];	\
									\
	_mm_store_si128((__m128i*)(void*)&idxarr[ 0], __xmm1);		\
	r0 ^= gost3411_2012_Ax[2][idxarr[ 0]]; 	\
	r1 ^= gost3411_2012_Ax[2][idxarr[ 1]]; 	\
	t0 ^= gost3411_2012_Ax[2][idxarr[ 2]]; 	\
	t1 ^= gost3411_2012_Ax[2][idxarr[ 3]]; 	\
	y0 ^= gost3411_2012_Ax[2][idxarr[ 4]]; 	\
	y1 ^= gost3411_2012_Ax[2][idxarr[ 5]]; 	\
	v0 ^= gost3411_2012_Ax[2][idxarr[ 6]]; 	\
	v1 ^= gost3411_2012_Ax[2][idxarr[ 7]]; 	\
									\
	r0 ^= gost3411_2012_Ax[3][idxarr[ 8]];	\
	r1 ^= gost3411_2012_Ax[3][idxarr[ 9]];	\
	t0 ^= gost3411_2012_Ax[3][idxarr[10]];	\
	t1 ^= gost3411_2012_Ax[3][idxarr[11]];	\
	y0 ^= gost3411_2012_Ax[3][idxarr[12]];	\
	y1 ^= gost3411_2012_Ax[3][idxarr[13]];	\
	v0 ^= gost3411_2012_Ax[3][idxarr[14]];	\
	v1 ^= gost3411_2012_Ax[3][idxarr[15]];	\
									\
	_mm_store_si128((__m128i*)(void*)&idxarr[ 0], __xmm2);		\
	r0 ^= gost3411_2012_Ax[4][idxarr[ 0]]; 	\
	r1 ^= gost3411_2012_Ax[4][idxarr[ 1]]; 	\
	t0 ^= gost3411_2012_Ax[4][idxarr[ 2]]; 	\
	t1 ^= gost3411_2012_Ax[4][idxarr[ 3]]; 	\
	y0 ^= gost3411_2012_Ax[4][idxarr[ 4]]; 	\
	y1 ^= gost3411_2012_Ax[4][idxarr[ 5]]; 	\
	v0 ^= gost3411_2012_Ax[4][idxarr[ 6]]; 	\
	v1 ^= gost3411_2012_Ax[4][idxarr[ 7]]; 	\
									\
	r0 ^= gost3411_2012_Ax[5][idxarr[ 8]];	\
	r1 ^= gost3411_2012_Ax[5][idxarr[ 9]];	\
	t0 ^= gost3411_2012_Ax[5][idxarr[10]];	\
	t1 ^= gost3411_2012_Ax[5][idxarr[11]];	\
	y0 ^= gost3411_2012_Ax[5][idxarr[12]];	\
	y1 ^= gost3411_2012_Ax[5][idxarr[13]];	\
	v0 ^= gost3411_2012_Ax[5][idxarr[14]];	\
	v1 ^= gost3411_2012_Ax[5][idxarr[15]];	\
									\
	_mm_store_si128((__m128i*)(void*)&idxarr[ 0], __xmm3);		\
	r0 ^= gost3411_2012_Ax[6][idxarr[ 0]]; 	\
	r1 ^= gost3411_2012_Ax[6][idxarr[ 1]]; 	\
	t0 ^= gost3411_2012_Ax[6][idxarr[ 2]]; 	\
	t1 ^= gost3411_2012_Ax[6][idxarr[ 3]]; 	\
	y0 ^= gost3411_2012_Ax[6][idxarr[ 4]]; 	\
	y1 ^= gost3411_2012_Ax[6][idxarr[ 5]]; 	\
	v0 ^= gost3411_2012_Ax[6][idxarr[ 6]]; 	\
	v1 ^= gost3411_2012_Ax[6][idxarr[ 7]]; 	\
									\
	r0 ^= gost3411_2012_Ax[7][idxarr[ 8]];	\
	r1 ^= gost3411_2012_Ax[7][idxarr[ 9]];	\
	t0 ^= gost3411_2012_Ax[7][idxarr[10]];	\
	t1 ^= gost3411_2012_Ax[7][idxarr[11]];	\
	y0 ^= gost3411_2012_Ax[7][idxarr[12]];	\
	y1 ^= gost3411_2012_Ax[7][idxarr[13]];	\
	v0 ^= gost3411_2012_Ax[7][idxarr[14]];	\
	v1 ^= gost3411_2012_Ax[7][idxarr[15]];	\
									\
	__dxmm0 = _mm_set_epi64x(r1, r0);				\
	__dxmm1 = _mm_set_epi64x(t1, t0);				\
	__dxmm2 = _mm_set_epi64x(y1, y0);				\
	__dxmm3 = _mm_set_epi64x(v1, v0);				\
}


#define GOST3411_2012_SSE_XSLP(__dxmm0, __dxmm1, __dxmm2, __dxmm3,	\
    __axmm0, __axmm1, __axmm2, __axmm3,					\
    __bxmm0, __bxmm1, __bxmm2, __bxmm3) {				\
	__m128i sxmm0, sxmm1, sxmm2, sxmm3;				\
									\
	GOST3411_2012_SSE_XOR2_512(sxmm0, sxmm1, sxmm2, sxmm3,		\
	    __axmm0, __axmm1, __axmm2, __axmm3,				\
	    __bxmm0, __bxmm1, __bxmm2, __bxmm3);			\
	GOST3411_2012_SSE_SLP(__dxmm0, __dxmm1, __dxmm2, __dxmm3,	\
	    sxmm0, sxmm1, sxmm2, sxmm3);				\
}

#define GOST3411_2012_SSE_LXSLP(__dxmm0, __dxmm1, __dxmm2, __dxmm3,	\
    __axmm0, __axmm1, __axmm2, __axmm3, __ptr) {			\
	__m128i sxmm0, sxmm1, sxmm2, sxmm3;				\
									\
	GOST3411_2012_SSE_LOAD(__ptr, sxmm0, sxmm1, sxmm2, sxmm3);	\
	GOST3411_2012_SSE_XOR2_512(sxmm0, sxmm1, sxmm2, sxmm3,		\
	    sxmm0, sxmm1, sxmm2, sxmm3,					\
	    __axmm0, __axmm1, __axmm2, __axmm3);			\
	GOST3411_2012_SSE_SLP(__dxmm0, __dxmm1, __dxmm2, __dxmm3,	\
	    sxmm0, sxmm1, sxmm2, sxmm3);				\
}

static inline void
gost3411_2012_transform(gost3411_2012_ctx_p ctx, const uint64_t *block) {
	register size_t i;
	__m128i *phash = (__m128i*)(void*)ctx->hash;
	const __m128i *pcounter = (const __m128i*)(const void*)ctx->counter;
	const __m128i *pblock = (const __m128i*)(const void*)block;
	const __m128i *pc;
	__m128i hxmm0, hxmm1, hxmm2, hxmm3; /* HASH. */
	__m128i kxmm0, kxmm1, kxmm2, kxmm3; /* Key. */
	__m128i txmm0, txmm1, txmm2, txmm3; /* Temp. */


	GOST3411_2012_SSE_LOAD(phash, hxmm0, hxmm1, hxmm2, hxmm3);
#if 0
	if (0 == (((size_t)block) & 15)) { /* 16 byte alligned. */
		GOST3411_2012_SSE_LOAD(pblock, txmm0, txmm1, txmm2, txmm3);
	} else { /* Unaligned. */
		GOST3411_2012_SSE_LOADU(pblock, txmm0, txmm1, txmm2, txmm3);
	}
#else
	GOST3411_2012_SSE_STREAM_LOAD((__m128i*)pblock, txmm0, txmm1, txmm2, txmm3);
#endif
	GOST3411_2012_SSE_LXSLP(kxmm0, kxmm1, kxmm2, kxmm3,
	    hxmm0, hxmm1, hxmm2, hxmm3,
	    pcounter); /* HASH design deffect here. */
	GOST3411_2012_SSE_XOR2_512(hxmm0, hxmm1, hxmm2, hxmm3,
	    hxmm0, hxmm1, hxmm2, hxmm3,
	    txmm0, txmm1, txmm2, txmm3); /* Pre Final XOR: hash ^= block. */
	/* E(). */
#pragma unroll
	for (i = 0; i < GOST3411_2012_ROUNDS_COUNT; i ++) {
		GOST3411_2012_SSE_XSLP(txmm0, txmm1, txmm2, txmm3,
		    txmm0, txmm1, txmm2, txmm3,
		    kxmm0, kxmm1, kxmm2, kxmm3);
		/* KeySchedule: next K. */
		GOST3411_2012_SSE_LXSLP(kxmm0, kxmm1, kxmm2, kxmm3,
		    kxmm0, kxmm1, kxmm2, kxmm3,
		    (const __m128i*)(const void*)gost3411_2012_C[i]);
	}
	/* Final XOR: hash ^= key ^ temp. */
	GOST3411_2012_SSE_XOR2_512(hxmm0, hxmm1, hxmm2, hxmm3,
	    hxmm0, hxmm1, hxmm2, hxmm3,
	    txmm0, txmm1, txmm2, txmm3);
	GOST3411_2012_SSE_XOR2_512(hxmm0, hxmm1, hxmm2, hxmm3,
	    hxmm0, hxmm1, hxmm2, hxmm3,
	    kxmm0, kxmm1, kxmm2, kxmm3);
	GOST3411_2012_SSE_STORE(phash, hxmm0, hxmm1, hxmm2, hxmm3);
	/* Restore the Floating-point status on the CPU. */
	//_mm_empty();
}
#endif

#ifdef GOST3411_2012_AVX256

#	include <immintrin.h> /* AVX256 */


#define GOST3411_2012_AVX256_LOAD(__ptr, __ymm0, __ymm1) {		\
	__ymm0 = _mm256_load_si256(&(__ptr)[0]);			\
	__ymm1 = _mm256_load_si256(&(__ptr)[1]);			\
}
#define GOST3411_2012_AVX256_STREAM_LOAD(__ptr, __ymm0, __ymm1) {	\
	__ymm0 = _mm256_stream_load_si256(&(__ptr)[0]);			\
	__ymm1 = _mm256_stream_load_si256(&(__ptr)[1]);			\
}
#define GOST3411_2012_AVX256_LOADU(__ptr, __ymm0, __ymm1) {		\
	__ymm0 = _mm256_loadu_si256(&(__ptr)[0]);			\
	__ymm1 = _mm256_loadu_si256(&(__ptr)[1]);			\
}
#define GOST3411_2012_AVX256_STORE(__ptr, __ymm0, __ymm1) {		\
	_mm256_store_si256(&(__ptr)[0], __ymm0);			\
	_mm256_store_si256(&(__ptr)[1], __ymm1);			\
}

#ifndef __AVX2__ /* AVX2 emulation. */
#define _mm256_xor_si256(__aymm, __bymm) 				\
	_mm256_castpd_si256(_mm256_xor_pd(				\
	    _mm256_castsi256_pd(__aymm), _mm256_castsi256_pd(__bymm)))
#endif /* __AVX2__ */

#define GOST3411_2012_AVX256_XOR2_512(__dymm0, __dymm1,			\
    __aymm0, __aymm1, __bymm0, __bymm1) { 				\
	__dymm0 = _mm256_xor_si256(__aymm0, __bymm0);			\
	__dymm1 = _mm256_xor_si256(__aymm1, __bymm1);			\
}


#ifndef __AVX2__666
#ifdef __clang__ /* Fix for clang. */
#define _mm256_extract_epi8_fx(__ymm, __imm)				\
    (_mm256_extract_epi8(__ymm, (__imm)) & 0xff)
#else
#define _mm256_extract_epi8_fx(__ymm, __imm)				\
    _mm256_extract_epi8(__ymm, (__imm))
#endif

/* i7-4770K CPU @ 3.50GHz
 * GCC:		10158788000
 * clang 3.8:	10486512000 / 10241965000 (AVX2)
 * clang 3.7:	10484803000
 * clang 3.4:	10497554000
 * 
 * AMD Athlon(tm) 5350 APU with Radeon(tm) R3      (2050.04-MHz K8-class CPU)
 * GCC:		24713716000
 * clang 3.8:	21053184000
 * clang 3.7:	21013776000
 * clang 3.4:	20679735000
 */
#define GOST3411_2012_AVX256_SLP___(__dymm0, __dymm1, __ymm0, __ymm1) {	\
	register uint64_t r0, r1, r2, r3;				\
	register uint64_t s0, s1, s2, s3;				\
									\
	r0  = gost3411_2012_Ax[0][_mm256_extract_epi8_fx(__ymm0,  0)];	\
	r1  = gost3411_2012_Ax[0][_mm256_extract_epi8_fx(__ymm0,  1)];	\
	r2  = gost3411_2012_Ax[0][_mm256_extract_epi8_fx(__ymm0,  2)];	\
	r3  = gost3411_2012_Ax[0][_mm256_extract_epi8_fx(__ymm0,  3)];	\
	s0  = gost3411_2012_Ax[0][_mm256_extract_epi8_fx(__ymm0,  4)];	\
	s1  = gost3411_2012_Ax[0][_mm256_extract_epi8_fx(__ymm0,  5)];	\
	s2  = gost3411_2012_Ax[0][_mm256_extract_epi8_fx(__ymm0,  6)];	\
	s3  = gost3411_2012_Ax[0][_mm256_extract_epi8_fx(__ymm0,  7)];	\
									\
	r0 ^= gost3411_2012_Ax[1][_mm256_extract_epi8_fx(__ymm0,  8)];	\
	r1 ^= gost3411_2012_Ax[1][_mm256_extract_epi8_fx(__ymm0,  9)];	\
	r2 ^= gost3411_2012_Ax[1][_mm256_extract_epi8_fx(__ymm0, 10)];	\
	r3 ^= gost3411_2012_Ax[1][_mm256_extract_epi8_fx(__ymm0, 11)];	\
	s0 ^= gost3411_2012_Ax[1][_mm256_extract_epi8_fx(__ymm0, 12)];	\
	s1 ^= gost3411_2012_Ax[1][_mm256_extract_epi8_fx(__ymm0, 13)];	\
	s2 ^= gost3411_2012_Ax[1][_mm256_extract_epi8_fx(__ymm0, 14)];	\
	s3 ^= gost3411_2012_Ax[1][_mm256_extract_epi8_fx(__ymm0, 15)];	\
									\
	r0 ^= gost3411_2012_Ax[2][_mm256_extract_epi8_fx(__ymm0, 16)];	\
	r1 ^= gost3411_2012_Ax[2][_mm256_extract_epi8_fx(__ymm0, 17)];	\
	r2 ^= gost3411_2012_Ax[2][_mm256_extract_epi8_fx(__ymm0, 18)];	\
	r3 ^= gost3411_2012_Ax[2][_mm256_extract_epi8_fx(__ymm0, 19)];	\
	s0 ^= gost3411_2012_Ax[2][_mm256_extract_epi8_fx(__ymm0, 20)]; 	\
	s1 ^= gost3411_2012_Ax[2][_mm256_extract_epi8_fx(__ymm0, 21)];	\
	s2 ^= gost3411_2012_Ax[2][_mm256_extract_epi8_fx(__ymm0, 22)];	\
	s3 ^= gost3411_2012_Ax[2][_mm256_extract_epi8_fx(__ymm0, 23)];	\
									\
	r0 ^= gost3411_2012_Ax[3][_mm256_extract_epi8_fx(__ymm0, 24)];	\
	r1 ^= gost3411_2012_Ax[3][_mm256_extract_epi8_fx(__ymm0, 25)];	\
	r2 ^= gost3411_2012_Ax[3][_mm256_extract_epi8_fx(__ymm0, 26)];	\
	r3 ^= gost3411_2012_Ax[3][_mm256_extract_epi8_fx(__ymm0, 27)];	\
	s0 ^= gost3411_2012_Ax[3][_mm256_extract_epi8_fx(__ymm0, 28)];	\
	s1 ^= gost3411_2012_Ax[3][_mm256_extract_epi8_fx(__ymm0, 29)];	\
	s2 ^= gost3411_2012_Ax[3][_mm256_extract_epi8_fx(__ymm0, 30)];	\
	s3 ^= gost3411_2012_Ax[3][_mm256_extract_epi8_fx(__ymm0, 31)];	\
									\
	r0 ^= gost3411_2012_Ax[4][_mm256_extract_epi8_fx(__ymm1,  0)];	\
	r1 ^= gost3411_2012_Ax[4][_mm256_extract_epi8_fx(__ymm1,  1)];	\
	r2 ^= gost3411_2012_Ax[4][_mm256_extract_epi8_fx(__ymm1,  2)];	\
	r3 ^= gost3411_2012_Ax[4][_mm256_extract_epi8_fx(__ymm1,  3)];	\
	s0 ^= gost3411_2012_Ax[4][_mm256_extract_epi8_fx(__ymm1,  4)];	\
	s1 ^= gost3411_2012_Ax[4][_mm256_extract_epi8_fx(__ymm1,  5)];	\
	s2 ^= gost3411_2012_Ax[4][_mm256_extract_epi8_fx(__ymm1,  6)];	\
	s3 ^= gost3411_2012_Ax[4][_mm256_extract_epi8_fx(__ymm1,  7)];	\
									\
	r0 ^= gost3411_2012_Ax[5][_mm256_extract_epi8_fx(__ymm1,  8)];	\
	r1 ^= gost3411_2012_Ax[5][_mm256_extract_epi8_fx(__ymm1,  9)];	\
	r2 ^= gost3411_2012_Ax[5][_mm256_extract_epi8_fx(__ymm1, 10)];	\
	r3 ^= gost3411_2012_Ax[5][_mm256_extract_epi8_fx(__ymm1, 11)];	\
	s0 ^= gost3411_2012_Ax[5][_mm256_extract_epi8_fx(__ymm1, 12)];	\
	s1 ^= gost3411_2012_Ax[5][_mm256_extract_epi8_fx(__ymm1, 13)];	\
	s2 ^= gost3411_2012_Ax[5][_mm256_extract_epi8_fx(__ymm1, 14)];	\
	s3 ^= gost3411_2012_Ax[5][_mm256_extract_epi8_fx(__ymm1, 15)];	\
									\
	r0 ^= gost3411_2012_Ax[6][_mm256_extract_epi8_fx(__ymm1, 16)];	\
	r1 ^= gost3411_2012_Ax[6][_mm256_extract_epi8_fx(__ymm1, 17)];	\
	r2 ^= gost3411_2012_Ax[6][_mm256_extract_epi8_fx(__ymm1, 18)];	\
	r3 ^= gost3411_2012_Ax[6][_mm256_extract_epi8_fx(__ymm1, 19)];	\
	s0 ^= gost3411_2012_Ax[6][_mm256_extract_epi8_fx(__ymm1, 20)];	\
	s1 ^= gost3411_2012_Ax[6][_mm256_extract_epi8_fx(__ymm1, 21)];	\
	s2 ^= gost3411_2012_Ax[6][_mm256_extract_epi8_fx(__ymm1, 22)];	\
	s3 ^= gost3411_2012_Ax[6][_mm256_extract_epi8_fx(__ymm1, 23)];	\
									\
	r0 ^= gost3411_2012_Ax[7][_mm256_extract_epi8_fx(__ymm1, 24)];	\
	r1 ^= gost3411_2012_Ax[7][_mm256_extract_epi8_fx(__ymm1, 25)];	\
	r2 ^= gost3411_2012_Ax[7][_mm256_extract_epi8_fx(__ymm1, 26)];	\
	r3 ^= gost3411_2012_Ax[7][_mm256_extract_epi8_fx(__ymm1, 27)];	\
	s0 ^= gost3411_2012_Ax[7][_mm256_extract_epi8_fx(__ymm1, 28)];	\
	s1 ^= gost3411_2012_Ax[7][_mm256_extract_epi8_fx(__ymm1, 29)];	\
	s2 ^= gost3411_2012_Ax[7][_mm256_extract_epi8_fx(__ymm1, 30)];	\
	s3 ^= gost3411_2012_Ax[7][_mm256_extract_epi8_fx(__ymm1, 31)];	\
									\
	__dymm0 = _mm256_set_epi64x(r3, r2, r1, r0);			\
	__dymm1 = _mm256_set_epi64x(s3, s2, s1, s0);			\
}

/* i7-4770K CPU @ 3.50GHz
 * GCC:		9647614000
 * clang 3.8:	9007906000 / 8654859000 (AVX2)
 * clang 3.7:	9013834000
 * clang 3.4:	9106909000
 * 
 * AMD Athlon(tm) 5350 APU with Radeon(tm) R3      (2050.04-MHz K8-class CPU)
 * GCC:		34306622000
 * clang 3.8:	26524505000
 * clang 3.7:	27460236000
 * clang 3.4:	30650436000
 */
#define GOST3411_2012_AVX256_SLP(__dymm0, __dymm1, __ymm0, __ymm1) {	\
	register uint64_t r0, r1, r2, r3;				\
	register uint64_t s0, s1, s2, s3;				\
	GOST3411_2012_ALIGN(32) uint8_t idxarr[64];			\
									\
	_mm256_store_si256((__m256i*)(void*)&idxarr[ 0], __ymm0);	\
	_mm256_store_si256((__m256i*)(void*)&idxarr[32], __ymm1);	\
	r0  = gost3411_2012_Ax[0][idxarr[ 0]];				\
	r1  = gost3411_2012_Ax[0][idxarr[ 1]];				\
	r2  = gost3411_2012_Ax[0][idxarr[ 2]];				\
	r3  = gost3411_2012_Ax[0][idxarr[ 3]];				\
	s0  = gost3411_2012_Ax[0][idxarr[ 4]];				\
	s1  = gost3411_2012_Ax[0][idxarr[ 5]];				\
	s2  = gost3411_2012_Ax[0][idxarr[ 6]];				\
	s3  = gost3411_2012_Ax[0][idxarr[ 7]];				\
									\
	r0 ^= gost3411_2012_Ax[1][idxarr[ 8]];				\
	r1 ^= gost3411_2012_Ax[1][idxarr[ 9]];				\
	r2 ^= gost3411_2012_Ax[1][idxarr[10]];				\
	r3 ^= gost3411_2012_Ax[1][idxarr[11]];				\
	s0 ^= gost3411_2012_Ax[1][idxarr[12]];				\
	s1 ^= gost3411_2012_Ax[1][idxarr[13]];				\
	s2 ^= gost3411_2012_Ax[1][idxarr[14]];				\
	s3 ^= gost3411_2012_Ax[1][idxarr[15]];				\
									\
	r0 ^= gost3411_2012_Ax[2][idxarr[16]];				\
	r1 ^= gost3411_2012_Ax[2][idxarr[17]];				\
	r2 ^= gost3411_2012_Ax[2][idxarr[18]];				\
	r3 ^= gost3411_2012_Ax[2][idxarr[19]];				\
	s0 ^= gost3411_2012_Ax[2][idxarr[20]]; 				\
	s1 ^= gost3411_2012_Ax[2][idxarr[21]];				\
	s2 ^= gost3411_2012_Ax[2][idxarr[22]];				\
	s3 ^= gost3411_2012_Ax[2][idxarr[23]];				\
									\
	r0 ^= gost3411_2012_Ax[3][idxarr[24]];				\
	r1 ^= gost3411_2012_Ax[3][idxarr[25]];				\
	r2 ^= gost3411_2012_Ax[3][idxarr[26]];				\
	r3 ^= gost3411_2012_Ax[3][idxarr[27]];				\
	s0 ^= gost3411_2012_Ax[3][idxarr[28]];				\
	s1 ^= gost3411_2012_Ax[3][idxarr[29]];				\
	s2 ^= gost3411_2012_Ax[3][idxarr[30]];				\
	s3 ^= gost3411_2012_Ax[3][idxarr[31]];				\
									\
	r0 ^= gost3411_2012_Ax[4][idxarr[32]];				\
	r1 ^= gost3411_2012_Ax[4][idxarr[33]];				\
	r2 ^= gost3411_2012_Ax[4][idxarr[34]];				\
	r3 ^= gost3411_2012_Ax[4][idxarr[35]];				\
	s0 ^= gost3411_2012_Ax[4][idxarr[36]];				\
	s1 ^= gost3411_2012_Ax[4][idxarr[37]];				\
	s2 ^= gost3411_2012_Ax[4][idxarr[38]];				\
	s3 ^= gost3411_2012_Ax[4][idxarr[39]];				\
									\
	r0 ^= gost3411_2012_Ax[5][idxarr[40]];				\
	r1 ^= gost3411_2012_Ax[5][idxarr[41]];				\
	r2 ^= gost3411_2012_Ax[5][idxarr[42]];				\
	r3 ^= gost3411_2012_Ax[5][idxarr[43]];				\
	s0 ^= gost3411_2012_Ax[5][idxarr[44]];				\
	s1 ^= gost3411_2012_Ax[5][idxarr[45]];				\
	s2 ^= gost3411_2012_Ax[5][idxarr[46]];				\
	s3 ^= gost3411_2012_Ax[5][idxarr[47]];				\
									\
	r0 ^= gost3411_2012_Ax[6][idxarr[48]];				\
	r1 ^= gost3411_2012_Ax[6][idxarr[49]];				\
	r2 ^= gost3411_2012_Ax[6][idxarr[50]];				\
	r3 ^= gost3411_2012_Ax[6][idxarr[51]];				\
	s0 ^= gost3411_2012_Ax[6][idxarr[52]];				\
	s1 ^= gost3411_2012_Ax[6][idxarr[53]];				\
	s2 ^= gost3411_2012_Ax[6][idxarr[54]];				\
	s3 ^= gost3411_2012_Ax[6][idxarr[55]];				\
									\
	r0 ^= gost3411_2012_Ax[7][idxarr[56]];				\
	r1 ^= gost3411_2012_Ax[7][idxarr[57]];				\
	r2 ^= gost3411_2012_Ax[7][idxarr[58]];				\
	r3 ^= gost3411_2012_Ax[7][idxarr[59]];				\
	s0 ^= gost3411_2012_Ax[7][idxarr[60]];				\
	s1 ^= gost3411_2012_Ax[7][idxarr[61]];				\
	s2 ^= gost3411_2012_Ax[7][idxarr[62]];				\
	s3 ^= gost3411_2012_Ax[7][idxarr[63]];				\
									\
	__dymm0 = _mm256_set_epi64x(r3, r2, r1, r0);			\
	__dymm1 = _mm256_set_epi64x(s3, s2, s1, s0);			\
}
#else /* __AVX2__ */
/* i7-4770K CPU @ 3.50GHz
 * GCC:		19234148000
 * clang 3.8:	18956077000
 * clang 3.7:	19059001000
 * clang 3.6:	19053848000
 * clang 3.4:	19140816000
 */
#define GOST3411_2012_AVX256_GATHER__(__aidx, __xmm)			\
	_mm256_i64gather_epi64(						\
	    (long long int const*)gost3411_2012_Ax[__aidx],		\
	    _mm256_cvtepu8_epi64(__xmm),				\
	    sizeof(uint64_t))

#define GOST3411_2012_AVX256_SLP__(__dymm0, __dymm1, __ymm0, __ymm1) {	\
	__m256i idxymm;							\
									\
	__dymm0 = GOST3411_2012_AVX256_GATHER(0, _mm256_extracti128_si256(__ymm0, 0));	\
	__dymm0 = _mm256_xor_si256(__dymm0, GOST3411_2012_AVX256_GATHER(2, _mm256_extracti128_si256(__ymm0, 1)));	\
									\
	idxymm = _mm256_srli_si256(__ymm0, 4);				\
	__dymm1 = GOST3411_2012_AVX256_GATHER(0, _mm256_extracti128_si256(idxymm, 0));	\
	__dymm1 = _mm256_xor_si256(__dymm1, GOST3411_2012_AVX256_GATHER(2, _mm256_extracti128_si256(idxymm, 1)));	\
									\
	idxymm = _mm256_srli_si256(__ymm0, 8);				\
	__dymm0 = _mm256_xor_si256(__dymm0, GOST3411_2012_AVX256_GATHER(1, _mm256_extracti128_si256(idxymm, 0)));	\
	__dymm0 = _mm256_xor_si256(__dymm0, GOST3411_2012_AVX256_GATHER(3, _mm256_extracti128_si256(idxymm, 1)));	\
									\
	idxymm = _mm256_srli_si256(__ymm0, 12);				\
	__dymm1 = _mm256_xor_si256(__dymm1, GOST3411_2012_AVX256_GATHER(1, _mm256_extracti128_si256(idxymm, 0)));	\
	__dymm1 = _mm256_xor_si256(__dymm1, GOST3411_2012_AVX256_GATHER(3, _mm256_extracti128_si256(idxymm, 1)));	\
									\
									\
	__dymm0 = _mm256_xor_si256(__dymm0, GOST3411_2012_AVX256_GATHER(4, _mm256_extracti128_si256(__ymm1, 0)));	\
	__dymm0 = _mm256_xor_si256(__dymm0, GOST3411_2012_AVX256_GATHER(6, _mm256_extracti128_si256(__ymm1, 1)));	\
									\
	idxymm = _mm256_srli_si256(__ymm1, 4);				\
	__dymm1 = _mm256_xor_si256(__dymm1, GOST3411_2012_AVX256_GATHER(4, _mm256_extracti128_si256(idxymm, 0)));	\
	__dymm1 = _mm256_xor_si256(__dymm1, GOST3411_2012_AVX256_GATHER(6, _mm256_extracti128_si256(idxymm, 1)));	\
									\
	idxymm = _mm256_srli_si256(__ymm1, 8);				\
	__dymm0 = _mm256_xor_si256(__dymm0, GOST3411_2012_AVX256_GATHER(5, _mm256_extracti128_si256(idxymm, 0)));	\
	__dymm0 = _mm256_xor_si256(__dymm0, GOST3411_2012_AVX256_GATHER(7, _mm256_extracti128_si256(idxymm, 1)));	\
									\
	idxymm = _mm256_srli_si256(__ymm1, 12);				\
	__dymm1 = _mm256_xor_si256(__dymm1, GOST3411_2012_AVX256_GATHER(5, _mm256_extracti128_si256(idxymm, 0)));	\
	__dymm1 = _mm256_xor_si256(__dymm1, GOST3411_2012_AVX256_GATHER(7, _mm256_extracti128_si256(idxymm, 1)));	\
}

/* i7-4770K CPU @ 3.50GHz
 * GCC:		17636751000
 * clang 3.8:	17563528000
 * clang 3.7:	18996508000
 * clang 3.6:	18999908000
 * clang 3.4:	21942882000
 */
#define GOST3411_2012_AVX256_GATHER_(__aidx, __ymm)			\
	_mm256_i64gather_epi64(						\
	    (long long int const*)gost3411_2012_Ax[__aidx],		\
	    __ymm, sizeof(uint64_t))

#define GOST3411_2012_AVX256_SLP_(__dymm0, __dymm1, __ymm0, __ymm1) {	\
	__m256i offsets, maskshuffle, maskymm;				\
									\
	/* |a0a1a2a3b0b1b2b3|c0c1c2c3d0d1d2d3|e0e1e2e3f0f1f2f3|g0g1g2g3h0h1h2h3| */ \
	/* |a0b0c0d0e0f0g0h0|a1b1c1d1e1f1g1h1|a2b2c2d2e2f2g2h2|a3b3c3d3e3f3g3h3| */ \
	maskshuffle = _mm256_setr_epi8(					\
		/*a0*/ 0, /*b0*/ 4, /*c0*/ 8, /*d0*/12,	/*|*/ /*a2*/ 2, /*b2*/ 6, /*c2*/10, /*d2*/14,	\
		/*a1*/ 1, /*b1*/ 5, /*c1*/ 9, /*d1*/13, /*|*/ /*a3*/ 3, /*b3*/ 7, /*c3*/11, /*d3*/15,	\
		/*---------------------------------------------------*/	\
		/*e0*/ 0, /*f0*/ 4, /*g0*/ 8, /*h0*/12, /*|*/ /*e2*/ 2, /*f2*/ 6, /*g2*/10, /*h2*/14,	\
		/*e1*/ 1, /*f1*/ 5, /*g1*/ 9, /*h1*/13, /*|*/ /*e3*/ 3, /*f3*/ 7, /*g3*/11, /*h3*/15);	\
	offsets = _mm256_setr_epi32(0, 4, 2, 6, 1, 5, 3, 7);		\
	maskymm = _mm256_set1_epi64x(0x00000000000000ff);		\
	__ymm0 = _mm256_permutevar8x32_epi32(_mm256_shuffle_epi8(__ymm0, maskshuffle), offsets);	\
	__ymm1 = _mm256_permutevar8x32_epi32(_mm256_shuffle_epi8(__ymm1, maskshuffle), offsets);	\
	/*_mm256_srli_si256 / _mm256_srli_epi64*/			\
	__dymm0 = GOST3411_2012_AVX256_GATHER(0, _mm256_and_si256(maskymm, __ymm0));	\
	__dymm1 = GOST3411_2012_AVX256_GATHER(0, _mm256_and_si256(maskymm, _mm256_srli_epi64(__ymm0, 8*1)));	\
									\
	__dymm0 = _mm256_xor_si256(__dymm0, GOST3411_2012_AVX256_GATHER(1, _mm256_and_si256(maskymm, _mm256_srli_epi64(__ymm0, 8*2))));	\
	__dymm1 = _mm256_xor_si256(__dymm1, GOST3411_2012_AVX256_GATHER(1, _mm256_and_si256(maskymm, _mm256_srli_epi64(__ymm0, 8*3))));	\
									\
	__dymm0 = _mm256_xor_si256(__dymm0, GOST3411_2012_AVX256_GATHER(2, _mm256_and_si256(maskymm, _mm256_srli_epi64(__ymm0, 8*4))));	\
	__dymm1 = _mm256_xor_si256(__dymm1, GOST3411_2012_AVX256_GATHER(2, _mm256_and_si256(maskymm, _mm256_srli_epi64(__ymm0, 8*5))));	\
									\
	__dymm0 = _mm256_xor_si256(__dymm0, GOST3411_2012_AVX256_GATHER(3, _mm256_and_si256(maskymm, _mm256_srli_epi64(__ymm0, 8*6))));	\
	__dymm1 = _mm256_xor_si256(__dymm1, GOST3411_2012_AVX256_GATHER(3, _mm256_srli_epi64(__ymm0, 8*7)));	\
									\
									\
	__dymm0 = _mm256_xor_si256(__dymm0, GOST3411_2012_AVX256_GATHER(4, _mm256_and_si256(maskymm, __ymm1)));	\
	__dymm1 = _mm256_xor_si256(__dymm1, GOST3411_2012_AVX256_GATHER(4, _mm256_and_si256(maskymm, _mm256_srli_epi64(__ymm1, 8*1))));	\
									\
	__dymm0 = _mm256_xor_si256(__dymm0, GOST3411_2012_AVX256_GATHER(5, _mm256_and_si256(maskymm, _mm256_srli_epi64(__ymm1, 8*2))));	\
	__dymm1 = _mm256_xor_si256(__dymm1, GOST3411_2012_AVX256_GATHER(5, _mm256_and_si256(maskymm, _mm256_srli_epi64(__ymm1, 8*3))));	\
									\
	__dymm0 = _mm256_xor_si256(__dymm0, GOST3411_2012_AVX256_GATHER(6, _mm256_and_si256(maskymm, _mm256_srli_epi64(__ymm1, 8*4))));	\
	__dymm1 = _mm256_xor_si256(__dymm1, GOST3411_2012_AVX256_GATHER(6, _mm256_and_si256(maskymm, _mm256_srli_epi64(__ymm1, 8*5))));	\
									\
	__dymm0 = _mm256_xor_si256(__dymm0, GOST3411_2012_AVX256_GATHER(7, _mm256_and_si256(maskymm, _mm256_srli_epi64(__ymm1, 8*6))));	\
	__dymm1 = _mm256_xor_si256(__dymm1, GOST3411_2012_AVX256_GATHER(7, _mm256_srli_epi64(__ymm1, 8*7)));	\
}


/* i7-4770K CPU @ 3.50GHz
 * GCC:		17522029000
 * clang 3.8:	18144509000
 * clang 3.7:	18812964000
 * clang 3.6:	18807209000
 * clang 3.4:	19524288000
 */
#define GOST3411_2012_AVX256_GATHER(__aidx, __yidx, __ymm)		\
	_mm256_i64gather_epi64(						\
	    (long long int const*)gost3411_2012_Ax[__aidx],		\
	    _mm256_shuffle_epi8(__ymm,					\
	        _mm256_setr_epi64x(					\
			(0x8080808080808000 | (__yidx)),		\
			(0x8080808080808008 | (__yidx)),		\
			(0x8080808080808000 | (__yidx)),		\
			(0x8080808080808008 | (__yidx)))),		\
	    sizeof(uint64_t))

#define GOST3411_2012_AVX256_SLP(__dymm0, __dymm1, __ymm0, __ymm1) {	\
	__m256i offsets, maskshuffle;					\
									\
	/* |a0a1a2a3b0b1b2b3|c0c1c2c3d0d1d2d3|e0e1e2e3f0f1f2f3|g0g1g2g3h0h1h2h3| */ \
	/* |a0b0c0d0e0f0g0h0|a1b1c1d1e1f1g1h1|a2b2c2d2e2f2g2h2|a3b3c3d3e3f3g3h3| */ \
	maskshuffle = _mm256_setr_epi8(					\
		/*a0*/ 0, /*b0*/ 4, /*c0*/ 8, /*d0*/12,	/*|*/ /*a2*/ 2, /*b2*/ 6, /*c2*/10, /*d2*/14,	\
		/*a1*/ 1, /*b1*/ 5, /*c1*/ 9, /*d1*/13, /*|*/ /*a3*/ 3, /*b3*/ 7, /*c3*/11, /*d3*/15,	\
		/*---------------------------------------------------*/	\
		/*e0*/ 0, /*f0*/ 4, /*g0*/ 8, /*h0*/12, /*|*/ /*e2*/ 2, /*f2*/ 6, /*g2*/10, /*h2*/14,	\
		/*e1*/ 1, /*f1*/ 5, /*g1*/ 9, /*h1*/13, /*|*/ /*e3*/ 3, /*f3*/ 7, /*g3*/11, /*h3*/15);	\
	offsets = _mm256_setr_epi32(0, 4, 2, 6, 1, 5, 3, 7);		\
	__ymm0 = _mm256_permutevar8x32_epi32(_mm256_shuffle_epi8(__ymm0, maskshuffle), offsets);	\
	__ymm1 = _mm256_permutevar8x32_epi32(_mm256_shuffle_epi8(__ymm1, maskshuffle), offsets);	\
									\
	__dymm0 = GOST3411_2012_AVX256_GATHER(0, 0, __ymm0);		\
	__dymm1 = GOST3411_2012_AVX256_GATHER(0, 1, __ymm0);		\
									\
	__dymm0 = _mm256_xor_si256(__dymm0, GOST3411_2012_AVX256_GATHER(1, 2, __ymm0));	\
	__dymm1 = _mm256_xor_si256(__dymm1, GOST3411_2012_AVX256_GATHER(1, 3, __ymm0));	\
									\
	__dymm0 = _mm256_xor_si256(__dymm0, GOST3411_2012_AVX256_GATHER(2, 4, __ymm0));	\
	__dymm1 = _mm256_xor_si256(__dymm1, GOST3411_2012_AVX256_GATHER(2, 5, __ymm0));	\
									\
	__dymm0 = _mm256_xor_si256(__dymm0, GOST3411_2012_AVX256_GATHER(3, 6, __ymm0));	\
	__dymm1 = _mm256_xor_si256(__dymm1, GOST3411_2012_AVX256_GATHER(3, 7, __ymm0));	\
									\
									\
	__dymm0 = _mm256_xor_si256(__dymm0, GOST3411_2012_AVX256_GATHER(4, 0, __ymm1));	\
	__dymm1 = _mm256_xor_si256(__dymm1, GOST3411_2012_AVX256_GATHER(4, 1, __ymm1));	\
									\
	__dymm0 = _mm256_xor_si256(__dymm0, GOST3411_2012_AVX256_GATHER(5, 2, __ymm1));	\
	__dymm1 = _mm256_xor_si256(__dymm1, GOST3411_2012_AVX256_GATHER(5, 3, __ymm1));	\
									\
	__dymm0 = _mm256_xor_si256(__dymm0, GOST3411_2012_AVX256_GATHER(6, 4, __ymm1));	\
	__dymm1 = _mm256_xor_si256(__dymm1, GOST3411_2012_AVX256_GATHER(6, 5, __ymm1));	\
									\
	__dymm0 = _mm256_xor_si256(__dymm0, GOST3411_2012_AVX256_GATHER(7, 6, __ymm1));	\
	__dymm1 = _mm256_xor_si256(__dymm1, GOST3411_2012_AVX256_GATHER(7, 7, __ymm1));	\
}
#endif /* __AVX2__ */


#define GOST3411_2012_AVX256_ADDMOD512(__dymm0, __dymm1, __ymm0, __ymm1) {	\
	__m256i carry0, carry1;						\
									\
	__dymm0 = _mm256_add_epi64(__dymm0, __ymm0);			\
	__dymm1 = _mm256_add_epi64(__dymm1, __ymm1);			\
	carry0 = _mm256_permute4x64_epi64(				\
	    _mm256_cmpgt_epi64(__ymm0, __dymm0),			\
	    ((1 << 0) | (2 << 2) | (3 << 4) | (0 << 6)));		\
	carry1 = _mm256_permute4x64_epi64(				\
	    _mm256_cmpgt_epi64(__ymm1, __dymm1),			\
	    ((1 << 0) | (2 << 2) | (3 << 4) | (0 << 6)));		\
	carry1 = _mm256_blend_epi32(carry1, carry0, 1);			\
	carry0 = _mm256_blend_epi32(carry0, _mm256_setzero_si256(), 1);	\
									\
	__dymm0 = _mm256_add_epi64(__dymm0, carry0);			\
	carry0 = _mm256_permute4x64_epi64(				\
	    _mm256_cmpgt_epi64(__ymm0, __dymm0),			\
	    ((1 << 0) | (2 << 2) | (3 << 4) | (0 << 6)));		\
	carry1 = _mm256_and_si256(carry1,				\
	    _mm256_blend_epi32(_mm256_setzero_si256(), carry0, 1));	\
	carry0 = _mm256_blend_epi32(carry0, _mm256_setzero_si256(), 1);	\
									\

}


#define GOST3411_2012_AVX256_XSLP(__dymm0, __dymm1, __aymm0, __aymm1,	\
    __bymm0, __bymm1) {							\
	__m256i symm0, symm1;						\
									\
	GOST3411_2012_AVX256_XOR2_512(symm0, symm1,			\
	    __aymm0, __aymm1,						\
	    __bymm0, __bymm1);						\
	GOST3411_2012_AVX256_SLP(__dymm0, __dymm1, symm0, symm1);	\
}

#define GOST3411_2012_AVX256_LXSLP(__dymm0, __dymm1, __aymm0, __aymm1, __ptr) { \
	__m256i symm0, symm1;						\
									\
	GOST3411_2012_AVX256_LOAD(__ptr, symm0, symm1);			\
	GOST3411_2012_AVX256_XOR2_512(symm0, symm1,			\
	    symm0, symm1,						\
	    __aymm0, __aymm1);						\
	GOST3411_2012_AVX256_SLP(__dymm0, __dymm1, symm0, symm1);	\
}

static inline void
gost3411_2012_transform(gost3411_2012_ctx_p ctx, const uint64_t *block) {
	register size_t i;
	__m256i *phash = (__m256i*)(void*)ctx->hash;
	const __m256i *pcounter = (const __m256i*)(const void*)ctx->counter;
	const __m256i *pblock = (const __m256i*)(const void*)block;
	__m256i hymm0, hymm1; /* HASH. */
	__m256i kymm0, kymm1; /* Key. */
	__m256i tymm0, tymm1; /* Temp. */


#if 0
	__m256i maskymm, offsets;

	hymm0 = _mm256_set_epi64x(0x7473727164636261, 0x5453525144434241, 0x3433323124232221, 0x1413121104030201);
	/* |a0a1a2a3b0b1b2b3|c0c1c2c3d0d1d2d3|e0e1e2e3f0f1f2f3|g0g1g2g3h0h1h2h3| */ \
	/* |a0b0c0d0e0f0g0h0|a1b1c1d1e1f1g1h1|a2b2c2d2e2f2g2h2|a3b3c3d3e3f3g3h3| */ \
	maskymm = _mm256_set_epi8(					\
		/*h3*/15, /*g3*/11, /*f3*/ 7, /*e3*/ 3, /*|*/ /*h1*/13, /*g1*/ 9, /*f1*/ 5, /*e1*/ 1,	\
		/*h2*/14, /*g2*/10, /*f2*/ 6, /*e2*/ 2, /*|*/ /*h0*/12, /*g0*/ 8, /*f0*/ 4, /*e0*/ 0,	\
		/*---------------------------------------------------*/	\
		/*d3*/15, /*c3*/11, /*b3*/ 7, /*a3*/ 3, /*|*/ /*d1*/13, /*c1*/ 9, /*b1*/ 5, /*a1*/ 1,	\
		/*d2*/14, /*c2*/10, /*b2*/ 6, /*a2*/ 2,	/*|*/ /*d0*/12, /*c0*/ 8, /*b0*/ 4, /*a0*/ 0);	\
	offsets = _mm256_setr_epi32(0, 4, 2, 6, 1, 5, 3, 7);		\
	tymm0 = _mm256_permutevar8x32_epi32(_mm256_shuffle_epi8(hymm0, maskymm), offsets);		\
	maskymm = _mm256_set_epi64x(0xff, 0xff, 0xff, 0xff);		\

	kymm1 = _mm256_and_si256(maskymm, _mm256_srli_epi64(tymm0, 8*7));

	__m128i s1;

	s1 = _mm_set_epi64x(0xdddddddddddddddd, 0xbbbbbbbb07060504);


	tymm0 = _mm256_set_epi64x(0xffffffffffffffff, 0xeeeeeeeeeeeeeeee, 0xdddddddddddddddd, 0xbbbbbbbb03020100);

	s1 = _mm256_extracti128_si256(tymm0, 0);
	tymm1 = _mm256_cvtepu8_epi64(s1);
	//hymm1 = GOST3411_2012_AVX256_GATHER(0, s1);



	int off = 0;

	kymm1 = _mm256_cvtepu8_epi64(_mm256_extracti128_si256(_mm256_srli_si256(tymm0, 0), 0));


	hymm0 = _mm256_set_epi8(
		-1, -1, -1, -1, -1, -1, -1, 3,
		-1, -1, -1, -1, -1, -1, -1, 2,
		-1, -1, -1, -1, -1, -1, -1, 1,
		-1, -1, -1, -1, -1, -1, -1, 0);
	hymm1 = _mm256_shuffle_epi8(tymm0, hymm0);
	kymm0 = _mm256_i64gather_epi64(
	    (long long int const*)gost3411_2012_Ax[0],
	    hymm1,
	    sizeof(uint64_t));
#endif



	GOST3411_2012_AVX256_LOAD(phash, hymm0, hymm1);
	if (0 == (((size_t)block) & 31)) { /* 32 byte alligned. */
#ifdef __AVX2__
		GOST3411_2012_AVX256_STREAM_LOAD(pblock, tymm0, tymm1);
#else
		GOST3411_2012_AVX256_LOAD(pblock, tymm0, tymm1);
#endif
	} else { /* Unaligned. */
		GOST3411_2012_AVX256_LOADU(pblock, tymm0, tymm1);
	}
	GOST3411_2012_AVX256_LXSLP(kymm0, kymm1,
	    hymm0, hymm1,
	    pcounter); /* HASH design deffect here. */
	GOST3411_2012_AVX256_XOR2_512(hymm0, hymm1,
	    hymm0, hymm1,
	    tymm0, tymm1); /* Pre Final XOR: hash ^= block. */
	/* E(). */
#pragma unroll
	for (i = 0; i < GOST3411_2012_ROUNDS_COUNT; i ++) {
		GOST3411_2012_AVX256_XSLP(tymm0, tymm1,
		    tymm0, tymm1,
		    kymm0, kymm1);
		/* KeySchedule: next K. */
		GOST3411_2012_AVX256_LXSLP(kymm0, kymm1,
		    kymm0, kymm1,
		    (const __m256i*)(const void*)gost3411_2012_C[i]);
	}
	/* Final XOR: hash ^= key ^ temp. */
	GOST3411_2012_AVX256_XOR2_512(hymm0, hymm1,
	    hymm0, hymm1,
	    tymm0, tymm1);
	GOST3411_2012_AVX256_XOR2_512(hymm0, hymm1,
	    hymm0, hymm1,
	    kymm0, kymm1);
	GOST3411_2012_AVX256_STORE(phash, hymm0, hymm1);
	/* Restore the Floating-point status on the CPU. */
	//_mm256_zeroall();
}
#endif



/*
 *  gost3411_2012_update
 *
 *  Description:
 *      This function accepts an array of octets as the next portion
 *      of the message.
 *
 *  Parameters:
 *      ctx: [in/out]
 *          The GOST3411_2012 ctx to update
 *      message_array: [in]
 *          An array of characters representing the next portion of
 *          the message.
 *      length: [in]
 *          The length of the message in message_array
 */
static inline void
gost3411_2012_update(gost3411_2012_ctx_p ctx, const uint8_t *data, size_t data_size) {
	size_t i, part_size;

	if (0 == data_size)
		return;
	//prefetch(gost3411_2012_Ax, sizeof(gost3411_2012_Ax));
	part_size = (GOST3411_2012_MSG_BLK_SIZE - ctx->buffer_usage);
	/* Transform as many times as possible. */
	if (data_size >= part_size) {
		if (0 != ctx->buffer_usage) { /* Add data to buffer and process it. */
			memcpy((((uint8_t*)ctx->buffer) + ctx->buffer_usage), data, part_size);
			gost3411_2012_transform(ctx, ctx->buffer);
			gost3411_2012_addmod512_digit(ctx->counter, GOST3411_2012_MSG_BLK_BITS); /* Update counter. */
			gost3411_2012_addmod512(ctx->sigma, ctx->buffer);
		} else { /* Proccess all data in loop. */
			part_size = 0;
		}

		/* Work with aligned buf. */
		if (0 == (((size_t)data + part_size) & 7)) { /* 8 byte alligned. */
			for (i = part_size; (i + GOST3411_2012_MSG_BLK_SIZE_MASK) < data_size;
			    i += GOST3411_2012_MSG_BLK_SIZE) {
				gost3411_2012_transform(ctx, (const void*)(data + i)); /* Skeep alignment warning here. */
				gost3411_2012_addmod512_digit(ctx->counter, GOST3411_2012_MSG_BLK_BITS); /* Update counter. */
				gost3411_2012_addmod512(ctx->sigma, (const void*)(data + i)); /* Skeep alignment warning here. */
			}
		} else { /* Unaligned. */
			for (i = part_size; (i + GOST3411_2012_MSG_BLK_SIZE_MASK) < data_size;
			    i += GOST3411_2012_MSG_BLK_SIZE) {
				memcpy(ctx->buffer, (data + i), GOST3411_2012_MSG_BLK_SIZE);
				gost3411_2012_transform(ctx, ctx->buffer);
				gost3411_2012_addmod512_digit(ctx->counter, GOST3411_2012_MSG_BLK_BITS); /* Update counter. */
				gost3411_2012_addmod512(ctx->sigma, ctx->buffer);
			}
		}
		data_size -= i;
		ctx->buffer_usage = 0;
	} else {
		i = 0;
	}
	/* Buffer remaining data. */
	memcpy((((uint8_t*)ctx->buffer) + ctx->buffer_usage), (data + i), data_size);
	ctx->buffer_usage += data_size;
}

/*
 *  gost3411_2012_final
 *
 *  Description:
 *      According to the standard, the message must be padded to an even
 *      512 bits.  The first padding bit must be a '1'.  All bits in
 *      between should be 0.  This function will pad the message
 *      according to those rules by filling the buffer array
 *      accordingly.  When it returns, it can be assumed that
 *      the message digest has been computed.
 *      This function will return the message digest into the
 *      digest array  provided by the caller.
 *
 *  Parameters:
 *      ctx: [in/out]
 *          The ctx to use to calculate the GOST3411_2012 hash.
 *      digest: [out]
 *          Where the digest is returned.
 */
static inline void
gost3411_2012_final(gost3411_2012_ctx_p ctx, uint8_t *digest) {
	size_t padding;

	/* Padd and process last block. */
	padding = (GOST3411_2012_MSG_BLK_SIZE - ctx->buffer_usage);
	if (padding) { /* Padding... */
		memset((((uint8_t*)ctx->buffer) + ctx->buffer_usage), 0x00, padding);
		(*(((uint8_t*)ctx->buffer) + ctx->buffer_usage)) = 0x01;
	}
	/* Processing. */
	gost3411_2012_transform(ctx, ctx->buffer);
	gost3411_2012_addmod512_digit(ctx->counter, (ctx->buffer_usage * 8)); /* Update counter. */
	gost3411_2012_addmod512(ctx->sigma, ctx->buffer);

	/* Finalize. */
	GOST3411_2012_XOR2_512(ctx->hash, ctx->hash, ctx->counter); /* XOR out counter from hash, for emulate g_0. */
	gost3411_2012_transform(ctx, ctx->counter);
	gost3411_2012_transform(ctx, ctx->sigma);
	GOST3411_2012_XOR2_512(ctx->hash, ctx->hash, ctx->counter); /* XOR in counter from hash, end g_0 emulation. */
	/* Store state in digest. */
	memcpy(digest, (((uint8_t*)ctx->hash) + GOST3411_2012_HASH_MAX_SIZE - ctx->hash_size),
	    ctx->hash_size);
	/* Zeroize sensitive information. */
	gost3411_2012_bzero(ctx, sizeof(gost3411_2012_ctx_t));
}


/* RFC 2104 */
/*
 * the HMAC_GOST3411_2012 transform looks like:
 *
 * GOST3411_2012(K XOR opad, GOST3411_2012(K XOR ipad, data))
 *
 * where K is an n byte 'key'
 * ipad is the byte 0x36 repeated 64 times
 * opad is the byte 0x5c repeated 64 times
 * and 'data' is the data being protected
 */
/*
 * data - pointer to data stream
 * data_size - length of data stream
 * key - pointer to authentication key
 * key_len - length of authentication key
 * digest - caller digest to be filled in
 */
static inline void
hmac_gost3411_2012_init(size_t bits, const uint8_t *key, size_t key_len,
    hmac_gost3411_2012_ctx_p hctx) {
	register size_t i;
	uint64_t k_ipad[GOST3411_2012_MSG_BLK_64CNT]; /* inner padding - key XORd with ipad. */

	/* Start out by storing key in pads. */
	/* If key is longer than block_size bytes reset it to key = GOST3411_2012(key). */
	gost3411_2012_init(bits, &hctx->ctx); /* Init context for 1st pass / Get hash params. */
	if (GOST3411_2012_MSG_BLK_SIZE < key_len) {
		gost3411_2012_update(&hctx->ctx, key, key_len);
		key_len = hctx->ctx.hash_size;
		gost3411_2012_final(&hctx->ctx, (uint8_t*)k_ipad);
		gost3411_2012_init(bits, &hctx->ctx); /* Reinit context for 1st pass. */
	} else {
		memcpy(k_ipad, key, key_len);
	}
	memset((((uint8_t*)k_ipad) + key_len), 0x00, (GOST3411_2012_MSG_BLK_SIZE - key_len));
	memcpy(hctx->k_opad, k_ipad, sizeof(k_ipad));

	/* XOR key with ipad and opad values. */
#pragma unroll
	for (i = 0; i < GOST3411_2012_MSG_BLK_64CNT; i ++) {
		k_ipad[i] ^= 0x3636363636363636ull;
		hctx->k_opad[i] ^= 0x5c5c5c5c5c5c5c5cull;
	}
	/* Perform inner GOST3411_2012. */
	gost3411_2012_update(&hctx->ctx, (uint8_t*)k_ipad, sizeof(k_ipad)); /* Start with inner pad. */
	/* Zeroize sensitive information. */
	gost3411_2012_bzero(k_ipad, sizeof(k_ipad));
}

static inline void
hmac_gost3411_2012_update(hmac_gost3411_2012_ctx_p hctx,
    const uint8_t *data, size_t data_size) {

	gost3411_2012_update(&hctx->ctx, data, data_size); /* Then data of datagram. */
}

static inline void
hmac_gost3411_2012_final(hmac_gost3411_2012_ctx_p hctx,
    uint8_t *digest, size_t *digest_size) {
	size_t bits;

	bits = hctx->ctx.hash_size;
	gost3411_2012_final(&hctx->ctx, digest); /* Finish up 1st pass. */
	/* Perform outer GOST3411_2012. */
	gost3411_2012_init(bits, &hctx->ctx); /* Init context for 2nd pass. */
	gost3411_2012_update(&hctx->ctx, (uint8_t*)hctx->k_opad, GOST3411_2012_MSG_BLK_SIZE); /* Start with outer pad. */
	gost3411_2012_update(&hctx->ctx, digest, hctx->ctx.hash_size); /* Then results of 1st hash. */
	if (NULL != digest_size) {
		(*digest_size) = hctx->ctx.hash_size;
	}
	gost3411_2012_final(&hctx->ctx, digest); /* Finish up 2nd pass. */
	/* Zeroize sensitive information. */
	gost3411_2012_bzero(hctx->k_opad, GOST3411_2012_MSG_BLK_SIZE);
}

static inline void
hmac_gost3411_2012(size_t bits, const uint8_t *key, size_t key_len,
    const uint8_t *data, size_t data_size,
    uint8_t *digest, size_t *digest_size) {
	hmac_gost3411_2012_ctx_t hctx;

	hmac_gost3411_2012_init(bits, key, key_len, &hctx);
	hmac_gost3411_2012_update(&hctx, data, data_size);
	hmac_gost3411_2012_final(&hctx, digest, digest_size);
}


static inline void
gost3411_2012_cvt_hex(const uint8_t *bin, size_t bin_size, uint8_t *hex) {
	static const uint8_t *hex_tbl = (const uint8_t*)"0123456789abcdef";
	register const uint8_t *bin_max;
	register uint8_t byte;

	for (bin_max = (bin + bin_size); bin < bin_max; bin ++) {
		byte = (*bin);
		(*hex ++) = hex_tbl[((byte >> 4) & 0x0f)];
		(*hex ++) = hex_tbl[(byte & 0x0f)];
	}
	(*hex) = 0;
}


/* Other staff. */
static inline void
gost3411_2012_cvt_strA(const uint8_t *digest, size_t digest_size,
    char *digest_str) {

	gost3411_2012_cvt_hex(digest, digest_size, (uint8_t*)digest_str);
}

#ifdef _WINDOWS
static inline void
gost3411_2012_cvt_strW(const uint8_t *digest, size_t digest_size,
    LPWSTR digest_str) {
	register size_t i, j;

	for (i = 0, j = 0; i < digest_size; i ++, j += 2) {
		wsprintfW((LPWSTR)(digest_str + j), L"%02x", digest[i]);
	}
	digest_str[j] = 0;
}
#endif


static inline void
gost3411_2012_get_digest(size_t bits, const void *data, size_t data_size,
    uint8_t *digest, size_t *digest_size) {
	gost3411_2012_ctx_t ctx;

	gost3411_2012_init(bits, &ctx);
	gost3411_2012_update(&ctx, data, data_size);
	if (NULL != digest_size) {
		(*digest_size) = ctx.hash_size;
	}
	gost3411_2012_final(&ctx, digest);
}

static inline void
gost3411_2012_get_digest_strA(size_t bits, const char *data, size_t data_size,
    char *digest_str, size_t *digest_str_size) {
	gost3411_2012_ctx_t ctx;
	size_t digest_size;
	uint8_t digest[GOST3411_2012_HASH_MAX_SIZE];

	gost3411_2012_init(bits, &ctx);
	gost3411_2012_update(&ctx, (const uint8_t*)data, data_size);
	digest_size = ctx.hash_size;
	gost3411_2012_final(&ctx, digest);

	gost3411_2012_cvt_strA(digest, digest_size, digest_str);
	if (NULL != digest_str_size) {
		(*digest_str_size) = (digest_size * 2);
	}
}

#ifdef _WINDOWS
static inline void
gost3411_2012_get_digest_strW(size_t bits, const LPWSTR data, size_t data_size,
    LPWSTR digest_str, size_t *digest_str_size) {
	gost3411_2012_ctx_t ctx;
	size_t digest_size;
	uint8_t digest[GOST3411_2012_HASH_MAX_SIZE];

	gost3411_2012_init(bits, &ctx);
	gost3411_2012_update(&ctx, (uint8_t*)data, data_size);
	digest_size = ctx.hash_size;
	gost3411_2012_final(&ctx, digest);

	gost3411_2012_cvt_strW(digest, digest_size, digest_str);
	if (NULL != digest_str_size) {
		(*digest_str_size) = (digest_size * 2);
	}
}
#endif


static inline void
gost3411_2012_hmac_get_digest(size_t bits, const void *key, size_t key_size,
    const void *data, size_t data_size, uint8_t *digest, size_t *digest_size) {

	hmac_gost3411_2012(bits, (const uint8_t*)key, key_size,
	    (const uint8_t*)data, data_size, digest, digest_size);
}

static inline void
gost3411_2012_hmac_get_digest_strA(size_t bits, const char *key, size_t key_size,
    const char *data, size_t data_size, char *digest_str, size_t *digest_str_size) {
	size_t digest_size;
	uint8_t digest[GOST3411_2012_HASH_MAX_SIZE];

	hmac_gost3411_2012(bits, (const uint8_t*)key, key_size,
	    (const uint8_t*)data, data_size, digest, &digest_size);
	gost3411_2012_cvt_strA(digest, digest_size, digest_str);
	if (NULL != digest_str_size) {
		(*digest_str_size) = (digest_size * 2);
	}
}

#ifdef _WINDOWS
static inline void
gost3411_2012_hmac_get_digest_strW(size_t bits, const LPWSTR key, size_t key_size,
    const LPWSTR data, size_t data_size, LPWSTR digest_str, size_t *digest_str_size) {
	size_t digest_size;
	uint8_t digest[GOST3411_2012_HASH_MAX_SIZE];

	hmac_gost3411_2012(bits, (const uint8_t*)key, key_size,
	    (const uint8_t*)data, data_size, digest, &digest_size);
	gost3411_2012_cvt_strW(digest, digest_size, digest_str);
	if (NULL != digest_str_size) {
		(*digest_str_size) = (digest_size * 2);
	}
}
#endif



#ifdef GOST3411_2012_SELF_TEST

typedef struct gost3411_2012_hash_test_vectors_s {
	const char 	*msg;
	size_t		msg_size;
	const char 	*hash256;
	const char 	*hash512;
} gost3411_2012_htv_t, *gost3411_2012_htv_p;

/* M2: "Се ветри, Стрибожи внуци, веютъ с моря стрелами на храбрыя плъкы Игоревы" */
static uint8_t gost3411_2012_hash_m2[] = {
	0xd1, 0xe5, 0x20, 0xe2, 0xe5, 0xf2, 0xf0, 0xe8,
	0x2c, 0x20, 0xd1, 0xf2, 0xf0, 0xe8, 0xe1, 0xee,
	0xe6, 0xe8, 0x20, 0xe2, 0xed, 0xf3, 0xf6, 0xe8,
	0x2c, 0x20, 0xe2, 0xe5, 0xfe, 0xf2, 0xfa, 0x20,
	0xf1, 0x20, 0xec, 0xee, 0xf0, 0xff, 0x20, 0xf1,
	0xf2, 0xf0, 0xe5, 0xeb, 0xe0, 0xec, 0xe8, 0x20,
	0xed, 0xe0, 0x20, 0xf5, 0xf0, 0xe0, 0xe1, 0xf0,
	0xfb, 0xff, 0x20, 0xef, 0xeb, 0xfa, 0xea, 0xfb,
	0x20, 0xc8, 0xe3, 0xee, 0xf0, 0xe5, 0xe2, 0xfb
};
/* https://github.com/mjosaarinen/stricat/blob/master/selftest.c m4 */
static uint8_t gost3411_2012_hash_m4[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static gost3411_2012_htv_t gost3411_2012_hash_tst[] = {
	{ /* 0: https://en.wikipedia.org/wiki/Streebog / https://www.streebog.net/src/trunk/examples/ 3 / http://www.stribob.com/dist/stricat/selftest.c m3*/
		/*.msg =*/	"",
		/*.msg_size =*/	0,
		/*.hash256 =*/	"3f539a213e97c802cc229d474c6aa32a825a360b2a933a949fd925208d9ce1bb",
		/*.hash512 =*/	"8e945da209aa869f0455928529bcae4679e9873ab707b55315f56ceb98bef0a7362f715528356ee83cda5f2aac4c6ad2ba3a715c1bcd81cb8e9f90bf4c1c1a8a",
	}, { /* 1: https://tools.ietf.org/html/rfc6986 M1 / https://www.streebog.net/src/trunk/examples/ 1 */
		/*.msg =*/	"012345678901234567890123456789012345678901234567890123456789012",
		/*.msg_size =*/	63,
		/*.hash256 =*/	"9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500",
		/*.hash512 =*/	"1b54d01a4af5b9d5cc3d86d68d285462b19abc2475222f35c085122be4ba1ffa00ad30f8767b3a82384c6574f024c311e2a481332b08ef7f41797891c1646f48",
	}, { /* 2:  https://tools.ietf.org/html/rfc6986 M2 / http://www.stribob.com/dist/stricat/selftest.c */
		/*.msg =*/	(const char*)gost3411_2012_hash_m2,
		/*.msg_size =*/	sizeof(gost3411_2012_hash_m2),
		/*.hash256 =*/	"9dd2fe4e90409e5da87f53976d7405b0c0cac628fc669a741d50063c557e8f50",
		/*.hash512 =*/	"1e88e62226bfca6f9994f1f2d51569e0daf8475a3b0fe61a5300eee46d961376035fe83549ada2b8620fcd7c496ce5b33f0cb9dddc2b6460143b03dabac9fb28",
	}, { /* 3: http://www.stribob.com/dist/stricat/selftest.c m4 */
		/*.msg =*/	(const char*)gost3411_2012_hash_m4,
		/*.msg_size =*/	sizeof(gost3411_2012_hash_m4),
		/*.hash256 =*/	"df1fda9ce83191390537358031db2ecaa6aa54cd0eda241dc107105e13636b95",
		/*.hash512 =*/	"b0fd29ac1b0df441769ff3fdb8dc564df67721d6ac06fb28ceffb7bbaa7948c6c014ac999235b58cb26fb60fb112a145d7b4ade9ae566bf2611402c552d20db7",
	}, { /* 4: https://en.wikipedia.org/wiki/Streebog */
		/*.msg =*/	"The quick brown fox jumps over the lazy dog",
		/*.msg_size =*/	43,
		/*.hash256 =*/	"3e7dea7f2384b6c5a3d0e24aaa29c05e89ddd762145030ec22c71a6db8b2c1f4",
		/*.hash512 =*/	NULL,
	}, { /* 5: https://en.wikipedia.org/wiki/Streebog */
		/*.msg =*/	"The quick brown fox jumps over the lazy dog.",
		/*.msg_size =*/	44,
		/*.hash256 =*/	"36816a824dcbe7d6171aa58500741f2ea2757ae2e1784ab72c5c3c6c198d71da",
		/*.hash512 =*/	NULL,
	}, { /* 6: http://git.cypherpunks.ru/cgit.cgi/pygost.git/tree/pygost/gost3411_12.py */
		/*.msg =*/	"foobar",
		/*.msg_size =*/	6,
		/*.hash256 =*/	"e3c9fd89226d93b489a9fe27d686806e24a514e3787bca053c698ec4616ceb78",
		/*.hash512 =*/	NULL,
	}, {
		/*.msg =*/	NULL,
		/*.msg_size =*/	0,
		/*.hash256 =*/	NULL,
		/*.hash512 =*/	NULL,
	}
};

#define GOST3411_2012_TEST_IDX 2


typedef struct gost3411_2012_hmac_test_vectors_s {
	const char 	*key;
	size_t		key_size;
	const char 	*msg;
	size_t		msg_size;
	const char 	*hmac256;
	const char 	*hmac512;
} gost3411_2012_hmtv_t, *gost3411_2012_hmtv_p;

/* http://www.tc26.ru/methods/recommendation/%D0%A2%D0%9A26%D0%90%D0%9B%D0%93.pdf */
/* https://tools.ietf.org/html/draft-smyshlyaev-gost-usage-00 */
/* https://datatracker.ietf.org/doc/rfc7836/?include_text=1 */
static uint8_t gost3411_2012_hmac_k1[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};
static uint8_t gost3411_2012_hmac_m1[] = {
	0x01, 0x26, 0xbd, 0xb8, 0x78, 0x00, 0xaf, 0x21,
	0x43, 0x41, 0x45, 0x65, 0x63, 0x78, 0x01, 0x00
};

static gost3411_2012_hmtv_t gost3411_2012_hmac_tst[] = {
	{ /* 0: https://tools.ietf.org/html/draft-smyshlyaev-gost-usage-00 */
		/*.key =*/	(const char*)gost3411_2012_hmac_k1,
		/*.key_size =*/	sizeof(gost3411_2012_hmac_k1),
		/*.msg =*/	(const char*)gost3411_2012_hmac_m1,
		/*.msg_size =*/	sizeof(gost3411_2012_hmac_m1),
		/*.hmac256 =*/	"a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9",
		/*.hmac512 =*/	"a59bab22ecae19c65fbde6e5f4e9f5d8549d31f037f9df9b905500e171923a773d5f1530f2ed7e964cb2eedc29e9ad2f3afe93b2814f79f5000ffc0366c251e6",
	}, {
		/*.key =*/	NULL,
		/*.key_size =*/	0,
		/*.msg =*/	NULL,
		/*.msg_size =*/	0,
		/*.hmac256 =*/	NULL,
		/*.hmac512 =*/	NULL,
	}
};


/* 0 - OK, non zero - error */
static inline int
gost3411_2012_self_test() {
	size_t i, j, k, tm;
	gost3411_2012_ctx_t ctx;
	uint8_t digest[GOST3411_2012_HASH_MAX_SIZE];
	char digest_str[(GOST3411_2012_HASH_STR_MAX_SIZE + 1)];

	/* Test 1 - HASH. */
	for (i = 0; NULL != gost3411_2012_hash_tst[i].msg; i ++) {
		if (NULL != gost3411_2012_hash_tst[i].hash256) {
			gost3411_2012_get_digest_strA(256,
			    gost3411_2012_hash_tst[i].msg,
			    gost3411_2012_hash_tst[i].msg_size,
			    digest_str, &tm);
			if (0 != memcmp(digest_str, gost3411_2012_hash_tst[i].hash256, tm)) {
				gost3411_2012_print("Test1: %zu - 256: FAIL!\nvec = %s\nres = %s\n",
				    i, gost3411_2012_hash_tst[i].hash256, digest_str);
				return (1);
			} else {
				gost3411_2012_print("Test1: %zu - 256: OK\n", i);
			}
		}
		if (NULL != gost3411_2012_hash_tst[i].hash512) {
			gost3411_2012_get_digest_strA(512,
			    gost3411_2012_hash_tst[i].msg,
			    gost3411_2012_hash_tst[i].msg_size,
			    digest_str, &tm);
			if (0 != memcmp(digest_str, gost3411_2012_hash_tst[i].hash512, tm)) {
				gost3411_2012_print("Test1: %zu - 512: FAIL!\nvec = %s\nres = %s\n",
				    i, gost3411_2012_hash_tst[i].hash512, digest_str);
				return (1);
			} else {
				gost3411_2012_print("Test1: %zu - 512: OK\n", i);
			}
		}
	}

	/* Test 2 - HASH by parts. */
	for (k = 0; NULL != gost3411_2012_hash_tst[k].msg; k ++) {
		for (j = 1; j < gost3411_2012_hash_tst[k].msg_size; j ++) {
			if (NULL != gost3411_2012_hash_tst[k].hash256) {
				gost3411_2012_init(256, &ctx);
				for (i = 0; i < gost3411_2012_hash_tst[k].msg_size; i += j) {
					tm = (gost3411_2012_hash_tst[k].msg_size - i);
					gost3411_2012_update(&ctx,
					    (const uint8_t*)(gost3411_2012_hash_tst[k].msg + i),
					    ((j < tm) ? j : tm));
				}
				tm = ctx.hash_size;
				gost3411_2012_final(&ctx, digest);
				gost3411_2012_cvt_strA(digest, tm, digest_str);
				if (0 != memcmp(digest_str, gost3411_2012_hash_tst[k].hash256, tm)) {
					gost3411_2012_print("Test2: %zu/%zu - 256: FAIL!\nvec = %s\nres = %s\n",
					    k, j, gost3411_2012_hash_tst[k].hash256, digest_str);
					return (2);
				}
			}
			if (NULL != gost3411_2012_hash_tst[k].hash512) {
				gost3411_2012_init(512, &ctx);
				for (i = 0; i < gost3411_2012_hash_tst[k].msg_size; i += j) {
					tm = (gost3411_2012_hash_tst[k].msg_size - i);
					gost3411_2012_update(&ctx,
					    (const uint8_t*)(gost3411_2012_hash_tst[k].msg + i),
					    ((j < tm) ? j : tm));
				}
				tm = ctx.hash_size;
				gost3411_2012_final(&ctx, digest);
				gost3411_2012_cvt_strA(digest, tm, digest_str);
				if (0 != memcmp(digest_str, gost3411_2012_hash_tst[k].hash512, tm)) {
					gost3411_2012_print("Test2: %zu/%zu - 512: FAIL!\nvec = %s\nres = %s\n",
					    k, j, gost3411_2012_hash_tst[k].hash512, digest_str);
					return (2);
				}
			}
		}
	}

	/* Test 3 - HMAC. */
	for (i = 0; NULL != gost3411_2012_hmac_tst[i].msg; i ++) {
		if (NULL != gost3411_2012_hmac_tst[i].hmac256) {
			gost3411_2012_hmac_get_digest_strA(256,
			    gost3411_2012_hmac_tst[i].key,
			    gost3411_2012_hmac_tst[i].key_size,
			    gost3411_2012_hmac_tst[i].msg,
			    gost3411_2012_hmac_tst[i].msg_size,
			    digest_str, &tm);
			if (0 != memcmp(digest_str, gost3411_2012_hmac_tst[i].hmac256, tm)) {
				gost3411_2012_print("Test3: %zu - 256: FAIL!\nvec = %s\nres = %s\n",
				    i, gost3411_2012_hmac_tst[i].hmac256, digest_str);
				return (3);
			} else {
				gost3411_2012_print("Test3: %zu - 256: OK\n", i);
			}
		}
		if (NULL != gost3411_2012_hmac_tst[i].hmac512) {
			gost3411_2012_hmac_get_digest_strA(512,
			    gost3411_2012_hmac_tst[i].key,
			    gost3411_2012_hmac_tst[i].key_size,
			    gost3411_2012_hmac_tst[i].msg,
			    gost3411_2012_hmac_tst[i].msg_size,
			    digest_str, &tm);
			if (0 != memcmp(digest_str, gost3411_2012_hmac_tst[i].hmac512, tm)) {
				gost3411_2012_print("Test3: %zu - 512: FAIL!\nvec = %s\nres = %s\n",
				    i, gost3411_2012_hmac_tst[i].hmac512, digest_str);
				return (3);
			} else {
				gost3411_2012_print("Test3: %zu - 512: OK\n", i);
			}
		}
	}

	return (0);
}
#endif


#endif // __GOST3411_2012_H__INCLUDED__
