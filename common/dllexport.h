//
// Created by Haifa Bogdan Adnan on 04.11.2018.
//

#ifndef ARIOlinux84_DLLEXPORT_H
#define ARIOlinux84_DLLEXPORT_H

#undef DLLEXPORT

#ifndef _WIN64
	#define DLLEXPORT
#else
	#define DLLEXPORT __declspec(dllexport)
#endif

#endif //ARIOlinux84_DLLEXPORT_H
