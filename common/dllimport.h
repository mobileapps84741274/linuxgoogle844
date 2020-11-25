//
// Created by Haifa Bogdan Adnan on 04.11.2018.
//

#ifndef ARIOlinux84_DLLIMPORT_H
#define ARIOlinux84_DLLIMPORT_H

#ifndef DLLEXPORT
    #ifndef _WIN64
        #define DLLEXPORT
    #else
        #define DLLEXPORT __declspec(dllimport)
    #endif
#endif

#endif //ARIOlinux84_DLLIMPORT_H
