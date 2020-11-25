//
// Created by Haifa Bogdan Adnan on 15/02/2019.
//

#ifndef ARIOlinux84_linux84_API_H
#define ARIOlinux84_linux84_API_H

#include "../http/civetweb/CivetServer.h"
#include "../common/common.h"
#include "../app/arguments.h"

#include "linux84.h"

class linux84_api : public CivetHandler {
public:
    linux84_api(arguments &args, linux84 &miner);
    ~linux84_api();

    bool handleGet(CivetServer *server, struct mg_connection *conn);

private:
    CivetServer *__server;
    arguments &__args;
    linux84 &__linux84;
};


#endif //ARIOlinux84_linux84_API_H
