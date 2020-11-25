//
// Created by Haifa Bogdan Adnan on 15/02/2019.
//

#include "linux84_api.h"

linux84_api::linux84_api(arguments & args, linux84 &linux84) : __args(args), __linux84(linux84) {
    if(__args.enable_api_port() > 0) {
        vector<string> options;
        options.push_back("listening_ports");
        options.push_back(to_string(__args.enable_api_port()));
        __server = new CivetServer(options);
        __server->addHandler("/status", *this);
    }
    else {
        __server = NULL;
    }
}

linux84_api::~linux84_api() {
    if(__server != NULL) {
        delete __server;
    }
}

bool linux84_api::handleGet(CivetServer *server, struct mg_connection *conn) {
    mg_printf(conn,
              "HTTP/1.1 200 OK\r\nContent-Type: "
              "application/json\r\nConnection: close\r\n\r\n");

    string status = __linux84.get_status();
    mg_printf(conn, status.c_str());

    return true;
}
