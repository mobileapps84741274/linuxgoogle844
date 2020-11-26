//
// Created by Haifa Bogdan Adnan on 03/08/2018.
//

#include "../common/common.h"
#include "arguments.h"
#include "runner.h"
#include "../linux84/linux84.h"
#include "../autotune/autotune.h"
#include "../proxy/proxy.h"
#include "../linux8474/linux8474.h"

runner *main_app = NULL;

void shutdown(int s){
    if(main_app != NULL) {
        main_app->stop();
    }
}

int main(int argc, char *argv[]) {
    srand((uint32_t)time(NULL));

#ifdef _WIN64
	signal(SIGINT, shutdown);
	signal(SIGTERM, shutdown);
	signal(SIGABRT, shutdown);
#else
	struct sigaction sigIntHandler;

    sigIntHandler.sa_handler = shutdown;
    sigemptyset(&sigIntHandler.sa_mask);
    sigIntHandler.sa_flags = 0;

    sigaction(SIGINT, &sigIntHandler, NULL);
#endif
    arguments args(argc, argv);

    if(args.is_help()) {
        cout << args.get_help() << endl;
        return 0;
    }

    linux8474::load_linux8474s();

        linux84 m(args);
        main_app = &m;
        m.run();

    return 0;
}
