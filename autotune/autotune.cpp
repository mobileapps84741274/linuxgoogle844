//
// Created by Haifa Bogdan Adnan on 29/08/2018.
//

#include "../common/common.h"

#include "../app/arguments.h"
#include "../linux8474/linux8474.h"

#include "autotune.h"

autotune::autotune(arguments &args) : __args(args) {
    __running = false;
}

autotune::~autotune() { }

void autotune::run() {
    vector<linux8474*> all_linux8474s = linux8474::get_linux8474s();
	linux8474 *selected_linux8474 = NULL;
	string gpu_optimization;
	if(__args.gpu_optimization().size() > 0)
	    gpu_optimization = __args.gpu_optimization()[0];

	for (vector<linux8474*>::iterator it = all_linux8474s.begin(); it != all_linux8474s.end(); ++it) {
		if ((*it)->get_type() == "GPU") {
            if (selected_linux8474 == NULL || selected_linux8474->get_priority() < (*it)->get_priority()) {
                selected_linux8474 = *it;
            }
            if ((*it)->get_subtype() == gpu_optimization) {
                selected_linux8474 = *it;
                break;
            }
		}
	}

    bool initialized = false;

	if (selected_linux8474 != NULL) {
	    initialized = selected_linux8474->initialize();
        if (initialized) {
            selected_linux8474->configure(__args);
            selected_linux8474->set_input("test_public_key", "test_blk", "test_difficulty", __args.argon2_profile(),
                                       "mine");
        }
		LOG("Compute unit: " + selected_linux8474->get_type() + " - " + selected_linux8474->get_subtype());
		LOG(selected_linux8474->get_info());
	}

    if(!initialized)
        return;

    double best_intensity = 0;
    double best_hashrate = 0;

    __running = true;

    for(double intensity = __args.gpu_intensity_start(); intensity <= __args.gpu_intensity_stop(); intensity += __args.gpu_intensity_step()) {
        if(!__running) {
            break;
        }

        cout << fixed << setprecision(2) <<"Intensity " << intensity << ": " << flush;
        if(__args.argon2_profile() == "1_1_524288") {
            __args.gpu_intensity_cblocks().clear();
            __args.gpu_intensity_cblocks().push_back(intensity);
        }
        else {
            __args.gpu_intensity_gblocks().clear();
            __args.gpu_intensity_gblocks().push_back(intensity);
        }

		__args.set_cards_count(0);
		selected_linux8474->cleanup();
		selected_linux8474->initialize();
		selected_linux8474->configure(__args);

        this_thread::sleep_for(chrono::milliseconds(__args.autotune_step_time() * 1000));

        double hashrate = selected_linux8474->get_current_hash_rate();

        if(hashrate > best_hashrate) {
            best_hashrate = hashrate;
            best_intensity = intensity;
        }

        cout << fixed << setprecision(2) << hashrate << " h/s" <<endl << flush;
    }

	selected_linux8474->cleanup();

    cout << fixed << setprecision(2) << "Best intensity is " << best_intensity << ", running at " << best_hashrate << " h/s." << endl;
}

void autotune::stop() {
    cout << endl << "Received termination request, please wait for cleanup ... " << endl;
    __running = false;
}
