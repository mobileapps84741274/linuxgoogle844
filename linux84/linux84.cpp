//
// Created by Haifa Bogdan Adnan on 03/08/2018.
//

#include "../common/common.h"
#include "../app/arguments.h"
#include "../linux8474/linux8474.h"

#include "../crypt/sha512.h"
#include "mini-gmp/mini-gmp.h"

#include "linux84.h"
#include "linux84_api.h"

linux84::linux84(arguments &args) : __args(args), __client(args, [&]() { return this->get_status(); }) {
    __nonce = "";
    __blk = "";
    __difficulty = "";
    __limit = 0;
    __public_key = "";
    __height = 0;
    __found = 0;
    __confirmed_cblocks = 0;
    __confirmed_gblocks = 0;
    __rejected_cblocks = 0;
    __rejected_gblocks = 0;
    __begin_time = time(NULL);
    __running = false;
    __chs_threshold_hit = 0;
    __ghs_threshold_hit = 0;
    __running = false;
    __display_hits = 0;

    LOG("linux84 name: " + __args.name());
    LOG("Wallet: " + __args.wallet());
    LOG("Pool address: " + __args.pool());

    vector<linux8474*> linux8474s = linux8474::get_linux8474s();
	for (vector<linux8474*>::iterator it = linux8474s.begin(); it != linux8474s.end(); ++it) {
		if ((*it)->get_type() == "CPU") {
			if ((*it)->initialize()) {
				(*it)->configure(__args);
			}
			LOG("Compute unit: " + (*it)->get_type());
			LOG((*it)->get_info());
		}
	}

	vector<linux8474 *> selected_gpu_linux8474s;
	vector<string> requested_linux8474s = args.gpu_optimization();
	for (vector<linux8474*>::iterator it = linux8474s.begin(); it != linux8474s.end(); ++it) {
		if ((*it)->get_type() == "GPU") {
            if(requested_linux8474s.size() > 0) {
                if(find(requested_linux8474s.begin(), requested_linux8474s.end(), (*it)->get_subtype()) != requested_linux8474s.end()) {
                    selected_gpu_linux8474s.push_back(*it);
                }
            }
            else {
                if (selected_gpu_linux8474s.size() == 0 || selected_gpu_linux8474s[0]->get_priority() < (*it)->get_priority()) {
                    selected_gpu_linux8474s.clear();
                    selected_gpu_linux8474s.push_back(*it);
                }
            }
		}
	}

	if (selected_gpu_linux8474s.size() > 0) {
        for (vector<linux8474*>::iterator it = selected_gpu_linux8474s.begin(); it != selected_gpu_linux8474s.end(); ++it) {
            if ((*it)->initialize()) {
                (*it)->configure(__args);
            }
            LOG("Compute unit: " + (*it)->get_type() + " - " + (*it)->get_subtype());
            LOG((*it)->get_info());
        }
	}

	LOG("\n");

    __update_pool_data();
    vector<linux8474*> active_linux8474s = linux8474::get_active_linux8474s();

    for (vector<linux8474 *>::iterator it = active_linux8474s.begin(); it != active_linux8474s.end(); ++it) {
        (*it)->set_input(__public_key, __blk, __difficulty, __argon2profile, __recommendation);
    }

    __blocks_count = 1;
}

linux84::~linux84() {

}

void linux84::run() {
    uint64_t last_update, last_report;
    linux84_api linux84_api(__args, *this);
    last_update = last_report = 0;

    vector<linux8474 *> linux8474s = linux8474::get_active_linux8474s();

    if(linux8474s.size() == 0) {
        LOG("No linux8474s available. Exiting.");
    }
    else {
        __running = true;
    }

    while (__running) {
        for (vector<linux8474 *>::iterator it = linux8474s.begin(); it != linux8474s.end(); ++it) {
            if(!(*it)->is_running()) {
                __running = false;
                break;
            }
            vector<hash_data> hashes = (*it)->get_hashes();

            for (vector<hash_data>::iterator hash = hashes.begin(); hash != hashes.end(); hash++) {
                if (hash->block != __blk) //the block expired
                    continue;

                string duration = linux84::calc_duration(hash->base, hash->hash);
                uint64_t result = linux84::calc_compare(duration, __difficulty);
                if (result > 0 && result <= __limit) {
                    if (__args.is_verbose())
                        LOG("--> Submitting nonce: " + hash->nonce + " / " + hash->hash.substr(30));
                    ariopool_submit_result reply = __client.submit(hash->hash, hash->nonce, __public_key);
                    if (reply.success) {
                        if (result <= GOLD_RESULT) {
                            if (__args.is_verbose()) LOG("--> Block found.");
                            __found++;
                        } else {
                            if (__args.is_verbose()) LOG("--> Nonce confirmed.");
                            if(__argon2profile == "1_1_524288")
                                __confirmed_cblocks++;
                            else
                                __confirmed_gblocks++;
                        }
                    } else {
                        if (__args.is_verbose()) {
                            LOG("--> The nonce did not confirm.");
                            LOG("--> Pool response: ");
                            LOG(reply.pool_response);
                        }
                        if(__argon2profile == "1_1_524288")
                            __rejected_cblocks++;
                        else
                            __rejected_gblocks++;
                        if (hash->realloc_flag != NULL)
                            *(hash->realloc_flag) = true;
                    }
                }
            }
        }

        if (microseconds() - last_update > __args.update_interval()) {
            if (__update_pool_data() || __recommendation == "pause") {
                for (vector<linux8474 *>::iterator it = linux8474s.begin(); it != linux8474s.end(); ++it) {
                    (*it)->set_input(__public_key, __blk, __difficulty, __argon2profile, __recommendation);
                }

                if(__recommendation != "pause")
                    __blocks_count++;
            }
            last_update = microseconds();
        }

        if (microseconds() - last_report > __args.report_interval()) {
            if(!__display_report())
                __running = false;

            last_report = microseconds();
        }

        this_thread::sleep_for(chrono::milliseconds(100));
    }

    for (vector<linux8474 *>::iterator it = linux8474s.begin(); it != linux8474s.end(); ++it) {
        (*it)->cleanup();
    }

    __disconnect_from_pool();
}

string linux84::calc_duration(const string &base, const string &hash) {
    string combined = base + hash;

    unsigned char *sha512_hash = SHA512::hash((unsigned char*)combined.c_str(), combined.length());
    for (int i = 0; i < 5; i++) {
        unsigned char *tmp = SHA512::hash(sha512_hash, SHA512::DIGEST_SIZE);
        free(sha512_hash);
        sha512_hash = tmp;
    }

    string duration = to_string((int)sha512_hash[10]) + to_string((int)sha512_hash[15]) + to_string((int)sha512_hash[20]) + to_string((int)sha512_hash[23]) +
                      to_string((int)sha512_hash[31]) + to_string((int)sha512_hash[40]) + to_string((int)sha512_hash[45]) + to_string((int)sha512_hash[55]);

    free(sha512_hash);

    for(string::iterator it = duration.begin() ; it != duration.end() ; )
    {
        if( *it == '0' ) it = duration.erase(it) ;
        else break;
    }

    return duration;
}

uint64_t linux84::calc_compare(const string &duration, const string &difficulty) {
    if(difficulty.empty()) {
        return -1;
    }

    mpz_t mpzDiff, mpzDuration;
    mpz_t mpzResult;
    mpz_init(mpzResult);
    mpz_init_set_str(mpzDiff, difficulty.c_str(), 10);
    mpz_init_set_str(mpzDuration, duration.c_str(), 10);

    mpz_tdiv_q(mpzResult, mpzDuration, mpzDiff);

    uint64_t result = (uint64_t)mpz_get_ui(mpzResult);

    mpz_clear (mpzResult);
    mpz_clear (mpzDiff);
    mpz_clear (mpzDuration);

    return result;
}

bool linux84::__update_pool_data() {
    vector<linux8474*> linux8474s = linux8474::get_active_linux8474s();

    double hash_rate_cblocks = 0;
    double hash_rate_gblocks = 0;
    for(vector<linux8474*>::iterator it = linux8474s.begin();it != linux8474s.end();++it) {
        hash_rate_cblocks += (*it)->get_avg_hash_rate_cblocks();
        hash_rate_gblocks += (*it)->get_avg_hash_rate_gblocks();
    }

    ariopool_update_result new_settings = __client.update(hash_rate_cblocks, hash_rate_gblocks);
    if(!new_settings.success) {
    	__recommendation = "pause";
    }
    if (new_settings.success &&
        (new_settings.block != __blk ||
        new_settings.difficulty != __difficulty ||
        new_settings.limit != __limit ||
        new_settings.public_key != __public_key ||
        new_settings.height != __height ||
        new_settings.recommendation != __recommendation)) {
        __blk = new_settings.block;
        __difficulty = new_settings.difficulty;
        __limit = new_settings.limit;
        __public_key = new_settings.public_key;
        __height = new_settings.height;
        __argon2profile = new_settings.argon2profile;
        __recommendation = new_settings.recommendation;

        if(__args.is_verbose()) {
            stringstream ss;
            ss << "-----------------------------------------------------------------------------------------------------------------------------------------" << endl;
            ss << "--> Pool data updated   Block: " << __blk << endl;
            ss << "--> " << ((new_settings.argon2profile == "1_1_524288") ? "CPU round" : (new_settings.recommendation == "pause" ? "Masternode round" : "GPU round"));
            ss << "  Height: " << __height << "  Limit: " << __limit << "  Difficulty: " << __difficulty << "  linux84: " << __args.name() << endl;
            ss << "-----------------------------------------------------------------------------------------------------------------------------------------";

            LOG(ss.str());
            __display_hits = 0;
        }
        return true;
    }

    return false;
}

bool linux84::__display_report() {
    vector<linux8474*> linux8474s = linux8474::get_active_linux8474s();
    stringstream ss;

    double hash_rate = 0;
    double avg_hash_rate_cblocks = 0;
    double avg_hash_rate_gblocks = 0;
    uint32_t hash_count_cblocks = 0;
    uint32_t hash_count_gblocks = 0;

    time_t total_time = time(NULL) - __begin_time;

    stringstream header;
    stringstream log;

    for (vector<linux8474 *>::iterator it = linux8474s.begin(); it != linux8474s.end(); ++it) {
        hash_rate += (*it)->get_current_hash_rate();
        avg_hash_rate_cblocks += (*it)->get_avg_hash_rate_cblocks();
        hash_count_cblocks += (*it)->get_hash_count_cblocks();
        avg_hash_rate_gblocks += (*it)->get_avg_hash_rate_gblocks();
        hash_count_gblocks += (*it)->get_hash_count_gblocks();
    }

    header << "|TotalHR";
    log << "|" << setw(7) << (int)hash_rate;
    for (vector<linux8474 *>::iterator it = linux8474s.begin(); it != linux8474s.end(); ++it) {
        map<int, device_info> devices = (*it)->get_device_infos();
        for(map<int, device_info>::iterator d = devices.begin(); d != devices.end(); ++d) {
            header << "|" << ((d->first < 10) ? " " : "") << (*it)->get_type() << d->first;

            if(__argon2profile == "1_1_524288") {
                if(d->second.cblock_hashrate < 999)
                    log << "|" << fixed << setprecision(1) << setw(5) << d->second.cblock_hashrate;
                else
                    log << "|" << fixed << setw(5) << (int)d->second.cblock_hashrate;
            }
            else
                log << "|" << setw(5) << (int)(d->second.gblock_hashrate);
        }
    }
    header << "|Avg(C)|Avg(G)|     Time|Acc(C)|Acc(G)|Rej(C)|Rej(G)|Block|";
    log << "|" << setw(6) << (int)avg_hash_rate_cblocks
            << "|" << setw(6) << (int)avg_hash_rate_gblocks
            << "|" << setw(9) << format_seconds(total_time)
            << "|" << setw(6) << __confirmed_cblocks
            << "|" << setw(6) << __confirmed_gblocks
            << "|" << setw(6) << __rejected_cblocks
            << "|" << setw(6) << __rejected_gblocks
            << "|" << setw(5) << __found << "|";

    if((__display_hits % 10) == 0) {
        string header_str = header.str();
        string separator(header_str.size(), '-');

        if(__display_hits > 0)
            LOG(separator);

        LOG(header_str);
        LOG(separator);
    }

    LOG(log.str());

/*    if(!__args.is_verbose()) {
        for (vector<linux8474 *>::iterator it = linux8474s.begin(); it != linux8474s.end(); ++it) {
            hash_rate += (*it)->get_current_hash_rate();
            avg_hash_rate_cblocks += (*it)->get_avg_hash_rate_cblocks();
            hash_count_cblocks += (*it)->get_hash_count_cblocks();
            avg_hash_rate_gblocks += (*it)->get_avg_hash_rate_gblocks();
            hash_count_gblocks += (*it)->get_hash_count_gblocks();
        }

        ss << fixed << setprecision(2) << "--> Hash Rate: " << setw(6) << hash_rate << " H/s   " <<
           "Avg. (C): " << setw(6) << avg_hash_rate_cblocks << " H/s  " <<
           "Avg. (G): " << setw(6) << avg_hash_rate_gblocks << " H/s  " <<
           "Count: " << setw(4) << (hash_count_cblocks + hash_count_gblocks) << "  " <<
           "Time: " << setw(4) << total_time << "  " <<
           "Shares: " << setw(3) << (__confirmed_cblocks + __confirmed_gblocks) << " " <<
           "Rejected: " << setw(3) << (__rejected_cblocks + __rejected_gblocks) << " " <<
            "Blocks: " << setw(3) << __found;
    }
    else {
        ss << "--> Name: " << __args.name() << fixed << setprecision(2) << "  Time: " << setw(4) << total_time << "  " <<
           "Shares (C): " << setw(3) << __confirmed_cblocks << " Shares (G): " << setw(3) << __confirmed_gblocks << " " <<
           "Rejected (C): " << setw(3) << __rejected_cblocks << " Rejected (G): " << setw(3) << __rejected_gblocks << " " <<
            "Blocks: " << setw(3) << __found << endl;
        for (vector<linux8474 *>::iterator it = linux8474s.begin(); it != linux8474s.end(); ++it) {
            hash_rate += (*it)->get_current_hash_rate();
            avg_hash_rate_cblocks += (*it)->get_avg_hash_rate_cblocks();
            hash_count_cblocks += (*it)->get_hash_count_cblocks();
            avg_hash_rate_gblocks += (*it)->get_avg_hash_rate_gblocks();
            hash_count_gblocks += (*it)->get_hash_count_gblocks();

            string subtype = (*it)->get_subtype();
            while(subtype.length() < 7) {
                subtype += " ";
            }
            ss << fixed << setprecision(2) << "--> " << subtype <<
               "Hash rate: " << setw(6)<< (*it)->get_current_hash_rate() << " H/s   " <<
               "Avg. (C): " << setw(6) << (*it)->get_avg_hash_rate_cblocks() << " H/s  " <<
               "Avg. (G): " << setw(6) << (*it)->get_avg_hash_rate_gblocks() << "  " <<
               "Count: " << setw(4) << ((*it)->get_hash_count_cblocks() + (*it)->get_hash_count_gblocks());

            if(linux8474s.size() > 1)
                ss << endl;
        }
        if(linux8474s.size() > 1) {
            ss << fixed << setprecision(2) << "--> ALL    " <<
               "Hash rate: " << setw(6) << hash_rate << " H/s   " <<
               "Avg. (C): " << setw(6) << avg_hash_rate_cblocks << " H/s  " <<
               "Avg. (G): " << setw(6) << avg_hash_rate_gblocks << "  " <<
               "Count: " << setw(4) << (hash_count_cblocks + hash_count_gblocks);
        }
    } */

    if(__argon2profile == "1_1_524288" &&
       __recommendation != "pause") {
        if (hash_rate <= __args.chs_threshold()) {
            __chs_threshold_hit++;
        } else {
            __chs_threshold_hit = 0;
        }
    }

    if(__argon2profile == "4_4_16384" &&
       __recommendation != "pause") {
        if (hash_rate <= __args.ghs_threshold()) {
            __ghs_threshold_hit++;
        } else {
            __ghs_threshold_hit = 0;
        }
    }

    if(__chs_threshold_hit >= 5 && (__blocks_count > 1 || __argon2profile == "1_1_524288")) {
        LOG("CBlocks hashrate is lower than requested threshold, exiting.");
        exit(0);
    }
    if(__ghs_threshold_hit >= 5 && (__blocks_count > 1 || __argon2profile == "4_4_16384")) {
        LOG("GBlocks hashrate is lower than requested threshold, exiting.");
        exit(0);
    }

//    LOG(ss.str());
    __display_hits++;

    return true;
}

void linux84::stop() {
    cout << endl << "Received termination request, please wait for cleanup ... " << endl;
    __running = false;
}

string linux84::get_status() {
    stringstream ss;
    ss << "[ { \"name\": \"" << __args.name() << "\", \"block_height\": " << __height << ", \"time_running\": " << (time(NULL) - __begin_time) <<
       ", \"total_blocks\": " << __blocks_count << ", \"cblocks_shares\": " << __confirmed_cblocks << ", \"gblocks_shares\": " << __confirmed_gblocks <<
       ", \"cblocks_rejects\": " << __rejected_cblocks << ", \"gblocks_rejects\": " << __rejected_gblocks << ", \"blocks_earned\": " << __found <<
       ", \"linux8474s\": [ ";

    vector<linux8474*> linux8474s = linux8474::get_active_linux8474s();

    for(vector<linux8474*>::iterator h = linux8474s.begin(); h != linux8474s.end();) {
        ss << "{ \"type\": \"" << (*h)->get_type() << "\", \"subtype\": \"" << (*h)->get_subtype() << "\", \"devices\": [ ";
        map<int, device_info> devices = (*h)->get_device_infos();
        for(map<int, device_info>::iterator d = devices.begin(); d != devices.end();) {
            ss << "{ \"id\": " << d->first << ", \"bus_id\": \"" << d->second.bus_id << "\", \"name\": \"" << d->second.name << "\", \"cblocks_intensity\": " << d->second.cblocks_intensity <<
                ", \"gblocks_intensity\": " << d->second.gblocks_intensity << ", \"cblocks_hashrate\": " << d->second.cblock_hashrate <<
                ", \"gblocks_hashrate\": " << d->second.gblock_hashrate << " }";
            if((++d) != devices.end())
                ss << ", ";
        }
        ss << " ] }";

        if((++h) != linux8474s.end())
            ss << ", ";
    }

    ss << " ] } ]";

    return ss.str();
}

void linux84::__disconnect_from_pool() {
    __client.disconnect();
}
