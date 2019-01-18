//
// Created by Haifa Bogdan Adnan on 04/08/2018.
//

#ifndef ARIOMINER_ARGUMENTS_H
#define ARIOMINER_ARGUMENTS_H

class DLLEXPORT arguments {
public:
    arguments(int argc, char *argv[]);

    bool valid(string &error);

    bool is_help();
    bool is_verbose();
    bool is_miner();
    bool is_autotune();
    bool is_proxy();

    string pool();
    string wallet();
    string name();
    double cpu_intensity();
    vector<double> &gpu_intensity_cblocks();
    vector<double> &gpu_intensity_gblocks();
    vector<string> gpu_filter();
    vector<int> gpu_threads();
    int proxy_port();
    string argon2_profile();

    double gpu_intensity_start();
    double gpu_intensity_stop();
    double gpu_intensity_step();
    int64_t autotune_step_time();

    int64_t update_interval();
    int64_t report_interval();
    int64_t hash_report_interval();

	string cpu_optimization();
	vector<string> gpu_optimization();

	int chs_threshold();
	int ghs_threshold();

	bool show_pool_requests();

    string get_help();

    static string get_app_folder();

    int get_cards_count() { return __cards_count; }
    void set_cards_count(int count) { __cards_count = count; }

private:
    void __init();
    vector<string> __parse_multiarg(const string &arg);

    string __error_message;
    bool __error_flag;

    int __help_flag;
    int __verbose_flag;
    int __miner_flag;
    int __proxy_flag;
    int __autotune_flag;

    string __pool;
    string __wallet;
    string __name;
    double __cpu_intensity;
    vector<double> __gpu_intensity_cblocks;
    vector<double> __gpu_intensity_gblocks;
	vector<string> __gpu_filter;
	vector<int> __gpu_threads;
    int __proxy_port;
    int64_t __update_interval;
    int64_t __report_interval;
    int64_t __hash_report_interval;

    double __gpu_intensity_start;
    double __gpu_intensity_stop;
    double __gpu_intensity_step;
    int64_t __autotune_step_time;

    string __argon2profile;

	string __cpu_optimization;
	vector<string> __gpu_optimization;

	int __chs_threshold;
	int __ghs_threshold;

	bool __show_pool_requests;

	int __cards_count;
    static string __argv_0;
};

#endif //ARIOMINER_ARGUMENTS_H
