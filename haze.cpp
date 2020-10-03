//
// Haze - a binary fuzzer
// rjohnson@fuzzing.io
//
// cd C:\code\haze\out\build\x64-Release
// haze.exe -i c:\code\fuzzdata\samples\ico -o ico -iterations 1000 -persist -target_module faster_gdiplus.exe -target_method fuzzit -nargs 1 -loop -instrument_module WindowsCodecs.dll -- c:\winafl\bin64\faster_gdiplus.exe @@
// c:\code\haze\out\build\x64-Release\haze.exe -i c:\code\fuzzdata\samples\ico -o ico -iterations 1000 -persist -target_module faster_gdiplus.exe -target_method fuzzit -nargs 1 -loop -instrument_module WindowsCodecs.dll -- c:\winafl\bin64\faster_gdiplus.exe @@
// c:\code\haze\out\build\x64-Release\haze.exe -i c:\winafl\testcases\images\ico -o ico -iterations 1000 -persist -target_module faster_gdiplus.exe -target_method fuzzit -nargs 1 -loop -instrument_module WindowsCodecs.dll -- c:\winafl\bin64\faster_gdiplus.exe @@
//


#define  _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <inttypes.h>
#include <stdbool.h>

#include <chrono>

#include <vector>
#include <iostream>
#include <fstream>
#include <algorithm>

#include "common.h"
#include "litecov.h"

#include "util.h"


#include <filesystem>
namespace fs = std::filesystem;

LiteCov* instrumentation;
bool persist;

int loop_iterations;
int total_iterations;
int persist_iteration;

// percent of mutations done by libFuzzer mutator
int mutate_libFuzzer_pct;


fs::path input_path;
fs::path out_path;
fs::path crash_path;
fs::path queue_path;
fs::path cur_input_path;

int target_argc;
char** target_argv;
unsigned int target_pid;

unsigned int mutation_seed = 31337;
unsigned int max_mut_count = 16;

// run a single iteration over the target process
// whether it's the whole process or target method
// and regardless if the target is persistent or not
// (should know what to do in pretty much all cases)
void RunTarget(int argc, char** argv, unsigned int pid, uint32_t timeout) {
	DebuggerStatus status;

	//printf("no argc? %d %ws\n\n", argc, argv[1]);

	// else clear only when the target function is reached
	if (!instrumentation->IsTargetFunctionDefined()) {
		instrumentation->ClearCoverage();
	}

	if (instrumentation->IsTargetAlive() && persist) {
		status = instrumentation->Continue(timeout);
	}
	else {
		instrumentation->Kill();
		persist_iteration = 0;
		if (argc) {
			status = instrumentation->Run(argc, argv, timeout);
		}
		else {
			status = instrumentation->Attach(pid, timeout);
		}
	}

	// if target function is defined,
	// we should wait until it is hit
	if (instrumentation->IsTargetFunctionDefined()) {
		if ((status != DEBUGGER_TARGET_START) && argc) {
			// try again with a clean process
			WARN("Target function not reached, retrying with a clean process\n");
			instrumentation->Kill();
			persist_iteration = 0;
			status = instrumentation->Run(argc, argv, timeout);
		}

		if (status != DEBUGGER_TARGET_START) {
			switch (status) {
			case DEBUGGER_CRASHED:
				FATAL("Process crashed before reaching the target method\n");
				break;
			case DEBUGGER_HANGED:
				FATAL("Process hanged before reaching the target method\n");
				break;
			case DEBUGGER_PROCESS_EXIT:
				FATAL("Process exited before reaching the target method\n");
				break;
			default:
				FATAL("An unknown problem occured before reaching the target method\n");
				break;
			}
		}

		instrumentation->ClearCoverage();

		status = instrumentation->Continue(timeout);
	}

	fs::path crashpath;
	switch (status) {
	case DEBUGGER_CRASHED:
		printf("Process crashed\n");
		instrumentation->Kill();
		crashpath = crash_path / std::to_string(rand());
		fs::copy_file(cur_input_path, crashpath);
		break;
	case DEBUGGER_HANGED:
		printf("Process hanged\n");
		instrumentation->Kill();
		break;
	case DEBUGGER_IGNORE_EXCEPTION:
		//printf("IGNORE EXCEPTION\n");
		instrumentation->Kill();
		// delay to avoid hitting files system error writing new input
		//printf("Sleep(10) in DEBUGGER_IGNORE_EXCEPTION");
		//Sleep(10);
		break;

	case DEBUGGER_PROCESS_EXIT:
		if (instrumentation->IsTargetFunctionDefined()) {
			printf("Process exit during target function\n");
		}
		else {
			//printf("Process finished normally\n");
		}
		break;
	case DEBUGGER_TARGET_END:
		if (instrumentation->IsTargetFunctionDefined()) {
			//printf("Target function returned normally\n");
			persist_iteration++;
			if (persist_iteration == loop_iterations) {
				instrumentation->Kill();
			}
		}
		else {
			FATAL("Unexpected status received from the debugger\n");
		}
		break;
	default:
		FATAL("Unexpected status received from the debugger\n");
		break;
	}
}


typedef struct {
	uint16_t offset;
	uint8_t  old_value;
	uint8_t  new_value;
} mutation;

// do up to MAX_MUTATIONS on a single input
#define MAX_MUTATIONS 16
mutation mutations[MAX_MUTATIONS];

char* USAGE_STRING =
"Usage:\n"
"\n"
"Attach:\n"
"%s <options> -pid <pid to attach to>\n"
"Run:\n"
"%s <options> -- <target command line>\n"
"\n"
"Options:\n";

void usage(char** argv)
{
	printf(USAGE_STRING, argv[0], argv[0]);
	printf("\n");

	exit(1);
}

void version()
{
	printf("Haze Binary Fuzzer\n");
}

template <typename Accessor, typename Cmp = std::less<> >
static auto compare_by(Accessor&& f, Cmp cmp = {}) {
	return[f = std::forward<Accessor>(f), cmp](auto const& a, auto const& b) {
		return cmp(f(a), f(b));
	};
}

bool prepare_queue()
{
	Coverage coverage;
	
	int num_iterations = 0;

	auto start = std::chrono::high_resolution_clock::now();
	
	// get input files 
	std::vector<fs::path> input_filepaths;
	for (const auto& entry : fs::directory_iterator{ fs::directory_entry(input_path) }) {
		if (entry.is_regular_file()) {
			input_filepaths.push_back(entry.path().string());
		}
	}

	// sort contents of input path by size 
	std::sort(input_filepaths.begin(), input_filepaths.end(),
		[](const auto& lhs, const auto& rhs) {
			return fs::file_size(lhs.string()) < fs::file_size(rhs.string());
		});
	

	long prev_elapsed = 0;
	std::cout << "Selecting inputs for queue.. " << std::endl;

	int queue_count = 0;
	for (const auto& input_path : input_filepaths) {
		num_iterations++;

		cur_input_path = out_path / ".cur_input";
		try {
			if (fs::is_regular_file(cur_input_path))
				fs::remove(cur_input_path);
		}
		catch (fs::filesystem_error& e) {
			// delay and retry
			bool deleted = false;
			for(int i = 0; i < 10; i++)
			{
				std::error_code ec;
				Sleep(10);

				if (fs::remove(cur_input_path, ec))
				{
					deleted = true;
					break;
				}
			}
			if (!deleted)
			{
				printf("Error: .cur_input seems to be locked[%s]. Exiting..", e.what());
				exit(1);
			}
		}
		try {
			fs::copy_file(input_path, cur_input_path);
		}		
		catch (fs::filesystem_error& e) {
			printf("Error: failed to copy input[%s] to cur_input: %s\n", (char *)input_path.c_str(), e.what());
			exit(1);
		}
		RunTarget(target_argc, target_argv, target_pid, 0xFFFFFFFF);

		Coverage newcoverage;

		instrumentation->GetCoverage(newcoverage, true);
		
		std::string input_str = "size:" + std::to_string(fs::file_size(input_path)) + " " + input_path.string();
		if (newcoverage.size() > 0)
		{
			std::cout << "[+] " << input_str << '\n';
			std::string queue_path = out_path.string() + "/queue/" + std::to_string(queue_count) + "-" + input_path.filename().string();
			fs::copy_file(input_path, queue_path);
			queue_count += 1;

			instrumentation->IgnoreCoverage(newcoverage);

			MergeCoverage(coverage, newcoverage);
		}
		else
		{
			std::cout << "[-] " << input_str << '\n';
		}
	}

	std::cout << std::endl;
	std::cout << queue_count << " of " << input_filepaths.size() << " added to queue" << std::endl;
	/*
	auto elapsed = std::chrono::high_resolution_clock::now() - start;
	long ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
	float secs = (float)ms / 1000;
	float execs = (float)num_iterations / secs;
	std::cout << "Time elapsed: " << ms << "ms  average exec/s: " << execs << std::endl << std::endl;
	*/
	return 0;
}

void mutate_input()
{

}


extern "C" size_t LLVMFuzzerMutate(uint8_t * Data, size_t Size, size_t MaxSize);
extern "C" int    LLVMFuzzerRunDriver(int* argc, char*** argv, 
							int (*UserCb)(const uint8_t * Data, size_t Size));
extern "C" void   LLVMFuzzerMyInit(
							int (*UserCb)(const uint8_t * Data,	size_t Size),
							unsigned int Seed);
extern "C" int dummy(const uint8_t * Data, size_t Size) {

	(void)(Data);
	(void)(Size);
	fprintf(stderr, "dummy() called\n");
	return 0;
}

#define MUTANT_MAX_SIZE 4096*4


bool fuzz_loop()
{
	auto fuzz_loop_start_clock = std::chrono::high_resolution_clock::now();
	Coverage coverage, newcoverage;

	LLVMFuzzerMyInit(dummy, mutation_seed);

//	char *mutant = (char *)calloc(1, MUTANT_MAX_SIZE);
//	int mutant_size = MUTANT_MAX_SIZE;

	bool done = false;
	uint64_t loop_iteration = 0;
	while (!done)
	{
		// select random input from queue
		std::vector<fs::path> queuepaths;
		for (const auto& entry : fs::directory_iterator{ fs::directory_entry(queue_path) }) {
			if (entry.is_regular_file()) {
				queuepaths.push_back(entry.path());
			}
		}
		unsigned int queue_size = (unsigned int)queuepaths.size();

		// get random input from queue
		unsigned int input_file_idx = rand() % queue_size;
		fs::path input_file_path = queuepaths[input_file_idx];

		auto sample = file2vec(input_file_path);

		printf("Mutating [%d/%d] for %d iterations: %ws\n", input_file_idx + 1, queue_size, loop_iterations, input_file_path.filename().c_str());


		auto iteration_loop_start_clock = std::chrono::high_resolution_clock::now();
		long prev_elapsed = 0;
		for (loop_iteration = 1; loop_iteration <= loop_iterations; loop_iteration++) {
			std::string mutator_name;
			
			// Use libFuzzer mutate_libFuzzer_pct% of the time and spray16 the rest if -libFuzzer is passed 
			if (loop_iteration < loop_iterations * (mutate_libFuzzer_pct/100.0))
			{
				mutator_name = "libFuzzer";

				// allow mutation to grow input by up to 128 bytes
				int mut_max_size = sample.size() + 128;

				//std::vector<char> mutant(sample);
				//mutant.reserve(mutant.size() + 128);
				//size_t ret = LLVMFuzzerMutate((uint8_t*)&mutant[0], mutant.size(), mutant.size() + 128);
				char* mutant = (char *)calloc(1, mut_max_size);
				memcpy(mutant, &sample[0], sample.size());
				size_t ret = LLVMFuzzerMutate((uint8_t*)mutant, sample.size(), mut_max_size);

				// write mutant to disk 
				std::ofstream outf(cur_input_path, std::ios::out | std::ios::binary);
				//outf.write(&mutant[0], ret);
				outf.write(mutant, ret);
				outf.flush();
				outf.close();
				free(mutant);
			}
			else
			{
				auto mut_count = rand() % max_mut_count;
				mutator_name = "spray" + std::to_string(mut_count);
				
				// init mutation records 
				memset(mutations, 0, sizeof(mutations));

				// generate mutation actions
				for (auto i = 0; i < mut_count; i++)
				{
					unsigned int sample_offset = rand() % sample.size();
					mutations[i].offset = sample_offset;
					mutations[i].old_value = sample[sample_offset];
					mutations[i].new_value = rand() % 256;
				}

				// apply mutations
				for (auto i = 0; i < mut_count; i++)
					sample[mutations[i].offset] = mutations[i].new_value;				

				// write mutant to disk 
				std::ofstream outf(cur_input_path, std::ios::out | std::ios::binary);
				outf.write(&sample[0], sample.size());
				outf.flush();
				outf.close();

				// restore mutated bytes to original 
				for (unsigned int i = 0; i < mut_count; i++)
					sample[mutations[i].offset] = mutations[i].old_value;

			}

			RunTarget(target_argc, target_argv, target_pid, 0xFFFFFFFF);

			Coverage newcoverage;
			instrumentation->GetCoverage(newcoverage, true);
			if (newcoverage.size() > 0)
			{
				auto input_filename = input_file_path.filename().string();
				int off = input_filename.find('-') + 1;
				if(off < input_filename.size())
					input_filename = input_filename.substr(input_filename.find('-') + 1);

				std::string new_input_name = "id" + std::to_string(total_iterations + loop_iteration) + "-" + input_filename;
				fs::path new_input_path = queue_path / new_input_name;
				try {
					fs::copy_file(cur_input_path, new_input_path);
				}
				catch (fs::filesystem_error& e) { // throws if path already exists
					printf("ERROR: failed to copy input with new coverage to queue [%s]: %s .. exiting.", (char *)new_input_path.c_str(), e.what());
					exit(1);
				}

				queue_size++;
			}
			for (auto iter = newcoverage.begin(); iter != newcoverage.end(); iter++) {
				//printf("    NEWCOV ### Iteration %6d: Found %d new offsets in %s\n", i, (int)iter->offsets.size(), iter->module_name);
				std::cout << "    NEWCOV ### Iteration " << std::to_string(total_iterations + loop_iteration) << ": mutator[" + mutator_name + "] Found " << iter->offsets.size() << " new offsets in " << iter->module_name << std::endl;
			}

			instrumentation->IgnoreCoverage(newcoverage);

			MergeCoverage(coverage, newcoverage);

		}
		total_iterations += loop_iterations;

		auto fuzz_loop_elapsed = std::chrono::high_resolution_clock::now() - fuzz_loop_start_clock; 
		auto iteration_loop_elapsed = std::chrono::high_resolution_clock::now() - iteration_loop_start_clock;
		unsigned int ms = (unsigned int)std::chrono::duration_cast<std::chrono::milliseconds>(iteration_loop_elapsed).count();
		float execs = (float)(loop_iterations * 1000) / ms;
		std::cout << loop_iterations << " iterations complete. Time elapsed: " << ms << "ms  average exec/s: " << execs << std::endl;
		std::cout << total_iterations << " total iterations. Time elapsed: " << fuzz_loop_elapsed << std::endl;
		std::cout << std::endl;
		//if (outfile) WriteCoverage(coverage, outfile);
	}
	return true;
}


int main(int argc, char** argv)
{
	version();
	printf("\n");

	instrumentation = new LiteCov();
	instrumentation->Init(argc, argv);

	// find target args
	int target_opt_ind = 0;
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--") == 0) {
			target_opt_ind = i + 1;
			break;
		}
	}

	target_argc = (target_opt_ind) ? argc - target_opt_ind : 0;

	// make a copy of target argv so we can modify it
	char** orig_target_argv = (target_opt_ind) ? argv + target_opt_ind : NULL;
	target_argv = (char **)malloc(target_argc * sizeof(char*));
	memcpy(target_argv, orig_target_argv, target_argc * sizeof(char*));
	
	unsigned int pid = GetIntOption("-pid", argc, argv, 0);
	persist = GetBinaryOption("-persist", argc, argv, false);
	loop_iterations = GetIntOption("-iterations", argc, argv, 1);
	//char* outfile = GetOption("-coverage_file", argc, argv);
	char* idir = GetOption("-i", argc, argv);
	char* odir = GetOption("-o", argc, argv);
	max_mut_count = GetIntOption("-mut_count", argc, argv, 16);
	if (max_mut_count > 16) max_mut_count = 16;
	unsigned int rseed = GetIntOption("-rseed", argc, argv, 0);
	mutate_libFuzzer_pct = GetIntOption("-libFuzzer", argc, argv, false);

	// validate required options 
	if ((!target_argc && !pid) || !idir || !odir) {
		usage(argv);
	}

	target_pid = pid;
	input_path = fs::path(idir);
	out_path = fs::path(odir);
	cur_input_path = out_path / ".cur_input";

	// replace target argv @@ with file path, exit if not found
	bool atat_found = false;
	for (int i = 0; i < target_argc; i++)
	{
		if (!strcmp(target_argv[i], "@@"))
		{
			target_argv[i] = (char *)_strdup(cur_input_path.string().c_str());
			atat_found = true;
		}
	}
	if (!atat_found)
	{
		std::cout << "error: target argv does not contain @@, nothing to fuzz.. exiting." << std::endl;
		usage(argv);
	}

	// check input dir exists 
	if (!fs::is_directory(input_path))
	{
		std::cout << "error: invalid input directory.. exiting" << std::endl;
		usage(argv);
	}

	// check and create output directory tree 
	if (fs::is_directory(out_path))
	{
		printf("WARNING: output directory already exists.. DELETE? (y/N): ");
		char c = getchar();
		if (!(c == 'y' || c == 'Y'))
			exit(0);
		printf("\n");

		try {
			fs::remove_all(out_path);
		}
		catch (fs::filesystem_error& e) {
			printf("WARNING: error deleteing output directory (retrying): %s", e.what());
			// delay and retry
			bool success = false;
			for (int i = 0; i < 10; i++)
			{
				std::error_code ec;
				Sleep(10);
				if (!fs::remove_all(out_path, ec))
				{
					success = true;
					break;
				}
			}
			if (!success)
			{
				printf("Error: output directory already exists and couldnt delete. Exiting..");
				exit(1);
			}
		}
	}
	Sleep(100);

	// create output directory	
	if (!fs::create_directory(out_path))
	{
		std::cout << "error: could not create output directory.. exiting." << std::endl;
		usage(argv);
	}

	// create output/queue
	queue_path = out_path / "queue";
	if (!fs::create_directory(queue_path))
	{
		std::cout << "error: could not create output directory.. exiting." << std::endl;
		usage(argv);
	}

	// create output/crashes
	crash_path = out_path / "crashes";
	if (!fs::create_directory(crash_path))
	{
		std::cout << "error: could not create output directory.. exiting." << std::endl;
		usage(argv);
	}
	// Sleep to avoid filesystem sync issues. 
	Sleep(100);


	if (rseed)
		mutation_seed = rseed;
	else
		mutation_seed = (unsigned int)time(NULL);
	srand(mutation_seed);
	std::cout << "random seed: " << mutation_seed << std::endl;


	// sort inputs by size, copy inputs that add new coverage to queue
	prepare_queue();

	fuzz_loop();

	return 0;
}
