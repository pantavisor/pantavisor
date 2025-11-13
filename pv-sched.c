#include <stdio.h>      // For file operations (fopen, fprintf, fscanf, etc.)
#include <stdlib.h>     // For malloc, free, exit, atoi, atof
#include <string.h>     // For strcmp, strcpy, strlen, strncpy
#include <unistd.h>     // For sleep, access
#include <time.h>       // For time_t, time, ctime
#include <sys/time.h>   // For gettimeofday
#include <math.h>       // For fabs (floating-point absolute value)

// --- Configuration Parameters ---
// These are now global variables that can be modified by env/args
#define MAX_CGROUP_NAME_LEN 64
#define MAX_CGROUP_BASE_PATH_LEN 256 // New constant for the base path length
// MAX_CGROUP_PATH_LEN now accounts for base path, cgroup name, and separator
#define MAX_CGROUP_PATH_LEN (MAX_CGROUP_BASE_PATH_LEN + MAX_CGROUP_NAME_LEN + 1) // 256 + 64 + 1 = 321. Using 512 for safety.
#define MAX_HIGH_LOAD_SAMPLES_PER_PERIOD 120 // Max samples for a 10-min period at 5s interval (600/5 = 120)

// Agent Configuration (Default values, overridden by env/args)
const char* HIGH_PRIO_CGROUP_NAMES[] = {"my_high_prio_app"}; // Replace with your actual high-priority cgroup names
#define NUM_HIGH_PRIO_CGROUPS (sizeof(HIGH_PRIO_CGROUP_NAMES) / sizeof(HIGH_PRIO_CGROUP_NAMES[0]))

const char* NORMAL_PRIO_CGROUP_NAMES[] = {"my_normal_prio_app"}; // Replace with your actual normal-priority cgroup names
#define NUM_NORMAL_PRIO_CGROUPS (sizeof(NORMAL_PRIO_CGROUP_NAMES) / sizeof(NORMAL_PRIO_CGROUP_NAMES[0]))

double user_defined_factor = 2.0;
int monitoring_interval_seconds = 2;
int adjustment_interval_seconds = 30;
double high_load_threshold_percent = 70.0;
int min_high_load_duration_seconds = 10;
double adjustment_step_percent = 5.0;
int min_high_prio_shares = 1024;
int max_high_prio_shares = 65536;
char cgroup_base_path[MAX_CGROUP_BASE_PATH_LEN] = "/sys/fs/cgroup/cpu"; // Default path, now uses MAX_CGROUP_BASE_PATH_LEN
int normal_prio_base_shares = 2048;

// --- Global Variables (for agent state) ---
char high_prio_cgroup_paths[NUM_HIGH_PRIO_CGROUPS][MAX_CGROUP_PATH_LEN];
char normal_prio_cgroup_paths[NUM_NORMAL_PRIO_CGROUPS][MAX_CGROUP_PATH_LEN];
char all_cgroup_paths[NUM_HIGH_PRIO_CGROUPS + NUM_NORMAL_PRIO_CGROUPS][MAX_CGROUP_PATH_LEN];

long long previous_cpu_usages[NUM_HIGH_PRIO_CGROUPS + NUM_NORMAL_PRIO_CGROUPS];
long long previous_total_cpu_time = 0;
long long previous_idle_cpu_time = 0;

int current_high_prio_shares_value;

// --- HighLoadPeriod Struct ---
typedef struct {
    struct timeval start_time;
    struct timeval end_time;
    double duration_seconds;
    long long high_prio_cpu_usages[MAX_HIGH_LOAD_SAMPLES_PER_PERIOD];
    int high_prio_cpu_count;
    long long normal_prio_cpu_usages[MAX_HIGH_LOAD_SAMPLES_PER_PERIOD];
    int normal_prio_cpu_count;
} HighLoadPeriod;

// Stores the last two longest high-load periods
HighLoadPeriod longest_high_load_periods[2];
int num_longest_periods = 0; // 0, 1, or 2

// Temporary storage for the currently active high-load period being monitored
HighLoadPeriod current_high_load_period_data;
int is_in_high_load_state = 0; // 0 = false, 1 = true

// --- Function Prototypes ---
// Updated prototypes to include configuration parameters
void print_usage();
void parse_environment_variables();
void parse_command_line_arguments(int argc, char* argv[]);
void set_cpu_shares(const char* cgroup_path, int shares);
long long get_cgroup_cpu_usage(const char* cgroup_path);
double get_system_cpu_utilization();
void initialize_cgroups();
void add_high_load_period(HighLoadPeriod* period);
void print_longest_periods_summary();
void monitor_and_collect_data(double high_load_threshold_percent, int min_high_load_duration_seconds);
void adjust_cpu_shares(double user_defined_factor, double adjustment_step_percent, int min_high_prio_shares, int max_high_prio_shares);


// --- Helper Functions ---

// Function to print usage information
void print_usage() {
    printf("Usage: cgroup_agent [OPTIONS]\n");
    printf("Options:\n");
    printf("  -f, --factor <value>                 User-defined factor for high-prio CPU (default: %.1f)\n", user_defined_factor);
    printf("  -m, --monitor-interval <seconds>     Monitoring interval in seconds (default: %d)\n", monitoring_interval_seconds);
    printf("  -a, --adjust-interval <seconds>      Adjustment interval in seconds (default: %d)\n", adjustment_interval_seconds);
    printf("  -t, --threshold <percent>            High load CPU threshold in percent (default: %.1f)\n", high_load_threshold_percent);
    printf("  -d, --min-duration <seconds>         Minimum high load duration in seconds (default: %d)\n", min_high_load_duration_seconds);
    printf("  -s, --step <percent>                 Adjustment step percentage (default: %.1f)\n", adjustment_step_percent);
    printf("  --min-shares <value>               Minimum high-prio shares (default: %d)\n", min_high_prio_shares);
    printf("  --max-shares <value>               Maximum high-prio shares (default: %d)\n", max_high_prio_shares);
    printf("  --base-path <path>                 Cgroup base path (default: %s)\n", cgroup_base_path);
    printf("  --normal-base-shares <value>       Normal prio base shares (default: %d)\n", normal_prio_base_shares);
    printf("  -h, --help                           Display this help message\n");
    printf("\nEnvironment variables (override defaults, overridden by args):\n");
    printf("  CG_FACTOR, CG_MONITOR_INTERVAL, CG_ADJUST_INTERVAL, CG_THRESHOLD,\n");
    printf("  CG_MIN_DURATION, CG_STEP, CG_MIN_SHARES, CG_MAX_SHARES,\n");
    printf("  CG_BASE_PATH, CG_NORMAL_BASE_SHARES\n");
}

// Function to parse environment variables
void parse_environment_variables() {
    char* env_val;

    printf("Parsing environment variables...\n");
    if ((env_val = getenv("CG_FACTOR")) != NULL) { user_defined_factor = atof(env_val); printf("  CG_FACTOR=%s\n", env_val); }
    if ((env_val = getenv("CG_MONITOR_INTERVAL")) != NULL) { monitoring_interval_seconds = atoi(env_val); printf("  CG_MONITOR_INTERVAL=%s\n", env_val); }
    if ((env_val = getenv("CG_ADJUST_INTERVAL")) != NULL) { adjustment_interval_seconds = atoi(env_val); printf("  CG_ADJUST_INTERVAL=%s\n", env_val); }
    if ((env_val = getenv("CG_THRESHOLD")) != NULL) { high_load_threshold_percent = atof(env_val); printf("  CG_THRESHOLD=%s\n", env_val); }
    if ((env_val = getenv("CG_MIN_DURATION")) != NULL) { min_high_load_duration_seconds = atoi(env_val); printf("  CG_MIN_DURATION=%s\n", env_val); }
    if ((env_val = getenv("CG_STEP")) != NULL) { adjustment_step_percent = atof(env_val); printf("  CG_STEP=%s\n", env_val); }
    if ((env_val = getenv("CG_MIN_SHARES")) != NULL) { min_high_prio_shares = atoi(env_val); printf("  CG_MIN_SHARES=%s\n", env_val); }
    if ((env_val = getenv("CG_MAX_SHARES")) != NULL) { max_high_prio_shares = atoi(env_val); printf("  CG_MAX_SHARES=%s\n", env_val); }
    if ((env_val = getenv("CG_BASE_PATH")) != NULL) { strncpy(cgroup_base_path, env_val, MAX_CGROUP_BASE_PATH_LEN - 1); cgroup_base_path[MAX_CGROUP_BASE_PATH_LEN - 1] = '\0'; printf("  CG_BASE_PATH=%s\n", env_val); }
    if ((env_val = getenv("CG_NORMAL_BASE_SHARES")) != NULL) { normal_prio_base_shares = atoi(env_val); printf("  CG_NORMAL_BASE_SHARES=%s\n", env_val); }
    printf("Environment parsing complete.\n");
}

// Function to parse command line arguments
void parse_command_line_arguments(int argc, char* argv[]) {
    printf("Parsing command line arguments...\n");
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--factor") == 0) {
            if (i + 1 < argc) user_defined_factor = atof(argv[++i]);
            else { fprintf(stderr, "Error: --factor requires a value.\n"); print_usage(); exit(1); }
        } else if (strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "--monitor-interval") == 0) {
            if (i + 1 < argc) monitoring_interval_seconds = atoi(argv[++i]);
            else { fprintf(stderr, "Error: --monitor-interval requires a value.\n"); print_usage(); exit(1); }
        } else if (strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--adjust-interval") == 0) {
            if (i + 1 < argc) adjustment_interval_seconds = atoi(argv[++i]);
            else { fprintf(stderr, "Error: --adjust-interval requires a value.\n"); print_usage(); exit(1); }
        } else if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--threshold") == 0) {
            if (i + 1 < argc) high_load_threshold_percent = atof(argv[++i]);
            else { fprintf(stderr, "Error: --threshold requires a value.\n"); print_usage(); exit(1); }
        } else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--min-duration") == 0) {
            if (i + 1 < argc) min_high_load_duration_seconds = atoi(argv[++i]);
            else { fprintf(stderr, "Error: --min-duration requires a value.\n"); print_usage(); exit(1); }
        } else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--step") == 0) {
            if (i + 1 < argc) adjustment_step_percent = atof(argv[++i]);
            else { fprintf(stderr, "Error: --step requires a value.\n"); print_usage(); exit(1); }
        } else if (strcmp(argv[i], "--min-shares") == 0) {
            if (i + 1 < argc) min_high_prio_shares = atoi(argv[++i]);
            else { fprintf(stderr, "Error: --min-shares requires a value.\n"); print_usage(); exit(1); }
        } else if (strcmp(argv[i], "--max-shares") == 0) {
            if (i + 1 < argc) max_high_prio_shares = atoi(argv[++i]);
            else { fprintf(stderr, "Error: --max-shares requires a value.\n"); print_usage(); exit(1); }
        } else if (strcmp(argv[i], "--base-path") == 0) {
            if (i + 1 < argc) {
                strncpy(cgroup_base_path, argv[++i], MAX_CGROUP_BASE_PATH_LEN - 1);
                cgroup_base_path[MAX_CGROUP_BASE_PATH_LEN - 1] = '\0';
            } else { fprintf(stderr, "Error: --base-path requires a value.\n"); print_usage(); exit(1); }
        } else if (strcmp(argv[i], "--normal-base-shares") == 0) {
            if (i + 1 < argc) normal_prio_base_shares = atoi(argv[++i]);
            else { fprintf(stderr, "Error: --normal-base-shares requires a value.\n"); print_usage(); exit(1); }
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage();
            exit(0);
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage();
            exit(1);
        }
    }
    printf("Command line parsing complete.\n");
}

// Function to set cpu.shares for a cgroup
void set_cpu_shares(const char* cgroup_path, int shares) {
    char shares_file[MAX_CGROUP_PATH_LEN + 16];
    snprintf(shares_file, sizeof(shares_file), "%s/cpu.shares", cgroup_path);

    FILE* fp = fopen(shares_file, "w");
    if (fp == NULL) {
        // If file doesn't exist, it's okay, just skip and print a message
        printf("Cgroup path %s or cpu.shares file does not exist. Skipping setting shares.\n", cgroup_path);
        return;
    }
    fprintf(fp, "%d", shares);
    fclose(fp);
    printf("Set %s/cpu.shares to %d\n", cgroup_path, shares);
}

// Function to get cpuacct.usage for a cgroup
long long get_cgroup_cpu_usage(const char* cgroup_path) {
    char usage_file[MAX_CGROUP_PATH_LEN + 16];
    snprintf(usage_file, sizeof(usage_file), "%s/cpuacct.usage", cgroup_path);

    // For cgroup v2, you would typically read cpu.stat and look at usage_usec
    // or cpu.usage_usec directly.
    FILE* fp = fopen(usage_file, "r");
    if (fp == NULL) {
        // If file doesn't exist, it's okay, just skip and print a message
        printf("Cgroup path %s or cpuacct.usage file does not exist. Skipping reading usage. Returning 0.\n", cgroup_path);
        return 0;
    }
    long long usage;
    if (fscanf(fp, "%lld", &usage) == 1) {
        fclose(fp);
        return usage;
    }
    fclose(fp);
    return 0; // Should not happen if fscanf returns 0 or EOF
}

// Function to get system-wide CPU utilization from /proc/stat
double get_system_cpu_utilization() {
    FILE* fp = fopen("/proc/stat", "r");
    if (fp == NULL) {
        perror("Error opening /proc/stat");
        fprintf(stderr, "Error reading /proc/stat for system CPU utilization. Returning 0.\n");
        return 0.0;
    }

    char line[256];
    long long user, nice, system, idle, iowait, irq, softirq, steal, guest, guest_nice;
    long long current_total_cpu_time, current_idle_cpu_time;

    if (fgets(line, sizeof(line), fp) != NULL) {
        // Parse the "cpu" line
        sscanf(line, "cpu %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld",
               &user, &nice, &system, &idle, &iowait, &irq, &softirq, &steal, &guest, &guest_nice);

        current_total_cpu_time = user + nice + system + idle + iowait + irq + softirq + steal + guest + guest_nice;
        current_idle_cpu_time = idle;

        if (previous_total_cpu_time == 0) {
            previous_total_cpu_time = current_total_cpu_time;
            previous_idle_cpu_time = current_idle_cpu_time;
            fclose(fp);
            return 0.0; // Cannot calculate on first read
        }

        long long delta_total = current_total_cpu_time - previous_total_cpu_time;
        long long delta_idle = current_idle_cpu_time - previous_idle_cpu_time;

        previous_total_cpu_time = current_total_cpu_time;
        previous_idle_cpu_time = current_idle_cpu_time;

        fclose(fp);

        if (delta_total == 0) {
            return 0.0; // Avoid division by zero
        }

        double utilization = (double)(delta_total - delta_idle) / delta_total;
        return utilization * 100.0; // Percentage
    }
    fclose(fp);
    return 0.0;
}

// Function to initialize cgroups (set initial shares)
void initialize_cgroups() {
    printf("Initializing cgroups (setting initial shares)...\n");
    for (int i = 0; i < NUM_HIGH_PRIO_CGROUPS; i++) {
        snprintf(high_prio_cgroup_paths[i], sizeof(high_prio_cgroup_paths[i]), "%s/%s", cgroup_base_path, HIGH_PRIO_CGROUP_NAMES[i]);
        set_cpu_shares(high_prio_cgroup_paths[i], current_high_prio_shares_value);
    }
    for (int i = 0; i < NUM_NORMAL_PRIO_CGROUPS; i++) {
        snprintf(normal_prio_cgroup_paths[i], sizeof(normal_prio_cgroup_paths[i]), "%s/%s", cgroup_base_path, NORMAL_PRIO_CGROUP_NAMES[i]);
        set_cpu_shares(normal_prio_cgroup_paths[i], normal_prio_base_shares);
    }
    printf("Initial shares set for specified cgroups.\n");
}

// Function to add a high load period, keeping only the two longest
void add_high_load_period(HighLoadPeriod* period) {
    if (num_longest_periods < 2) {
        longest_high_load_periods[num_longest_periods] = *period;
        num_longest_periods++;
    } else {
        // Find the shortest period among the current longest two
        int shortest_idx = (longest_high_load_periods[0].duration_seconds < longest_high_load_periods[1].duration_seconds) ? 0 : 1;
        
        // If the new period is longer than the shortest of the two, replace it
        if (period->duration_seconds > longest_high_load_periods[shortest_idx].duration_seconds) {
            longest_high_load_periods[shortest_idx] = *period;
        }
    }
    // Simple sort to keep the longest at index 0 (or just ensure it's sorted)
    if (num_longest_periods == 2 && longest_high_load_periods[0].duration_seconds < longest_high_load_periods[1].duration_seconds) {
        HighLoadPeriod temp = longest_high_load_periods[0];
        longest_high_load_periods[0] = longest_high_load_periods[1];
        longest_high_load_periods[1] = temp;
    }
}

// Function to print a summary of the currently stored longest high load periods
void print_longest_periods_summary() {
    if (num_longest_periods == 0) {
        printf("No significant high load periods recorded yet.\n");
        return;
    }

    printf("\n--- Longest High Load Periods ---\n");
    for (int i = 0; i < num_longest_periods; i++) {
        char start_time_str[30], end_time_str[30];
        struct tm *tm_info;

        tm_info = localtime(&longest_high_load_periods[i].start_time.tv_sec);
        strftime(start_time_str, sizeof(start_time_str), "%H:%M:%S", tm_info);

        if (longest_high_load_periods[i].end_time.tv_sec != 0) {
            tm_info = localtime(&longest_high_load_periods[i].end_time.tv_sec);
            strftime(end_time_str, sizeof(end_time_str), "%H:%M:%S", tm_info);
        } else {
            strcpy(end_time_str, "N/A");
        }
        
        printf("  Period %d: Duration=%.2fs, Start=%s, End=%s\n",
               i + 1, longest_high_load_periods[i].duration_seconds,
               start_time_str, end_time_str);
    }
    printf("---------------------------------\n\n");
}

// Function to monitor CPU usage and update high-load period history
void monitor_and_collect_data(double high_load_threshold_percent_param, int min_high_load_duration_seconds_param) {
    double current_system_util = get_system_cpu_utilization();

    // Skip first iteration for accurate delta calculation
    if (previous_total_cpu_time == 0) {
        return;
    }

    long long current_combined_high_prio_cpu_usage = 0;
    for (int i = 0; i < NUM_HIGH_PRIO_CGROUPS; i++) {
        long long current_usage = get_cgroup_cpu_usage(high_prio_cgroup_paths[i]);
        long long delta_usage = current_usage - previous_cpu_usages[i];
        current_combined_high_prio_cpu_usage += delta_usage;
        previous_cpu_usages[i] = current_usage;
    }

    long long current_combined_normal_prio_cpu_usage = 0;
    for (int i = 0; i < NUM_NORMAL_PRIO_CGROUPS; i++) {
        long long current_usage = get_cgroup_cpu_usage(normal_prio_cgroup_paths[i]);
        long long delta_usage = current_usage - previous_cpu_usages[NUM_HIGH_PRIO_CGROUPS + i];
        current_combined_normal_prio_cpu_usage += delta_usage;
        previous_cpu_usages[NUM_HIGH_PRIO_CGROUPS + i] = current_usage;
    }

    // High Load Detection Logic
    if (current_system_util >= high_load_threshold_percent_param) {
        if (!is_in_high_load_state) {
            // Just entered high load state
            is_in_high_load_state = 1;
            gettimeofday(&current_high_load_period_data.start_time, NULL);
            current_high_load_period_data.end_time.tv_sec = 0; // Mark as ongoing
            current_high_load_period_data.duration_seconds = 0.0;
            current_high_load_period_data.high_prio_cpu_count = 0;
            current_high_load_period_data.normal_prio_cpu_count = 0;
            printf("Entered high load state at %s", ctime(&current_high_load_period_data.start_time.tv_sec));
        }
        
        // Collect data for the current high load period
        if (current_high_load_period_data.high_prio_cpu_count < MAX_HIGH_LOAD_SAMPLES_PER_PERIOD) {
            current_high_load_period_data.high_prio_cpu_usages[current_high_load_period_data.high_prio_cpu_count++] = current_combined_high_prio_cpu_usage;
            current_high_load_period_data.normal_prio_cpu_usages[current_high_load_period_data.normal_prio_cpu_count++] = current_combined_normal_prio_cpu_usage;
        } else {
            fprintf(stderr, "Warning: High load period data buffer full. Cannot store more samples.\n");
        }
    } else {
        if (is_in_high_load_state) {
            // Just exited high load state
            is_in_high_load_state = 0;
            gettimeofday(&current_high_load_period_data.end_time, NULL);
            current_high_load_period_data.duration_seconds = 
                (current_high_load_period_data.end_time.tv_sec - current_high_load_period_data.start_time.tv_sec) +
                (double)(current_high_load_period_data.end_time.tv_usec - current_high_load_period_data.start_time.tv_usec) / 1000000.0;

            if (current_high_load_period_data.duration_seconds >= min_high_load_duration_seconds_param) {
                printf("Exited high load state. Duration: %.2fs\n", current_high_load_period_data.duration_seconds);
                add_high_load_period(&current_high_load_period_data);
            } else {
                printf("High load period too short (%.2fs), discarding.\n", current_high_load_period_data.duration_seconds);
            }
            // Reset current_high_load_period_data (implicitly done by setting is_in_high_load_state=0)
        }
    }
    
    printf("Monitoring: System CPU: %.2f%%, High Prio CPU: %lld, Normal Prio CPU: %lld\n",
           current_system_util, current_combined_high_prio_cpu_usage, current_combined_normal_prio_cpu_usage);
    print_longest_periods_summary();
}

// Function to calculate and apply new cpu.shares based on historical high load data
void adjust_cpu_shares(double user_defined_factor_param, double adjustment_step_percent_param, int min_high_prio_shares_param, int max_high_prio_shares_param) {
    if (num_longest_periods == 0) {
        printf("Not enough historical high load data to adjust CPU shares.\n");
        return;
    }

    long long total_high_prio_cycles = 0;
    long long total_normal_prio_cycles = 0;
    int total_intervals_in_high_load = 0;

    for (int i = 0; i < num_longest_periods; i++) {
        for (int j = 0; j < longest_high_load_periods[i].high_prio_cpu_count; j++) {
            total_high_prio_cycles += longest_high_load_periods[i].high_prio_cpu_usages[j];
            total_normal_prio_cycles += longest_high_load_periods[i].normal_prio_cpu_usages[j];
        }
        total_intervals_in_high_load += longest_high_load_periods[i].high_prio_cpu_count;
    }

    if (total_intervals_in_high_load == 0) {
        printf("No CPU usage data collected during high load periods. Deferring adjustment.\n");
        return;
    }

    double avg_high_prio_combined_cpu_per_interval = (double)total_high_prio_cycles / total_intervals_in_high_load;
    double avg_normal_prio_combined_cpu_per_interval = (double)total_normal_prio_cycles / total_intervals_in_high_load;

    printf("Adjustment: Avg High Prio Combined CPU per interval: %.2f\n", avg_high_prio_combined_cpu_per_interval);
    printf("Adjustment: Avg Normal Prio Combined CPU per interval: %.2f\n", avg_normal_prio_combined_cpu_per_interval);

    if (avg_normal_prio_combined_cpu_per_interval == 0) {
        printf("Normal priority cgroups were idle during high load. Cannot calculate ratio. Deferring adjustment.\n");
        return;
    }

    double current_observed_ratio = avg_high_prio_combined_cpu_per_interval / avg_normal_prio_combined_cpu_per_interval;
    printf("Adjustment: Current Observed Ratio (High/Normal): %.2f\n", current_observed_ratio);
    printf("Adjustment: User Defined Factor: %.2f\n", user_defined_factor_param);

    // Determine adjustment direction and magnitude
    if (fabs(current_observed_ratio - user_defined_factor_param) < 0.05) { // Within 5% tolerance
        printf("Current ratio is close to target factor. No adjustment needed.\n");
        return;
    }

    double proposed_individual_high_prio_shares = (double)current_high_prio_shares_value;

    if (current_observed_ratio < user_defined_factor_param) {
        // High prio is getting less than desired, increase shares
        proposed_individual_high_prio_shares *= (1.0 + adjustment_step_percent_param / 100.0);
        printf("Adjustment: Increasing high_prio_shares.\n");
    } else {
        // High prio is getting more than desired, decrease shares
        proposed_individual_high_prio_shares *= (1.0 - adjustment_step_percent_param / 100.0);
        printf("Adjustment: Decreasing high_prio_shares.\n");
    }

    // Clamp the shares value within min/max bounds
    int new_high_prio_shares = (int)proposed_individual_high_prio_shares;
    if (new_high_prio_shares < min_high_prio_shares_param) new_high_prio_shares = min_high_prio_shares_param;
    if (new_high_prio_shares > max_high_prio_shares_param) new_high_prio_shares = max_high_prio_shares_param;

    if (new_high_prio_shares == current_high_prio_shares_value) {
        printf("Adjustment: Calculated new shares is same as current or clamped. No change applied.\n");
        return;
    }

    current_high_prio_shares_value = new_high_prio_shares;
    printf("Adjustment: New high_prio_shares_value: %d\n", current_high_prio_shares_value);

    // Apply the new shares to all high-priority cgroups
    for (int i = 0; i < NUM_HIGH_PRIO_CGROUPS; i++) {
        set_cpu_shares(high_prio_cgroup_paths[i], current_high_prio_shares_value);
    }
}

// --- Main Function ---
int main(int argc, char* argv[]) {
    // 1. Parse environment variables (sets defaults if not overridden by args)
    parse_environment_variables();

    // 2. Parse command-line arguments (overrides environment variables)
    parse_command_line_arguments(argc, argv);

    // Initialize cgroup paths using the potentially updated cgroup_base_path
    for (int i = 0; i < NUM_HIGH_PRIO_CGROUPS; i++) {
        snprintf(high_prio_cgroup_paths[i], sizeof(high_prio_cgroup_paths[i]), "%s/%s", cgroup_base_path, HIGH_PRIO_CGROUP_NAMES[i]);
    }
    for (int i = 0; i < NUM_NORMAL_PRIO_CGROUPS; i++) {
        snprintf(normal_prio_cgroup_paths[i], sizeof(normal_prio_cgroup_paths[i]), "%s/%s", cgroup_base_path, NORMAL_PRIO_CGROUP_NAMES[i]);
    }
    
    // Initialize previous_cpu_usages array for all cgroups
    for (int i = 0; i < NUM_HIGH_PRIO_CGROUPS; i++) {
        previous_cpu_usages[i] = get_cgroup_cpu_usage(high_prio_cgroup_paths[i]);
    }
    for (int i = 0; i < NUM_NORMAL_PRIO_CGROUPS; i++) {
        previous_cpu_usages[NUM_HIGH_PRIO_CGROUPS + i] = get_cgroup_cpu_usage(normal_prio_cgroup_paths[i]);
    }

    // Initial high_prio_shares value calculation based on potentially updated config
    if (NUM_HIGH_PRIO_CGROUPS > 0) {
        current_high_prio_shares_value = (int)(
            (user_defined_factor * NUM_NORMAL_PRIO_CGROUPS * normal_prio_base_shares) / NUM_HIGH_PRIO_CGROUPS
        );
        // Clamp initial value
        if (current_high_prio_shares_value < min_high_prio_shares) current_high_prio_shares_value = min_high_prio_shares;
        if (current_high_prio_shares_value > max_high_prio_shares) current_high_prio_shares_value = max_high_prio_shares;
    } else {
        current_high_prio_shares_value = normal_prio_base_shares;
    }
    printf("Agent initialized. Initial high_prio_shares_value: %d\n", current_high_prio_shares_value);

    initialize_cgroups(); // Set initial shares for existing cgroups

    // Get initial system CPU stats for the first delta calculation
    get_system_cpu_utilization();

    int monitor_counter = 0;
    
    printf("\nAgent started. Monitoring and adjusting cgroups...\n\n");

    while (1) {
        monitor_and_collect_data(high_load_threshold_percent, min_high_load_duration_seconds);
        monitor_counter += monitoring_interval_seconds;

        if (monitor_counter >= adjustment_interval_seconds) {
            adjust_cpu_shares(user_defined_factor, adjustment_step_percent, min_high_prio_shares, max_high_prio_shares);
            monitor_counter = 0; // Reset counter for next adjustment cycle
        }

        sleep(monitoring_interval_seconds);
    }

    return 0;
}

