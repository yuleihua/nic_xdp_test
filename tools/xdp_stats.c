#include <linux/bpf.h>
#include <linux/if_link.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/resource.h>
#include <net/if.h>

#include "bpf.h"
#include "libbpf.h"


#define MAP_DIR "/sys/fs/bpf"
#define COUNTER_MAP_PATH "/sys/fs/bpf/action_counters"
#define ACTION_MAP_PATH "/sys/fs/bpf/action"

#ifndef XDP_MAX_ACTIONS
#define XDP_MAX_ACTIONS (XDP_REDIRECT + 1)
#endif

#ifndef IF_NAMESIZE
#define IF_NAMESIZE 128
#endif

/* Exit codes */
#define EXIT_OK 0
#define EXIT_FAIL_GENERIC 1
#define EXIT_FAIL_OPTIONS 2

#define EXIT_FAIL_XDP_ATTACH 3
#define EXIT_FAIL_XDP_DETACH 4

#define EXIT_FAIL_XDP_MAP_OPEN 5
#define EXIT_FAIL_XDP_MAP_LOOKUP 6
#define EXIT_FAIL_XDP_MAP_UPDATE 7
#define EXIT_FAIL_XDP_MAP_DELETE 8
#define EXIT_FAIL_XDP_MAP_PIN 9

#define EXIT_FAIL_RLIMIT 10

static const char *xdp_action_names[XDP_MAX_ACTIONS] = {
    [XDP_ABORTED] = "XDP_ABORTED",
    [XDP_DROP] = "XDP_DROP",
    [XDP_PASS] = "XDP_PASS",
    [XDP_TX] = "XDP_TX",
    [XDP_REDIRECT] = "XDP_REDIRECT",
};

struct counters {
    __u64 packets;
    __u64 bytes;
};

static const char *action2str(int action)
{
    if (action < XDP_MAX_ACTIONS)
    {
        return xdp_action_names[action];
    }
    return NULL;
}

static int str2action(const char *action)
{
    int i;
    for (i = 0; i < XDP_MAX_ACTIONS; i++)
    {
        if (strcmp(xdp_action_names[i], action) == 0)
        {
            return i;
        }
    }
    return -1;
}

static char *default_prog_path = "xdp_stats_kern.o";
static char *default_section = "xdp_stats";
static const char *doc = "XDP: Map pinning and loading/unloading\n";

static const struct option long_options[] = {
    {"help", no_argument, NULL, 'h'},
    {"xdp-program", optional_argument, NULL, 'x'},
    {"xdp-section", optional_argument, NULL, 'n'},
    {"attach", required_argument, NULL, 'a'},
    {"detach", required_argument, NULL, 'd'},
    {"stats", no_argument, NULL, 's'},
    {"set-action", required_argument, NULL, 'e'},
    {0, 0, NULL, 0}};

static const char *long_options_descriptions[] = {
    [0] = "Display this help message.",
    [1] = "The file path to the xdp program to load.",
    [2] = "The section name to load from the given xdp program.",
    [3] = "Attach the specified XDP program to the specified network device.",
    [4] = "Detach the specified XDP program from the specified network device.",
    [5] = "Print statistics from the already loaded XDP program.",
    [6] = "Set the XDP action for the XDP program to return.",
};

static inline unsigned int bpf_num_possible_cpus(void)
{
	static const char *fcpu = "/sys/devices/system/cpu/possible";
	unsigned int start, end, possible_cpus = 0;
	char buff[128];
	FILE *fp;
	int n;

	fp = fopen(fcpu, "r");
	if (!fp) {
		printf("Failed to open %s: '%s'!\n", fcpu, strerror(errno));
		exit(1);
	}

	while (fgets(buff, sizeof(buff), fp)) {
		n = sscanf(buff, "%u-%u", &start, &end);
		if (n == 0) {
			printf("Failed to retrieve # possible CPUs!\n");
			exit(1);
		} else if (n == 1) {
			end = start;
		}
		possible_cpus = start == 0 ? end + 1 : 0;
		break;
	}
	fclose(fp);

	return possible_cpus;
}


int open_bpf_map(const char *file)
{
    int fd;

    fd = bpf_obj_get(file);
    if (fd < 0)
    {
        printf("ERR: Failed to open bpf map file: '%s' err(%d): %s\n",
               file, errno, strerror(errno));
        return -errno;
    }
    return fd;
}

static int get_action_stats(int fd)
{
    unsigned int num_cpus = bpf_num_possible_cpus();
    struct counters values[num_cpus];
    struct counters overall = {
        .bytes = 0,
        .packets = 0,
    };

    for (__u32 i = 0; i < XDP_MAX_ACTIONS; i++)
    {
        overall.bytes = 0;
        overall.packets = 0;

        if ((bpf_map_lookup_elem(fd, &i, values)) != 0)
        {
            printf("ERR: Failed to lookup map counter for action '%s' err(%d): %s\n",
                   action2str(i), errno, strerror(errno));
            return EXIT_FAIL_XDP_MAP_LOOKUP;
        }

        for (int j = 0; j < num_cpus; j++)
        {
            overall.bytes += values[j].bytes;
            overall.packets += values[j].packets;
        }

        printf("Action '%s':\n\tPackets: %llu\n\tBytes:   %llu Bytes\n\n",
               action2str(i), overall.packets, overall.bytes);
    }

    return EXIT_OK;
}

static int print_action_stats()
{
    int map_fd = open_bpf_map(COUNTER_MAP_PATH);
    if (map_fd < 0)
    {
        return EXIT_FAIL_XDP_MAP_OPEN;
    }
    return get_action_stats(map_fd);
}

static void usage(char *argv[], const char *doc, const struct option long_options[], const char *long_options_descriptions[])
{
    int i;
    printf("%s\n", doc);
    printf("Usage: %s [options]\n\n", argv[0]);
    printf("Options:\n");

    for (i = 0; long_options[i].name != 0; i++)
    {
        printf(" -%c|--%-12s %s\n", long_options[i].val, long_options[i].name,
               long_options_descriptions[i]);
    }
    printf("\n");
}

/*
    This is needed due to getopt's optional_argument parsing:
    https://stackoverflow.com/questions/1052746/getopt-does-not-parse-optional-arguments-to-parameters
*/
bool handle_optional_argument(int argc, char **argv)
{
    if (!optarg && optind < argc && NULL != argv[optind] && '\0' != argv[optind][0] && '-' != argv[optind][0])
    {
        return true;
    }
    return false;
}

static int get_ifindex(const char *raw_ifname)
{
    char ifname_buf[IF_NAMESIZE];
    char *ifname = NULL;

    if (strlen(raw_ifname) >= IF_NAMESIZE)
    {
        printf("ERR: Device name '%s' too long: must be less than %d characters\n",
               raw_ifname, IF_NAMESIZE);
        return -1;
    }
    ifname = (char *)&ifname_buf;
    strncpy(ifname, raw_ifname, IF_NAMESIZE);

    int if_index = if_nametoindex(ifname);
    if (if_index == 0)
    {
        printf("ERR: Device name '%s' not found err(%d): %s\n", raw_ifname, errno,
               strerror(errno));
        return -1;
    }

    return if_index;
}

static int set_rlimit()
{
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};

    if (setrlimit(RLIMIT_MEMLOCK, &r))
    {
        printf("ERR: failed to call setrlimit(RLIMIT_MEMLOCK, RLIM_INFINITY) err(%d): %s\n",
               errno, strerror(errno));
        return EXIT_FAIL_RLIMIT;
    }
    return EXIT_OK;
}


static int handle_action(const char *str_action)
{
    int action = str2action(str_action);
    if (action < 0)
    {
        printf("ERR: Failed to parse the suppled action '%s': must be one of "
               "['XDP_ABORTED', 'XDP_DROP', 'XDP_PASS', 'XDP_TX', 'XDP_REDIRECT'].\n",
               str_action);
        return EXIT_FAIL_OPTIONS;
    }

    int map_fd = open_bpf_map(ACTION_MAP_PATH);
    if (map_fd < 0)
    {
        return EXIT_FAIL_XDP_MAP_OPEN;
    }

    __u32 action_idx = 0;

    if (bpf_map_update_elem(map_fd, &action_idx, &action, 0) != 0)
    {
        printf("ERR: Failed to set specified action '%s' err(%d): %s\n",
               str_action, errno, strerror(errno));
        return EXIT_FAIL_XDP_MAP_UPDATE;
    }
    return EXIT_OK;
}

static int detach(int if_index, char *prog_path)
{
    struct bpf_object *bpf_obj;
    int bpf_prog_fd = -1;
    int ret = 0;

    ret = bpf_prog_load(prog_path, BPF_PROG_TYPE_XDP, &bpf_obj, &bpf_prog_fd);
    if (ret != 0)
    {
        printf("ERR: Unable to load XDP program from file '%s' err(%d): %s\n",
               prog_path, -ret, strerror(-ret));
        return EXIT_FAIL_XDP_DETACH;
    }

    ret = bpf_set_link_xdp_fd(if_index, -1, 0);
    if (ret != 0)
    {
        printf("WARN: Cannont detach XDP program from specified device at index '%d' err(%d): %s\n",
               if_index, -ret, strerror(-ret));
    }

    ret = bpf_object__unpin_maps(bpf_obj, MAP_DIR);
    if (ret != 0)
    {
        printf("WARN: Unable to unpin the XDP program's '%s' maps from '%s' err(%d): %s\n",
               prog_path, MAP_DIR, -ret, strerror(-ret));
    }

    return EXIT_OK;
}

static int load_section(struct bpf_object *bpf_obj, char *section)
{
    struct bpf_program *bpf_prog;

    bpf_prog = bpf_object__find_program_by_title(bpf_obj, section);
    if (bpf_prog == NULL)
    {
        return -EINVAL;
    }

    return bpf_program__fd(bpf_prog);
}

static int attach(int if_index, char *prog_path, char *section)
{
    struct bpf_object *bpf_obj;
    int bpf_prog_fd = -1;
    int ret = 0;

    ret = bpf_prog_load(prog_path, BPF_PROG_TYPE_XDP, &bpf_obj, &bpf_prog_fd);
    if (ret != 0)
    {
        printf("ERR: Unable to load XDP program from file '%s' err(%d): %s\n",
               prog_path, -ret, strerror(-ret));
        return EXIT_FAIL_XDP_ATTACH;
    }

    int section_fd = load_section(bpf_obj, section);
    if (section_fd < 0)
    {
        printf("WARN: Unable to load section '%s' from load bpf object file '%s' err(%d): %s.\n",
               section, prog_path, -section_fd, strerror(-section_fd));
        printf("WARN: Falling back to first program in loaded bpf object file '%s'.\n",
               prog_path);
    }
    else
    {
        bpf_prog_fd = section_fd;
    }

    ret = bpf_set_link_xdp_fd(if_index, bpf_prog_fd, 0);
    if (ret != 0)
    {
        printf("ERR: Unable to attach loaded XDP program to specified device index '%d' err(%d): %s\n",
               if_index, -ret, strerror(-ret));
        return EXIT_FAIL_XDP_ATTACH;
    }

    ret = bpf_object__pin_maps(bpf_obj, MAP_DIR);
    if (ret != 0)
    {
        printf("ERR: Unable to pin the loaded and attached XDP program's maps to '%s' err(%d): %s\n",
               MAP_DIR, -ret, strerror(-ret));
        return EXIT_FAIL_XDP_MAP_PIN;
    }

    return EXIT_OK;
}

int main(int argc, char **argv)
{
    int opt;
    int longindex = 0;

    char *prog_path = NULL;
    char *section = NULL;

    int if_index = -1;

    bool should_detach = false;
    bool should_attach = false;

    char *action = NULL;

    int rlimit_ret = set_rlimit();
    if (rlimit_ret != EXIT_OK)
    {
        return rlimit_ret;
    }

    while ((opt = getopt_long(argc, argv, "hx::n::a:d:se:", long_options, &longindex)) != -1)
    {
        char *tmp_value = optarg;
        switch (opt)
        {
        case 'x':
            if (handle_optional_argument(argc, argv))
            {
                tmp_value = argv[optind++];
                prog_path = alloca(strlen(tmp_value));
                strcpy(prog_path, tmp_value);
            }
            break;
        case 'n':
            if (handle_optional_argument(argc, argv))
            {
                tmp_value = argv[optind++];
                section = alloca(strlen(tmp_value));
                strcpy(section, tmp_value);
            }
            break;
        case 'a':
            if (should_detach)
            {
                printf("ERR: Must not specify both '-a|--attach' and '-d|--detach' "
                       "during the same invocation.\n");
                return EXIT_FAIL_OPTIONS;
            }
            should_attach = true;
            if_index = get_ifindex(optarg);
            if (if_index < 0)
            {
                return EXIT_FAIL_OPTIONS;
            }
            break;
        case 'd':
            if (should_attach)
            {
                printf("ERR: Must not specify both '-a|--attach' and '-d|--detach' "
                       "during the same invocation.\n");
                return EXIT_FAIL_OPTIONS;
            }
            should_detach = true;
            if_index = get_ifindex(optarg);
            if (if_index < 0)
            {
                return EXIT_FAIL_OPTIONS;
            }
            break;
        case 's':
            return print_action_stats();
        case 'e':
            action = alloca(strlen(tmp_value));
            strcpy(action, tmp_value);
            break;
        case 'h':
        default:
            usage(argv, doc, long_options, long_options_descriptions);
            return EXIT_FAIL_OPTIONS;
        }
    }

    if (should_detach)
    {
        return detach(if_index, prog_path == NULL ? default_prog_path : prog_path);
    }

    if (should_attach)
    {
        return attach(if_index, prog_path == NULL ? default_prog_path : prog_path, section == NULL ? default_section : section);
    }

    if (action != NULL)
    {
        return handle_action(action);
    }

    return EXIT_OK;
}
