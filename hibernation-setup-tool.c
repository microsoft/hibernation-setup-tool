// Hibernation Setup Tool
// Sets up a swap area suitable to hibernate a Linux system.
//
// Copyright (c) 2021 Microsoft Corp.
// Licensed under the terms of the MIT license.

#define _GNU_SOURCE

/* sys/mount.h has to be included before linux/fs.h
 * https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=898743
 */
#include <sys/mount.h>

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <linux/falloc.h>
#include <linux/fs.h>
#include <linux/ioctl.h>
#include <linux/magic.h>
#include <linux/suspend_ioctls.h>
#include <mntent.h>
#include <netdb.h> /* struct hostent, gethostbyname */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <spawn.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/swap.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <syscall.h>
#include <syslog.h>
#include <sys/socket.h> /* socket, connect */
#include <unistd.h>

#define MEGA_BYTES (1ul << 20)
#define GIGA_BYTES (1ul << 30)

#ifndef SEEK_HOLE
#define SEEK_HOLE 4
#endif

#ifndef IOPRIO_WHO_PROCESS
#define IOPRIO_WHO_PROCESS 1
#endif

#ifndef IOPRIO_CLASS_IDLE
#define IOPRIO_CLASS_IDLE 3
#endif

#ifndef IOPRIO_PRIO_VALUE
#define IOPRIO_PRIO_VALUE(klass, data) (((klass) << 13) | (data))
#endif

#ifndef XFS_SUPER_MAGIC
#define XFS_SUPER_MAGIC ('X' << 24 | 'F' << 16 | 'S' << 8 | 'B')
#endif

static const char swap_file_name[] = "/hibfile.sys";

/* Prefix is needed when not running as a service.  Output from this the tool is fed to the
 * system log while systemd is processing the request to hibernate.  This makes it easier to
 * grep for hibernation-setup-tool there too in case of a failure. */
static bool log_needs_prefix = false;

/* We don't always want to spam syslog: spamming stdout is fine as this is supposed to be
 * executed as a daemon in systemd and this output will be stored in the journal.  However,
 * this agent can run as a hook and we want to make sure that the messages there are logged
 * somewhere. */
static bool log_needs_syslog = false;

/* This is a link pointing to a file in a tmpfs filesystem and is mostly used to detect
 * if we got a cold boot or not. */
static const char hibernate_lock_file_name[] = "/etc/hibernation-setup-tool.last_hibernation";

enum host_vm_notification {
    HOST_VM_NOTIFY_COLD_BOOT,                /* Sent every time system cold boots */
    HOST_VM_NOTIFY_HIBERNATING,              /* Sent right before hibernation */
    HOST_VM_NOTIFY_RESUMED_FROM_HIBERNATION, /* Sent right after hibernation */
    HOST_VM_NOTIFY_PRE_HIBERNATION_FAILED,   /* Sent on errors when hibernating or resuming */
};

struct swap_file {
    size_t capacity;
    char path[];
};

static int ioprio_set(int which, int who, int ioprio) { return (int)syscall(SYS_ioprio_set, which, who, ioprio); }

static void log_impl(int log_level, const char *fmt, va_list ap)
{
    if (log_needs_syslog)
        vsyslog(log_level, fmt, ap);

    flockfile(stdout);

    if (log_needs_prefix)
        printf("hibernation-setup-tool: ");

    if (log_level == LOG_INFO)
        printf("INFO: ");
    else if (log_level == LOG_ERR)
        printf("ERROR: ");
    vprintf(fmt, ap);
    printf("\n");

    funlockfile(stdout);
}

__attribute__((format(printf, 1, 2))) static void log_info(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    log_impl(LOG_INFO, fmt, ap);
    va_end(ap);
}

__attribute__((format(printf, 1, 2))) __attribute__((noreturn)) static void log_fatal(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    strerror(errno);
    log_impl(LOG_ERR, fmt, ap);
    va_end(ap);

    exit(1);
    __builtin_unreachable();
}

static char *next_field(char *current)
{
    if (!current)
        return NULL;

    if (*current == '\0')
        return NULL;

    while (!isspace(*current))
        current++;

    *current = '\0'; /* 0-terminate the previous call to next_field() */
    current++;       /* skip the NUL terminator */

    while (isspace(*current))
        current++;

    return current;
}

static size_t parse_size_or_die(const char *ptr, const char expected_end, char **endptr)
{
    size_t parsed;

    errno = 0;

    if (sizeof(size_t) == sizeof(unsigned long long)) {
        parsed = strtoull(ptr, endptr, 10);
    } else if (sizeof(size_t) == sizeof(unsigned long)) {
        parsed = strtoul(ptr, endptr, 10);
    } else {
        log_fatal("Invalid size of size_t: %zu", sizeof(size_t));
    }

    if (errno || (endptr && **endptr != expected_end))
        log_fatal("Could not parse size: %s", strerror(errno));

    return parsed;
}

static const char *find_executable_in_path(const char *name, const char *path_env, char path_buf[static PATH_MAX])
{
    if (!path_env)
        path_env = "/bin:/sbin:/usr/bin:/usr/sbin";

    while (*path_env) {
        const char *p = strchr(path_env, ':');
        int ret;

        if (!p) {
            /* Last segment of $PATH */
            ret = snprintf(path_buf, PATH_MAX, "%s/%s", path_env, name);
            path_env = "";
        } else if (p - path_env) {
            /* Middle segments */
            ret = snprintf(path_buf, PATH_MAX, "%.*s/%s", (int)(p - path_env), path_env, name);
            path_env = p + 1;
        } else {
            /* Empty segment or non-root directory? Skip. */
            path_env = p + 1;
            continue;
        }
        if (ret < 0 || ret >= PATH_MAX)
            log_fatal("Building path to determine if %s exists would overflow buffer", name);

        if (path_buf[0] != '/')
            continue;

        if (!access(path_buf, X_OK))
            return path_buf;
    }

    return NULL;
}

static bool is_exec_in_path(const char *name)
{
    char path_buf[PATH_MAX];
    return find_executable_in_path(name, getenv("PATH"), path_buf) != NULL;
}

static struct swap_file *new_swap_file(const char *path, size_t capacity)
{
    struct swap_file *out;

    out = malloc(sizeof(*out) + strlen(path) + 1);
    if (!out)
        log_fatal("Could not allocate memory for swap file information");

    out->capacity = capacity;
    memcpy(out->path, path, strlen(path) + 1);

    return out;
}

static struct swap_file *find_swap_file(size_t needed_size)
{
    char buffer[1024];
    FILE *swaps;
    struct swap_file *out = NULL;

    swaps = fopen("/proc/swaps", "re");
    if (!swaps)
        log_fatal("Could not open /proc/swaps: is /proc mounted?");

    /* Skip first line (header) */
    if (!fgets(buffer, sizeof(buffer), swaps))
        log_fatal("Could not skip first line from /proc/swaps");

    while (fgets(buffer, sizeof(buffer), swaps)) {
        char *filename = buffer;
        char *type = next_field(filename);

        if (!type) {
            log_info("Couldn't get the second field while parsing /proc/swaps");
            break;
        }

        if (!strcmp(type, "file")) {
            char *size = next_field(type);

            if (!size)
                log_fatal("Malformed line in /proc/swaps: can't find size column");

            size_t size_as_int = parse_size_or_die(size, ' ', NULL);
            if (size_as_int < needed_size)
                continue;

            out = new_swap_file(filename, size_as_int);
            break;
        }
    }

    fclose(swaps);

    if (!out) {
        struct stat st;

        if (stat(swap_file_name, &st) < 0)
            return NULL;

        if (!S_ISREG(st.st_mode))
            return NULL;

        return new_swap_file(swap_file_name, st.st_size);
    }

    return out;
}

static size_t physical_memory(void)
{
    FILE *meminfo;
    char buffer[256];
    size_t total = 0;

    meminfo = fopen("/proc/meminfo", "re");
    if (!meminfo)
        log_fatal("Could not determine physical memory size. Is /proc mounted?");

    while (fgets(buffer, sizeof(buffer), meminfo)) {
        static const size_t mem_total_len = sizeof("MemTotal: ") - 1;

        if (!strncmp(buffer, "MemTotal: ", mem_total_len)) {
            char *endptr;

            total = parse_size_or_die(buffer + mem_total_len, ' ', &endptr);

            if (!strcmp(endptr, " kB\n"))
                total *= 1024;
            else if (!strcmp(endptr, " MB\n"))
                total *= MEGA_BYTES;
            else if (!strcmp(endptr, " GB\n"))
                total *= 1024 * MEGA_BYTES;
            else if (!strcmp(endptr, " TB\n"))
                total *= (size_t)MEGA_BYTES * (size_t)MEGA_BYTES;
            else
                log_fatal("Could not determine unit for physical memory information");

            break;
        }
    }

    fclose(meminfo);
    return total;
}

static size_t swap_needed_size(size_t phys_mem)
{
    /* This is using the recommendation from the Fedora project documentation. */
    if (phys_mem <= 2 * GIGA_BYTES)
        return 3 * phys_mem;
    if (phys_mem <= 8 * GIGA_BYTES)
        return 2 * phys_mem;
    if (phys_mem <= 64 * GIGA_BYTES)
        return (3 * phys_mem) / 2;
    /* Note: Fedora documentation doesn't recommend hibernation for machines over 64GB of RAM,
     * but we're extending this for a bit. */
    if (phys_mem <= 256 * GIGA_BYTES)
        return (5 * phys_mem) / 4;
    log_fatal("Hibernation not recommended for a machine with more than 256GB of RAM");
}

static char *get_uuid_for_dev_path(const char *path)
{
    struct stat dev_st;
    struct dirent *ent;
    char *uuid = NULL;
    DIR *uuid_dir;

    if (stat(path, &dev_st) < 0) {
        log_info("Could not stat(%s): %s", path, strerror(errno));
        return NULL;
    }

    uuid_dir = opendir("/dev/disk/by-uuid/");
    if (!uuid_dir) {
        log_info("Could not open directory /dev/disk/by-uuid/: %s", strerror(errno));
        return NULL;
    }

    while ((ent = readdir(uuid_dir))) {
        struct stat ent_st;

        if (fstatat(dirfd(uuid_dir), ent->d_name, &ent_st, 0) < 0)
            continue;

        /* Shouldn't happen, but just in case */
        if ((ent_st.st_mode & S_IFMT) != S_IFBLK)
            continue;

        if (ent_st.st_rdev == dev_st.st_rdev) {
            uuid = strdup(ent->d_name);
            break;
        }
    }

    closedir(uuid_dir);

    if (uuid)
        log_info("UUID for device %s is %s", path, uuid);

    return uuid;
}

static char *get_disk_uuid_for_file_path(const char *path)
{
    FILE *mounts = setmntent("/proc/mounts", "re");
    struct mntent *ent;
    struct stat st;

    if (!mounts)
        return NULL;

    if (stat(path, &st) < 0)
        log_fatal("Could not stat(%s): %s", path, strerror(errno));

    while ((ent = getmntent(mounts))) {
        struct stat ent_st;

        if (stat(ent->mnt_dir, &ent_st) < 0)
            continue;
        if (ent_st.st_dev == st.st_dev)
            break;
    }

    endmntent(mounts);

    if (!ent) {
        log_info("Could not determine device for file in path %s", path);
        return NULL;
    }

    return get_uuid_for_dev_path(ent->mnt_fsname);
}

static long determine_block_size_for_root_fs(void)
{
    FILE *mtab = setmntent("/proc/mounts", "re");
    struct mntent *mntent;
    long sector_size = 0;

    if (!mtab)
        log_fatal("Could not determine mounted partitions. Is /proc mounted?");

    while ((mntent = getmntent(mtab))) {
        if (!strcmp(mntent->mnt_dir, "/")) {
            int fd = open(mntent->mnt_fsname, O_RDONLY | O_CLOEXEC);

            if (fd < 0) {
                log_fatal("Could not open %s to determine block size: %s", mntent->mnt_fsname, strerror(errno));
            }

            if (ioctl(fd, BLKSSZGET, &sector_size) < 0)
                sector_size = 0;

            close(fd);
            break;
        }
    }
    endmntent(mtab);

    if (sector_size) {
        struct statfs sfs;
        if (statfs("/", &sfs) < 0)
            log_fatal("Could not determine optimal block size for root filesystem: %s", strerror(errno));

        return sfs.f_bsize > sector_size ? sfs.f_bsize : sector_size;
    }

    log_fatal("Could not obtain sector size for root partition: %s", strerror(errno));
}

static char *read_first_line_from_file(const char *path, char buffer[static 1024])
{
    FILE *f = fopen(path, "re");

    if (!f)
        return NULL;

    bool did_read = fgets(buffer, 1024, f) != NULL;
    fclose(f);

    if (!did_read)
        return NULL;

    char *lf = strchr(buffer, '\n');
    if (lf)
        *lf = '\0';

    return buffer;
}

static bool is_hyperv(void) { return !access("/sys/bus/vmbus", F_OK); }

static bool is_running_in_container(void)
{
    FILE *cgroup;
    char buffer[1024];
    bool ret = false;

    cgroup = fopen("/proc/1/cgroup", "re");
    if (!cgroup)
        log_fatal("Could not read /proc/1/cgroup to determine if we're running in a container");

    while (fgets(buffer, sizeof(buffer), cgroup)) {
        const char *first_colon = strchr(buffer, ':');

        if (!first_colon)
            continue;

        /* When running in a container, PID 1 will have a line in
         * /proc/1/cgroup with "0::/" as a content; whereas, when running in
         * the host, it might have something like "0::/init.slice".
         *
         * Things might be different with anything other than systemd, but
         * since we're supporting systemd-only distros at this point, it's
         * safer to use this method rather than rely on things like the
         * presence of /.dockerenv or something like that as the container
         * runtime not be docker.  */
        if (!strcmp(first_colon, "::/\n")) {
            ret = true;
            break;
        }
    }

    fclose(cgroup);

    return ret;
}

static bool is_hibernation_enabled_for_vm(void)
{
    char buffer[1024];
    char *entry;

    if (is_running_in_container()) {
        log_info("We're running in a container; this isn't supported.");
        return false;
    }

    if (access("/dev/snapshot", F_OK) != 0) {
        log_info("Kernel does not support hibernation or /dev/snapshot has not been found.");
        return false;
    }

    /* First, check if the kernel can hibernate.  Don't even bother if the
     * interface to hibernate it isn't available.  */
    entry = read_first_line_from_file("/sys/power/disk", buffer);
    if (!entry) {
        log_info("Kernel does not support hibernation (/sys/power/disk does not exist or can't be read).");
        return false;
    }
    if (strstr(entry, "platform")) {
        log_info("VM supports hibernation with platform-supported events.");
        return true;
    }
    if (strstr(entry, "shutdown")) {
        log_info("VM supports hibernation only with the shutdown method. This is not ideal.");
    } else if (strstr(entry, "suspend")) {
        log_info("VM supports hibernation only with the suspend method. This is not ideal.");
    } else {
        log_info("Unknown VM hibernation support mode found: %s", entry);
        return false;
    }

    if (is_hyperv()) {
        log_info("This is a Hyper-V VM, checking if hibernation is enabled through VMBus events.");
        entry = read_first_line_from_file("/sys/bus/vmbus/hibernation", buffer);
        if (entry) {
            if (!strcmp(entry, "1")) {
                log_info("Hibernation is enabled according to VMBus. This is ideal.");
                return true;
            }

            log_info("Hibernation is disabled according to VMBus.");
        }
    }

    log_info("Even though VM is capable of hibernation, it seems to be disabled.");
    return false;
}

static bool is_hibernation_allowed_for_vm(void)
{   
    /* first where are we going to send it? */
    int portno = 80;
    char *host = "169.254.169.254";
    char *request = "GET /metadata/instance/compute/additionalCapabilities?api-version=2021-11-01 HTTP/1.1\r\nAccept: */*\r\nMetadata:true\r\n";

    struct hostent *server;
    struct sockaddr_in serv_addr;
    int sockfd, bytes, sent, received, total;
    char response[4096];
    
    /* What are we going to send? */
    log_info("Request:\n%s\n",request);

    /* create the socket */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) 
    {
        perror("ERROR opening socket");
        return false;
    }

    struct timeval timeout;      
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
    
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout) < 0 || 
        setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout) < 0)
    {
        perror("ERROR, unable to set timeouts for socket");
        return false;
    }

    /* lookup the ip address */
    server = gethostbyname(host);
    if (server == NULL) 
    {
        perror("ERROR, no such host");
        return false;
    }

    /* fill in the structure */
    memset(&serv_addr,0,sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(portno);
    memcpy(&serv_addr.sin_addr.s_addr,server->h_addr,server->h_length);

    /* connect the socket */
    if (connect(sockfd,(struct sockaddr *)&serv_addr,sizeof(serv_addr)) < 0)
    {
        perror("ERROR connecting");
        return false;
    }

    /* send the request */
    total = strlen(request);
    sent = 0;
    do {
        bytes = write(sockfd,request+sent,total-sent);
        if (bytes < 0)
        {
            perror("ERROR writing message to socket");
            return false;
        }
        if (bytes == 0)
            break;
        sent+=bytes;
    } while (sent < total);

    /* receive the response */
    memset(response,0,sizeof(response));
    total = sizeof(response)-1;
    received = 0;
    do {
        bytes = read(sockfd,response+received,total-received);
        if (bytes < 0)
        {
            perror("ERROR reading response from socket");
            return false;
        }
        if (bytes == 0)
            break;
        received+=bytes;
    } while (received < total);

    /*
     * if the number of received bytes is the total size of the
     * array then we have run out of space to store the response
     * and it hasn't all arrived yet - so that's a bad thing
     */
    if (received == total)
        perror("ERROR storing complete response from socket");

    /* close the socket */
    close(sockfd);

    /* process response */
    log_info("Response:\n%s\n",response);
    return false;
}

static uint32_t get_swap_file_offset(int fd)
{
    uint32_t blksize;

    if (ioctl(fd, FIGETBSZ, &blksize) < 0)
        log_fatal("Could not get file block size: %s", strerror(errno));

    uint32_t last = 0, first = 0, num_contiguous_blocks = 0;
    uint32_t blocks_per_page = sysconf(_SC_PAGE_SIZE) / blksize;
    uint32_t first_blknum = ~0;
    for (uint32_t i = 0; i < blocks_per_page; i++) {
        uint32_t blknum = i;

        if (ioctl(fd, FIBMAP, &blknum) < 0)
            log_fatal("Could not get filesystem block number for block #%d: %s", i, strerror(errno));

        if (i == 0)
            first_blknum = blknum;

        if (last && blknum - last != 1) {
            /* If we find a block that's not contiguous, bail out.  We
             * check below if we have enough contiguous blocks for hibernation
             * to work. */
            break;
        }

        if (!first)
            first = blknum;

        last = blknum;
        num_contiguous_blocks++;
    }

    log_info("First %d blocks of %d bytes are contiguous", num_contiguous_blocks, blksize);

    if (num_contiguous_blocks * blksize >= sysconf(_SC_PAGE_SIZE))
        return first_blknum;

    return ~0;
}

static bool try_zero_out_with_write(const char *path, off_t needed_size)
{
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    int ret = true;

    if (fd < 0) {
        log_info("Could not open %s: %s", path, strerror(errno));
        return false;
    }

    long block_size = determine_block_size_for_root_fs();
    const uint32_t pattern = 'T' << 24 | 'F' << 16 | 'S' << 8 | 'M';
    for (off_t offset = 0; offset < needed_size; offset += block_size) {
        ssize_t written = pwrite(fd, &pattern, sizeof(pattern), offset);

        if (written < 0) {
            log_info("Could not write pattern to %s: %s", path, strerror(errno));
            ret = false;
            goto out;
        }
    }

    fdatasync(fd);
out:
    close(fd);

    return ret;
}

static bool fs_set_flags(int fd, int flags_to_set, int flags_to_reset)
{
    int current_flags;

    if (ioctl(fd, FS_IOC_GETFLAGS, &current_flags) < 0)
        return false;

    current_flags |= flags_to_set;
    current_flags &= ~flags_to_reset;

    if (ioctl(fd, FS_IOC_SETFLAGS, &current_flags) < 0)
        return false;

    return true;
}

static bool is_file_on_fs(const char *path, __fsword_t magic)
{
    struct statfs stfs;

    if (!statfs(path, &stfs))
        return stfs.f_type == magic;

    return false;
}

static bool create_swap_file_with_size(const char *path, off_t size)
{
    int fd = open(path, O_CLOEXEC | O_WRONLY | O_CREAT, 0600);
    int rc;

    if (fd < 0)
        return false;

    /* Disabling CoW is necessary on btrfs filesystems, but issue the
     * ioctl regardless of the filesystem just in case.
     * More information: https://wiki.archlinux.org/index.php/btrfs#Swap_file
     */
    if (!fs_set_flags(fd, FS_NOCOW_FL, 0)) {
        /* Some filesystems don't support CoW (EXT4 for instance), so don't bother
         * giving an error message in those cases. */
        if (errno != EOPNOTSUPP)
            log_info("Could not disable CoW for %s: %s. Will try setting up swap anyway.", path, strerror(errno));
    }
    /* Disable compression, too. */
    if (!fs_set_flags(fd, FS_NOCOMP_FL, FS_COMPR_FL)) {
        /* Compression is optional, too, so don't bother giving an error message in
         * case the filesystem doesn't support it. */
        if (errno != EOPNOTSUPP)
            log_info("Could not disable compression for %s: %s. Will try setting up swap anyway.", path, strerror(errno));
    }

    if (is_file_on_fs(path, XFS_SUPER_MAGIC)) {
        rc = 0;
    } else {
        rc = ftruncate(fd, size);
        if (rc < 0) {
            if (errno == EPERM) {
                log_info("Not enough disk space to create %s with %zu MB.", path, size / MEGA_BYTES);
            } else {
                log_info("Could not resize %s to %ld MB: %s", path, size / MEGA_BYTES, strerror(errno));
            }
        }
    }

    close(fd);

    return rc == 0;
}

static bool try_zeroing_out_with_fallocate(const char *path, off_t size)
{
    int fd = open(path, O_CLOEXEC | O_WRONLY);

    if (fd < 0) {
        log_info("Could not open %s for writing: %s", path, strerror(errno));
        return false;
    }

    if (fallocate(fd, 0, 0, size) < 0) {
        if (errno == ENOSPC) {
            log_fatal("System ran out of disk space while allocating hibernation file. It needs %zd MiB", size / MEGA_BYTES);
        } else {
            log_fatal("Could not allocate %s: %s", path, strerror(errno));
        }
    }

    close(fd);

    return true;
}

static bool try_vspawn_and_wait(const char *program, int n_args, va_list ap)
{
    pid_t pid;
    int rc;
    char **argv;

    argv = calloc(n_args + 2, sizeof(char *));
    if (!argv) {
        log_info("Couldn't allocate memory for argument array");
        return false;
    }

    argv[0] = (char *)program;
    for (int i = 1; i <= n_args; i++)
        argv[i] = va_arg(ap, char *);

    rc = posix_spawnp(&pid, program, NULL, NULL, argv, NULL);

    free(argv);

    if (rc != 0) {
        log_info("Could not spawn %s: %s", program, strerror(rc));
        return false;
    }

    log_info("Waiting for %s (pid %d) to finish.", program, pid);

    int wstatus;
    if (waitpid(pid, &wstatus, 0) != pid) {
        log_info("Couldn't wait for %s: %s", program, strerror(errno));
        return false;
    }
    if (!WIFEXITED(wstatus)) {
        log_info("%s ended abnormally: %s", program, strerror(errno));
        return false;
    }
    if (WEXITSTATUS(wstatus) == 127) {
        log_info("Failed to spawn %s", program);
        return false;
    }
    if (WEXITSTATUS(wstatus) != 0) {
        log_info("%s ended with unexpected exit code %d", program, WEXITSTATUS(wstatus));
        return false;
    }

    log_info("%s finished successfully.", program);
    return true;
}

static bool try_spawn_and_wait(const char *program, int n_args, ...)
{
    va_list ap;
    bool spawned;

    va_start(ap, n_args);
    spawned = try_vspawn_and_wait(program, n_args, ap);
    va_end(ap);

    return spawned;
}

static void spawn_and_wait(const char *program, int n_args, ...)
{
    va_list ap;
    bool spawned;

    va_start(ap, n_args);
    spawned = try_vspawn_and_wait(program, n_args, ap);
    va_end(ap);

    if (!spawned)
        log_fatal("Aborting program due to error condition when spawning %s", program);
}

static void perform_fs_specific_checks(const char *path)
{
    if (is_file_on_fs(path, EXT4_SUPER_MAGIC) && is_exec_in_path("e4defrag")) {
        try_spawn_and_wait("e4defrag", 1, path);
        return;
    }

    if (is_file_on_fs(path, BTRFS_SUPER_MAGIC)) {
        struct utsname utsbuf;

        if (uname(&utsbuf) < 0)
            log_fatal("Could not determine Linux kernel version: %s", strerror(errno));
        if (utsbuf.release[1] != '.')
            log_fatal("Could not parse Linux kernel version");
        if (utsbuf.release[0] < '5')
            log_fatal("Swap files are not supported on Btrfs running on kernel %s", utsbuf.release);

        if (is_exec_in_path("btrfs"))
            try_spawn_and_wait("btrfs", 3, "filesystem", "defragment", path);
        return;
    }

    if (is_file_on_fs(path, XFS_SUPER_MAGIC) && is_exec_in_path("xfs_fsr")) {
        try_spawn_and_wait("xfs_fsr", 2, "-v", path);
        return;
    }
}

bool is_kernel_version_at_least(const char *version)
{
    struct utsname my_uname;
    if (uname(&my_uname) == -1) {
        log_info("uname call failed.");
        return true;
    }
    unsigned sys_major_version = 0, sys_minor_version = 0;
    unsigned req_major_version = 0, req_minor_version = 0;
    sscanf(my_uname.release, "%u.%u", &sys_major_version, &sys_minor_version);
    sscanf(version, "%u.%u", &req_major_version, &req_minor_version);
    uint64_t sys_version = sys_major_version * 10000 + sys_minor_version;
    uint64_t req_version = req_major_version * 10000 + req_minor_version;
    return sys_version >= req_version;
}

static struct swap_file *create_swap_file(size_t needed_size)
{
    log_info("Creating hibernation file at %s with %zu MB.", swap_file_name, needed_size / MEGA_BYTES);

    if (!create_swap_file_with_size(swap_file_name, needed_size))
        log_fatal("Could not create swap file, aborting.");

    /* Allocate the swap file with the lowest I/O priority possible to not thrash workload */
    ioprio_set(IOPRIO_WHO_PROCESS, 0, IOPRIO_PRIO_VALUE(IOPRIO_CLASS_IDLE, 7));

    log_info("Ensuring %s has no holes in it.", swap_file_name);

    /* Preallocated swap files are supported on xfs since Linux 4.18. So using fallocate for XFS if system version is higher than 4.18 */
    bool swap_on_xfs = is_file_on_fs(swap_file_name, XFS_SUPER_MAGIC) && !is_kernel_version_at_least("4.18");
    if (swap_on_xfs || !try_zeroing_out_with_fallocate(swap_file_name, needed_size)) {
        if (swap_on_xfs)
            log_info("Root partition is in a XFS filesystem and kernel version is older than 4.18. Need to use slower method to allocate swap file");
        else
            log_info("Fast method failed; trying a slower method.");

        if (!try_zero_out_with_write(swap_file_name, needed_size))
            log_fatal("Could not create swap file.");
    }
    perform_fs_specific_checks(swap_file_name);

    spawn_and_wait("mkswap", 1, swap_file_name);

    struct swap_file *ret = malloc(sizeof(*ret) + sizeof(swap_file_name));
    if (!ret)
        log_fatal("Could not allocate memory to represent a swap file: %s", strerror(errno));

    ret->capacity = needed_size;
    memcpy(ret->path, swap_file_name, sizeof(swap_file_name));
    return ret;
}

static bool is_kernel_cmdline_correct(const char *dev_uuid, off_t resume_offset)
{
    char buffer[1024];

    char *line = read_first_line_from_file("/proc/cmdline", buffer);
    if (!line) {
        log_info("Could not read /proc/cmdline; is /proc mounted? Assuming information is incorrect.");
        return false;
    }

    char *resume_field = NULL;
    char *resume_offset_field = NULL;
    char *no_console_suspend_field = NULL;
    for (char *field = line; field; field = next_field(field)) {
        if (!strncmp(field, "resume=", sizeof("resume=") - 1))
            resume_field = field + sizeof("resume=") - 1;
        else if (!strncmp(field, "resume_offset=", sizeof("resume_offset=") - 1))
            resume_offset_field = field + sizeof("resume_offset=") - 1;
        else if (!strncmp(field, "no_console_suspend=", sizeof("no_console_suspend=") - 1))
            no_console_suspend_field = field + sizeof("no_console_suspend=") - 1;
    }

    if (!resume_field)
        return false;
    if (!resume_offset_field)
        return false;
    if (!no_console_suspend_field)
        return false;

    char full_dev_path[PATH_MAX];
    int r = snprintf(full_dev_path, PATH_MAX, "/dev/disk/by-uuid/%s", dev_uuid);
    if (r < 0 || r >= PATH_MAX)
        return false;
    if (strcmp(resume_field, full_dev_path) != 0)
        return false;

    char offset_buf[3 * sizeof(size_t)];
    snprintf(offset_buf, sizeof(offset_buf), "%zd", resume_offset);
    if (strcmp(offset_buf, resume_offset_field) != 0)
        return false;

    if (strcmp(no_console_suspend_field, "1") != 0)
        return false;

    return true;
}

static struct resume_swap_area get_swap_area(const struct swap_file *swap)
{
    int fd = open(swap->path, O_RDONLY | O_CLOEXEC);
    struct stat st;

    if (fd < 0)
        log_fatal("Could not open %s: %s", swap->path, strerror(errno));

    if (fstat(fd, &st) < 0)
        log_fatal("Could not stat %s: %s", swap->path, strerror(errno));

    if (!S_ISREG(st.st_mode))
        log_fatal("Swap file %s is not a regular file", swap->path);

    uint32_t offset = get_swap_file_offset(fd);
    if (offset == ~0u)
        log_fatal("Could not determine file system block number for %s, or file isn't contiguous", swap->path);

    close(fd);

    log_info("Swap file %s is at device %ld, offset %d", swap->path, st.st_dev, offset);

    return (struct resume_swap_area){
        .offset = offset,
        .dev = st.st_dev,
    };
}

static const char *find_grub_cfg_path(void)
{
    static const char *possible_paths[] = {"/boot/grub2/grub.cfg", "/boot/grub/grub.cfg", NULL};

    for (int i = 0; possible_paths[i]; i++) {
        if (!access(possible_paths[i], F_OK))
            return possible_paths[i];
    }

    log_info("Could not find GRUB configuration file. Is /boot mounted?");
    return NULL;
}

static bool is_directory_empty(const char *path)
{
    DIR *dir = opendir(path);
    struct dirent *ent;
    bool has_file = false;

    if (!dir)
        return true;

    while ((ent = readdir(dir))) {
        if (!strcmp(ent->d_name, "."))
            continue;
        if (!strcmp(ent->d_name, ".."))
            continue;
        has_file = true;
        break;
    }

    closedir(dir);

    return !has_file;
}

static bool update_kernel_cmdline_params_for_grub(
    const char *dev_uuid, const struct resume_swap_area swap_area, bool has_grubby, bool has_update_grub2, bool has_grub2_mkconfig)
{
    bool ret_value = true;

    /* Doc:
     * https://docs.fedoraproject.org/en-US/fedora/rawhide/system-administrators-guide/kernel-module-driver-configuration/Working_with_the_GRUB_2_Boot_Loader/#sec-Making_Persistent_Changes_to_a_GRUB_2_Menu_Using_the_grubby_Tool
     */
    log_info("Kernel command line is missing parameters to resume from hibernation.  Trying to patch grub configuration file.");

    char *args;
    if (asprintf(&args, "resume=/dev/disk/by-uuid/%s resume_offset=%lld no_console_suspend=1", dev_uuid, swap_area.offset) < 0) {
        log_info("Could not allocate memory for kernel argument");
        return false;
    }

    /* Updating initramfs to include resume config changes in boot process, varies by distro. update-initramfs command works
     * for Ubuntu, Debian whereas dracut is a tool to build initramfs archives on RHEL, CentOS */
    if (is_exec_in_path("update-initramfs")) {
        log_info("Updating initramfs to include resume stuff");

        FILE *conf = fopen("/etc/initramfs-tools/conf.d/resume", "we");
        if (!conf)
            log_fatal("Could not open initramfs-tools configuration file: %s", strerror(errno));

        fprintf(conf, "# Updated automatically by hibernation-setup-tool. Do not modify.\n");
        fprintf(conf, "RESUME=UUID=%s\n", dev_uuid);
        fclose(conf);
        spawn_and_wait("update-initramfs", 1, "-u");
    } else if (is_exec_in_path("dracut")) {
        log_info("Updating initramfs(dracut) to include resume stuff");

        FILE *conf = fopen("/etc/dracut.conf.d/resume.conf", "we");
        if (!conf)
            log_fatal("Could not open initramfs-tools configuration file: %s", strerror(errno));

        fprintf(conf, "# Updated automatically by hibernation-setup-tool. Do not modify.\n");
        fprintf(conf, "add_dracutmodules+=\" resume \"");
        fclose(conf);
        spawn_and_wait("dracut", 1, "-f");
    }

    if (has_grubby) {
        log_info("Using grubby to patch GRUB configuration");
        spawn_and_wait("grubby", 3, "--update-kernel=ALL", "--args", args);
    } else if (has_update_grub2 || has_grub2_mkconfig) {
        FILE *resume_cfg;
        char *old_contents = NULL;
        const char *grub_cfg_path;
        size_t old_contents_len = 0;
        char buffer[1024];

        if (!is_directory_empty("/etc/default/grub.d")) {
            /* If we find this directory, it might be possible that some of the configuration
             * files there will override GRUB_CMDLINE_LINUX_DEFAULT.  This seems to be the case
             * in some Azure Marketplace images, with files such as "50-cloudimg-settings.cfg".
             * If we find the directory, assume we can create our own with higher priority
             * instead of modifying the global configuration file. */
            grub_cfg_path = "/etc/default/grub.d/99-hibernate-settings.cfg";
        } else if (!access("/etc/default/grub", F_OK)) {
            grub_cfg_path = "/etc/default/grub";
        } else {
            log_fatal("Could not determine where the Grub configuration file is");
        }

        resume_cfg = fopen(grub_cfg_path, "re");
        if (resume_cfg) {
            bool in_az_hibernate_agent_block = false;
            while (fgets(buffer, sizeof(buffer), resume_cfg)) {
                if (in_az_hibernate_agent_block) {
                    if (strstr(buffer, "# hibernation-setup-tool:end"))
                        in_az_hibernate_agent_block = false;
                    continue;
                }

                if (strstr(buffer, "# hibernation-setup-tool:start")) {
                    in_az_hibernate_agent_block = true;
                    continue;
                }

                size_t buflen = strlen(buffer);
                char *tmp = realloc(old_contents, old_contents_len + buflen + 1);
                if (!tmp)
                    log_fatal("Could not allocate memory: %s", strerror(errno));

                memcpy(tmp + old_contents_len, buffer, buflen + 1);
                old_contents_len += buflen;
                old_contents = tmp;
            }

            fclose(resume_cfg);
        }

        resume_cfg = fopen(grub_cfg_path, "we");
        if (!resume_cfg)
            log_fatal("Could not open %s for writing: %s", grub_cfg_path, strerror(errno));

        if (old_contents) {
            fwrite(old_contents, old_contents_len, 1, resume_cfg);
            free(old_contents);
        }

        fprintf(resume_cfg, "\n# hibernation-setup-tool:start\n");
        fprintf(resume_cfg, "GRUB_CMDLINE_LINUX_DEFAULT=\"$GRUB_CMDLINE_LINUX_DEFAULT %s\"\n", args);
        fprintf(resume_cfg, "unset GRUB_FORCE_PARTUUID\n");
        fprintf(resume_cfg, "# hibernation-setup-tool:end\n");

        fclose(resume_cfg);

        if (has_update_grub2) {
            log_info("Using update-grub2 to patch GRUB configuration in %s", grub_cfg_path);
            spawn_and_wait("update-grub2", 0);
        } else if (has_grub2_mkconfig) {
            const char *grub_cfg_path = find_grub_cfg_path();

            if (!grub_cfg_path) {
                ret_value = false;
            } else {
                log_info("Using grub2-mkconfig to patch GRUB configuration in %s", grub_cfg_path);
                spawn_and_wait("grub2-mkconfig", 2, "-o", grub_cfg_path);
            }
        }
    }

    free(args);

    return ret_value;
}

static bool update_swap_offset(const struct swap_file *swap)
{
    bool ret = true;

    log_info("Updating swap offset");

    int fd = open("/dev/snapshot", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        log_info("Could not open /dev/snapshot: %s", strerror(errno));
        return false;
    }

    struct resume_swap_area swap_area = get_swap_area(swap);
    if (ioctl(fd, SNAPSHOT_SET_SWAP_AREA, &swap_area) < 0) {
        log_info("Could not set resume_swap_area parameters in /dev/snapshot: %s", strerror(errno));
        close(fd);
        return false;
    }

    close(fd);

    char *dev_uuid = get_disk_uuid_for_file_path(swap->path);

    if (!dev_uuid)
        log_fatal("Could not determine device UUID for swap file %s", swap->path);

    log_info("Swap file %s is in device UUID %s", swap->path, dev_uuid);

    if (!is_kernel_cmdline_correct(dev_uuid, swap_area.offset)) {
        log_info("Kernel command-line parameters need updating.");

        bool has_grubby = is_exec_in_path("grubby");
        bool has_update_grub2 = is_exec_in_path("update-grub2");
        bool has_grub2_mkconfig = is_exec_in_path("grub2-mkconfig");
        if (has_grubby || has_update_grub2 || has_grub2_mkconfig) {
            ret = update_kernel_cmdline_params_for_grub(dev_uuid, swap_area, has_grubby, has_update_grub2, has_grub2_mkconfig);
        } else {
            log_info(
                "Could not determine how system was booted to update kernel parameters for next boot.  System won't be able to resume until you fix this.");
            ret = false;
        }
    }

    free(dev_uuid);
    return ret;
}

static void ensure_swap_is_enabled(const struct swap_file *swap, bool created)
{
    FILE *fstab;
    char *old_contents = NULL;
    size_t old_contents_len = 0;
    char buffer[1024];

    log_info("Ensuring swap file %s is enabled", swap->path);

    if (chmod(swap->path, 0600) < 0)
        log_fatal("Couldn't set correct permissions on %s: %s", swap->path, strerror(errno));

    if (swapon(swap->path, 0) < 0) {
        if (errno == EINVAL && !created)
            log_fatal("%s exists but kernel isn't accepting it as a swap file. Try removing it and re-running the agent.", swap->path);

        if (errno != EBUSY)
            log_fatal("Could not enable swap file: %s", strerror(errno));
    }

    log_info("Updating /etc/fstab");

    fstab = fopen("/etc/fstab", "re");
    if (!fstab)
        log_fatal("Could not open fstab: %s", strerror(errno));

    while (fgets(buffer, sizeof(buffer), fstab)) {
        if (strstr(buffer, swap->path))
            continue;

        size_t buflen = strlen(buffer);
        char *tmp = realloc(old_contents, old_contents_len + buflen + 1);

        if (!tmp)
            log_fatal("Couldn't allocate memory");

        memcpy(tmp + old_contents_len, buffer, buflen + 1);
        old_contents_len += buflen;
        old_contents = tmp;
    }

    fclose(fstab);

    fstab = fopen("/etc/fstab", "we");
    if (!fstab)
        log_fatal("Could not open fstab for writing: %s", strerror(errno));

    if (old_contents) {
        fwrite(old_contents, old_contents_len, 1, fstab);
        free(old_contents);
    }
    fprintf(fstab, "\n%s\tnone\tswap\tswap\t0\t0\n", swap->path);

    fclose(fstab);
}

static void ensure_udev_rules_are_installed(void)
{
    char systemctl_path_buf[PATH_MAX];
    const char *udev_rule_path;
    const char *systemctl_path;

    systemctl_path = find_executable_in_path("systemctl", NULL, systemctl_path_buf);
    if (!systemctl_path) {
        log_info("systemctl not found or not executable, udev rule won't work");
        return;
    }
    if (!is_exec_in_path("udevadm")) {
        log_info("udevadm has not been found in $PATH; maybe system doesn't use systemd?");
        return;
    }

    if (!access("/usr/lib/udev/rules.d", F_OK)) {
        udev_rule_path = "/usr/lib/udev/rules.d/99-vm-hibernation.rules";
    } else if (!access("/etc/udev/rules.d", F_OK)) {
        udev_rule_path = "/etc/udev/rules.d/99-vm-hibernation.rules";
    } else if (!access("/lib/udev/rules.d", F_OK)) {
        udev_rule_path = "/lib/udev/rules.d/99-vm-hibernation.rules";
    } else {
        log_info("Couldn't find where udev stores the rules.  VM may not hibernate.");
        return;
    }

    FILE *rule_file = fopen(udev_rule_path, "we");
    if (!rule_file)
        log_fatal("Could not open '%s' for writing: %s", udev_rule_path, strerror(errno));
    fprintf(rule_file,
            "SUBSYSTEM==\"vmbus\", ACTION==\"change\", "
            "DRIVER==\"hv_utils\", ENV{EVENT}==\"hibernate\", "
            "RUN+=\"%s hibernate\"\n",
            systemctl_path);
    fclose(rule_file);

    log_info("udev rule to hibernate with systemd set up in %s.  Telling udev about it.", udev_rule_path);

    /* This isn't strictly necessary, but do it anyway just in case. */
    spawn_and_wait("udevadm", 2, "control", "--reload-rules");
    spawn_and_wait("udevadm", 1, "trigger");
}

static const char *readlink0(const char *path, char buf[static PATH_MAX])
{
    ssize_t len = readlink(path, buf, PATH_MAX - 1);

    if (len < 0)
        return NULL;

    buf[len] = '\0';
    return buf;
}

static bool is_cold_boot(void)
{
    /* We detect cold boot by creating a file in a tmpfs filesystem right
     * before asking system to hibernate.  If this file is not there during
     * agent startup, then it's a cold boot and resuming failed; if it's
     * still there, then we successfully resumed.  */
    char lock_file_path_buf[PATH_MAX];
    const char *lock_file_path;

    lock_file_path = readlink0(hibernate_lock_file_name, lock_file_path_buf);
    if (lock_file_path) {
        unlink(hibernate_lock_file_name);

        if (access(lock_file_path, F_OK) < 0)
            return true;

        unlink(lock_file_path);
    }

    return false;
}

static void notify_vm_host(enum host_vm_notification notification)
{
    static const char *types[] = {
        [HOST_VM_NOTIFY_COLD_BOOT] = "cold-boot",
        [HOST_VM_NOTIFY_HIBERNATING] = "hibernating",
        [HOST_VM_NOTIFY_RESUMED_FROM_HIBERNATION] = "resumed-from-hibernation",
        [HOST_VM_NOTIFY_PRE_HIBERNATION_FAILED] = "pre-hibernation-failed",
    };

    log_info("Changed hibernation state to: %s", types[notification]);
}

static int recursive_rmdir_cb(const char *fpath, const struct stat *st, int typeflag, struct FTW *ftwbuf)
{
    (void)st;
    (void)ftwbuf;

    switch (typeflag) {
    case FTW_SLN: /* symbolic link pointing to a non-existing file */
    case FTW_F:   /* regular file */
        return unlink(fpath) == 0 ? FTW_CONTINUE : FTW_STOP;

    case FTW_D: /* directory */
        return rmdir(fpath) == 0 ? FTW_CONTINUE : FTW_STOP;

    case FTW_SL:
        /* We refuse to follow symbolic links as it might lead us to some directory outside
         * the one we're trying to remove.  The only symlinks we care about are those that
         * point to a path that does not exist, but we delete those before doing anything
         * anyway. */
        log_info("%s is a symbolic link. Refusing to follow.", fpath);
        return FTW_STOP;

    case FTW_DNR:
        log_info("Can't read directory %s", fpath);
        return FTW_STOP;

    case FTW_NS:
        log_info("stat() failed on %s", fpath);
        return FTW_STOP;

    default:
        log_info("nftw callback called with unknown typeflag %d, stopping", typeflag);
        return FTW_STOP;
    }
}

static bool recursive_rmdir(const char *path) { return nftw(path, recursive_rmdir_cb, 16, FTW_DEPTH | FTW_PHYS | FTW_ACTIONRETVAL) != FTW_STOP; }

static int handle_pre_systemd_suspend_notification(const char *action)
{
    if (!strcmp(action, "hibernate")) {
        log_info("Running pre-hibernate hooks");

        /* Creating this directory with the right permissions is racy as
         * we're writing to tmp which is world-writable.  So do our best
         * here to ensure that if this for loop terminates normally, the
         * directory is empty and readable/writable only by us.  In normal
         * scenarios (i.e. nobody else tried creating a directory with that
         * name), this will succeed the first try.  This directory will be
         * removed when we resume. */
        for (int try = 0;; try++) {
            if (try > 10) {
                notify_vm_host(HOST_VM_NOTIFY_PRE_HIBERNATION_FAILED);
                log_fatal("Tried too many times to create /tmp/hibernation-setup-tool and failed. Giving up");
            }

            if (!mkdir("/tmp/hibernation-setup-tool", 0700))
                break;
            if (errno != EEXIST) {
                notify_vm_host(HOST_VM_NOTIFY_PRE_HIBERNATION_FAILED);
                log_fatal("Couldn't create location to store hibernation agent state: %s", strerror(errno));
            }

            struct stat st;
            if (!stat("/tmp/hibernation-setup-tool", &st)) {
                if (S_ISDIR(st.st_mode)) {
                    log_info("/tmp/hibernation-setup-tool exists, removing it");

                    if (umount2("/tmp/hibernation-setup-tool", UMOUNT_NOFOLLOW | MNT_DETACH) < 0) {
                        /* See comment related to the umount2() call in handle_post_systemd_suspend_notification(). */
                        if (errno != EINVAL)
                            log_fatal("Error while unmounting /tmp/hibernation-setup-tool: %s", strerror(errno));
                    }

                    if (recursive_rmdir("/tmp/hibernation-setup-tool"))
                        continue;

                    notify_vm_host(HOST_VM_NOTIFY_PRE_HIBERNATION_FAILED);
                    log_fatal("Couldn't remove /tmp/hibernation-setup-tool directory before proceeding");
                }

                log_info("/tmp/hibernation-setup-tool exists and isn't a directory! Removing it and trying again (try %d)", try);

                if (!unlink("/tmp/hibernation-setup-tool"))
                    continue;

                notify_vm_host(HOST_VM_NOTIFY_PRE_HIBERNATION_FAILED);
                log_fatal("Couldn't remove the file: %s, giving up", strerror(errno));
            }

            log_info("/tmp/hibernation-setup-tool couldn't be found but mkdir() told us it exists, trying again (try %d)", try);
            continue;
        }

        if (!is_file_on_fs("/tmp/hibernation-setup-tool", TMPFS_MAGIC)) {
            log_info("/tmp isn't a tmpfs filesystem; trying to mount /tmp/hibernation-setup-tool as such");

            if (mount("tmpfs", "/tmp/hibernation-setup-tool", "tmpfs", 0, NULL) < 0) {
                notify_vm_host(HOST_VM_NOTIFY_PRE_HIBERNATION_FAILED);
                log_fatal("Couldn't mount temporary filesystem: %s. We need this to detect cold boots!", strerror(errno));
            }
        }

        char pattern[] = "/tmp/hibernation-setup-tool/hibernatedXXXXXX";
        int fd = mkostemp(pattern, O_CLOEXEC);
        if (fd < 0) {
            notify_vm_host(HOST_VM_NOTIFY_PRE_HIBERNATION_FAILED);
            log_fatal("Couldn't create a temporary file: %s", strerror(errno));
        }
        close(fd);

        if (unlink(hibernate_lock_file_name) < 0) {
            if (errno != EEXIST) {
                notify_vm_host(HOST_VM_NOTIFY_PRE_HIBERNATION_FAILED);
                log_fatal("Couldn't remove %s: %s", hibernate_lock_file_name, strerror(errno));
            }
        }
        if (link(pattern, hibernate_lock_file_name) < 0) {
            notify_vm_host(HOST_VM_NOTIFY_PRE_HIBERNATION_FAILED);
            log_fatal("Couldn't link %s to %s: %s", pattern, hibernate_lock_file_name, strerror(errno));
        }

        notify_vm_host(HOST_VM_NOTIFY_HIBERNATING);
        log_info("Pre-hibernation hooks executed successfully");

        return 0;
    }

    log_fatal("Can't handle `pre %s' notifications", action);
    return 1;
}

static int handle_post_systemd_suspend_notification(const char *action)
{
    if (!strcmp(action, "hibernate")) {
        char real_path_buf[PATH_MAX];
        const char *real_path;

        log_info("Running post-hibernate hooks");

        real_path = readlink0(hibernate_lock_file_name, real_path_buf);
        if (!real_path) {
            /* No need to notify host VM here: if link wasn't there, it's most likely that the
             * pre-hibernation hooks failed to create it in the first place.  Log for debugging
             * but keep going. */
            log_info("This is probably fine, but couldn't readlink(%s): %s", hibernate_lock_file_name, strerror(errno));
        } else if (unlink(real_path) < 0) {
            log_info("This is fine, but couldn't remove %s: %s", real_path, strerror(errno));
        }
        if (unlink(hibernate_lock_file_name) < 0)
            log_info("This is fine, but couldn't remove %s: %s", hibernate_lock_file_name, strerror(errno));

        if (umount2("/tmp/hibernation-setup-tool", UMOUNT_NOFOLLOW | MNT_DETACH) < 0) {
            /* EINVAL is returned if this isn't a mount point. This is normal if /tmp was already
             * a tmpfs and we didn't create and mounted this directory in the pre-hibernate hook.
             * Calling umount2() is cheaper than checking if this directory is indeed mounted as
             * a tmpfs directory. */
            if (errno != EINVAL)
                log_info("While unmounting /tmp/hibernation-setup-tool: %s", strerror(errno));
        }

        if (!recursive_rmdir("/tmp/hibernation-setup-tool"))
            log_info("While removing /tmp/hibernation-setup-tool: %s", strerror(errno));

        notify_vm_host(HOST_VM_NOTIFY_RESUMED_FROM_HIBERNATION);
        log_info("Post-hibernation hooks executed successfully");

        return 0;
    }

    log_fatal("Can't handle `post %s' notifications", action);
    return 1;
}

static int handle_systemd_suspend_notification(const char *argv0, const char *when, const char *action)
{
    if (!getenv("SYSTEMD_SLEEP_ACTION")) {
        log_fatal("These arguments can only be used when called from systemd");
        return 1;
    }

    log_needs_prefix = true;
    log_needs_syslog = true;

    if (!strcmp(when, "pre"))
        return handle_pre_systemd_suspend_notification(action);

    if (!strcmp(when, "post"))
        return handle_post_systemd_suspend_notification(action);

    log_fatal("Invalid usage: %s %s %s", argv0, when, action);
    return 1;
}

static void link_hook(const char *src, const char *dest)
{
    if (link(src, dest) < 0) {
        if (errno != EEXIST)
            return log_fatal("Couldn't link %s to %s: %s", src, dest, strerror(errno));
    }

    log_info("Notifying systemd of new hooks");
    spawn_and_wait("systemctl", 1, "daemon-reload");
}

static void ensure_systemd_hooks_are_set_up(void)
{
    /* Although the systemd manual cautions against dropping executables or scripts in
     * this directory, the proposed D-Bus interface (Inhibitor) is not sufficient for
     * our use case here: we're not trying to inhibit hibernation/suspend, we're just
     * trying to know when this happened.
     *
     * More info: https://www.freedesktop.org/software/systemd/man/systemd-suspend.service.html
     */
    const char *execfn = (const char *)getauxval(AT_EXECFN);
    const char *location_to_link = "/usr/lib/systemd/systemd-sleep";
    struct stat st;
    int r;

    r = stat(location_to_link, &st);
    if (r < 0 && errno == ENOENT) {
        log_info("Attempting to create hibernate/resume hook directory: %s", location_to_link);
        if (mkdir(location_to_link, 0755) < 0) {
            log_info("Couldn't create %s: %s. VM host won't receive suspend/resume notifications.", location_to_link, strerror(errno));
            return;
        }
    } else if (r < 0) {
        log_info("Couldn't stat(%s): %s. We need to drop a file there to allow "
                 "the VM host to be notified of hibernation/resumes.",
                 location_to_link, strerror(errno));
        return;
    } else if (!S_ISDIR(st.st_mode)) {
        log_info("%s isn't a directory, can't drop a link to the agent there to "
                 " notify host of hibernation/resume",
                 location_to_link);
        return;
    }

    if (execfn)
        return link_hook(execfn, location_to_link);

    char self_path_buf[PATH_MAX];
    const char *self_path = readlink0("/proc/self/exe", self_path_buf);
    if (self_path)
        return link_hook(self_path, location_to_link);

    return log_fatal("Both getauxval() and readlink(/proc/self/exe) failed. "
                     "Couldn't determine location of this executable to install "
                     "systemd hooks");
}

int main(int argc, char *argv[])
{
    if (!is_hibernation_allowed_for_vm()) {
        log_fatal("Hibernation not allowed for this VM. Please enable Hibernation during VM creation");
        return 1;
    }

    if (geteuid() != 0) {
        log_fatal("This program has to be executed with superuser privileges.");
        return 1;
    }

    if (!is_hibernation_enabled_for_vm()) {
        log_fatal("Hibernation not enabled for this VM.");
        return 1;
    }

    if (is_hyperv()) {
        /* We only handle these things here on Hyper-V VMs because it's the only
         * hypervisor we know that might need these kinds of notifications. */
        if (argc == 3)
            return handle_systemd_suspend_notification(argv[0], argv[1], argv[2]);
        if (is_cold_boot())
            notify_vm_host(HOST_VM_NOTIFY_COLD_BOOT);
    }

    size_t total_ram = physical_memory();
    if (!total_ram)
        log_fatal("Could not obtain memory total from this computer");

    size_t needed_swap = swap_needed_size(total_ram);

    log_info("System has %zu MB of RAM; needs a swap area of %zu MB", total_ram / MEGA_BYTES, needed_swap / MEGA_BYTES);

    struct swap_file *swap = find_swap_file(needed_swap);

    if (swap) {
        log_info("Swap file found with size %zu MB at %s", swap->capacity / MEGA_BYTES, swap->path);
    } else {
        log_info("Swap file not found");
    }

    if (swap && swap->capacity < needed_swap) {
        log_info("Swap file %s has capacity of %zu MB but needs %zu MB. Recreating. "
                 "System will run without a swap file while this is being set up.",
                 swap->path, swap->capacity / MEGA_BYTES, needed_swap / MEGA_BYTES);

        if (swapoff(swap->path) < 0) {
            if (errno == EINVAL) {
                log_info("%s is not currently being used as a swap partition. That's OK.", swap->path);
            } else {
                log_fatal("Could not disable swap file %s: %s", swap->path, strerror(errno));
            }
        }

        if (unlink(swap->path) < 0) {
            /* If we're trying to remove the file but it's not there anymore,
             * that's fine... no need to error out. */
            if (!access(swap->path, F_OK))
                log_fatal("Could not remove swap file %s: %s", swap->path, strerror(errno));
        }

        free(swap);
        swap = NULL;
    }

    bool created = false;
    if (!swap) {
        log_info("Creating swap file with %zu MB", needed_swap / MEGA_BYTES);

        swap = create_swap_file(needed_swap);
        if (!swap)
            log_fatal("Could not create swap file");

        created = true;
    }

    ensure_swap_is_enabled(swap, created);
    if (!update_swap_offset(swap))
        log_fatal("Could not update swap offset.");

    if (is_hyperv()) {
        ensure_udev_rules_are_installed();
        ensure_systemd_hooks_are_set_up();
    }

    log_info("Swap file for VM hibernation set up successfully");

    free(swap);

    return 0;
}
