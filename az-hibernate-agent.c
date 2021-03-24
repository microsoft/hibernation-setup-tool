// Azure Hibernation Agent
// Sets up a swap area suitable to hibernate a virtual machine in an Azure
// environment.
//
// Copyright (c) 2021 Microsoft Corp.
// Licensed under the terms of the MIT license.

#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/falloc.h>
#include <linux/fs.h>
#include <linux/ioctl.h>
#include <linux/suspend_ioctls.h>
#include <linux/magic.h>
#include <mntent.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <sys/ioctl.h>
#include <sys/statfs.h>
#include <sys/stat.h>
#include <sys/swap.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/vfs.h>
#include <unistd.h>

#define MEGA_BYTES (1<<20)

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

static const char swap_file_name[] = "/hibfile.sys";

struct swap_file {
    size_t capacity;
    char path[];
};

static int ioprio_set(int which, int who, int ioprio)
{
    return (int)syscall(SYS_ioprio_set, which, who, ioprio);
}

static void log_impl(const char *type, const char *fmt, va_list ap)
{
    flockfile(stdout);
    printf("az-hibernate-agent: %s ", type);
    vprintf(fmt, ap);
    printf("\n");
    funlockfile(stdout);
}

__attribute__((format(printf, 1, 2)))
static void log_info(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    log_impl("INFO", fmt, ap);
    va_end(ap);
}

__attribute__((format(printf, 1, 2)))
__attribute__((noreturn))
static void log_fatal(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    log_impl("FATAL", fmt, ap);
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
    current++; /* skip the NUL terminator */

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
        __builtin_unreachable();
    }

    if (errno || (endptr && **endptr != expected_end))
        log_fatal("Could not parse size: %s", strerror(errno));

    return parsed;
}

static bool is_exec_in_path(const char *name)
{
    const char *path_env = getenv("PATH") ? : "/bin:/sbin:/usr/bin:/usr/sbin";

    while (*path_env) {
        const char *p = strchr(path_env, ':');
        char path[PATH_MAX];
        int ret;

        if (!p) {
            /* Last segment of $PATH */
            ret = snprintf(path, PATH_MAX, "%s/%s", path_env, name);
            path_env = "";
        } else if (p - path_env) {
            /* Middle segments */
            ret = snprintf(path, PATH_MAX, "%.*s/%s", (int)(p - path_env), path_env, name);
            path_env = p + 1;
        } else {
            /* Empty segment or non-root directory? Skip. */
            path_env = p + 1;
            continue;
        }
        if (ret < 0 || ret >= PATH_MAX)
            log_fatal("Building path to determine if %s exists would overflow buffer", name);

        if (path[0] != '/')
            continue;

        if (!access(path, X_OK))
            return true;
    }

    return false;
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
        char *size = next_field(type);

        if (!strcmp(type, "file")) {
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

            /* FIXME: Check for overflow? */
            /* FIXME: Confirm in kernel if units are always kB or if MB/GB/TB are actually used */
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
    /* FIXME: use constant from the kernel headers for the hibernation overhead? (Do
     * those even exist?) */
    /* FIXME: Is this sufficient? Maybe 2 * phys_mem at least should be used instead,
     * so there's phys_mem bytes available for the whole memory being used by the workload
     * plus whatever was in the swap partition?  */
    return phys_mem + 10 * MEGA_BYTES;
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
            int fd = open(mntent->mnt_fsname, O_RDONLY|O_CLOEXEC);

            if (fd < 0) {
                log_fatal("Could not open %s to determine block size: %s",
                    mntent->mnt_fsname, strerror(errno));
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
    __builtin_unreachable();
}

static char *allocate_block_for_swap_warmup(long block_size)
{
    char *block = calloc(1, block_size);

    if (!block)
        log_fatal("Couldn't allocate temporary block for swap warmup procedure");

    const uint32_t pattern = 'M' << 24 | 'S' << 16 | 'F' << 8 | 'T';
    memcpy(block, &pattern, sizeof(pattern));
    return block;
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

static bool is_hibernation_enabled_for_vm(void)
{
    return true;

    char buffer[1024];
    char *entry;

    /* FIXME: check if running under a container and bail out */

    if (access("/dev/snapshot", F_OK) != 0) {
        log_info("Kernel does not support hibernation or /dev/snapshot has not been found.");
        return false;
    }

    entry = read_first_line_from_file("/proc/bus/vmbus/hibernation", buffer);
    if (entry && !strcmp(entry, "1"))
        return true;

    entry = read_first_line_from_file("/sys/power/disk", buffer);
    if (entry && strstr(entry, "platform"))
        return true;

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

    if (num_contiguous_blocks * blksize >= sysconf(_SC_PAGE_SIZE))
        return first_blknum;

    return ~0;
}

static bool try_zero_out_with_write(const char *path, off_t needed_size, long block_size)
{
    /* O_DSYNC isn't used here as fdatasync() is called after the write loop is finished. */
    int fd = open(path, O_WRONLY | O_CLOEXEC | O_SYNC);

    if (fd < 0) {
        log_info("Could not open %s: %s", path, strerror(errno));
        return false;
    }

    /* This pattern will be overwritten by mkswap(8) called below.  This is
     * an attempt to allocate a file without holes in them.  mkswap(8)
     * recommends `dd` to be used to 0-initialize the whole file, but
     * writing 4 bytes every block seems to be sufficient to avoid a swap
     * file without holes.  */
    char *pattern = allocate_block_for_swap_warmup(block_size);
    off_t last_off = needed_size / block_size;
    for (off_t off = 0; off < last_off; off += block_size) {
        if (pwrite(fd, pattern, block_size, off) < 0) {
            log_info("Could not write pattern to %s: %s", path, strerror(errno));
            free(pattern);
            close(fd);
            return false;
        }
    }
    /* FIXME: maybe a better strategy here would be calling
     * posix_fadvise(DONTNEED) every PAGE_SIZE/block_size times to discard
     * the data from the page cache, and not open it in O_DIRECT mode?
     * Should avoid having to write a pattern in the whole file without
     * thrashing the page cache -- O_DIRECT requires block size to match
     * the device block size, and we could just write a small amount of
     * data every block_size bytes instead of the whole block_size region,
     * saving us precious time in systems with lots of RAM and slow disks */
    fdatasync(fd);
    free(pattern);
    close(fd);

    return true;
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

    rc = ftruncate(fd, size);
    if (rc < 0) {
        if (errno == EPERM) {
            log_info("Not enough disk space to create %s with %zu MB.", path, size / MEGA_BYTES);
        } else {
            log_info("Could not resize %s to %ld MB: %s", path, size / MEGA_BYTES, strerror(errno));
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
            log_fatal("System ran out of disk space while allocating hibernation file");
        } else {
            log_fatal("Could not allocate %s: %s", path, strerror(errno));
        }
    }

    close(fd);

    return true;
}

static void spawn_and_wait(const char *program, int n_args, ...)
{
    va_list ap;
    char **argv;
    pid_t pid;
    int rc;

    /* +1 for argv[0], +1 for trailing NULL (implicit due to calloc
     * zeroing out allocated buffer) */
    argv = calloc(n_args + 2, sizeof(char *));
    if (!argv)
        log_fatal("Couldn't allocate memory for argument array");

    va_start(ap, n_args);
    argv[0] = (char *)program;
    for (int i = 1; i <= n_args; i++)
        argv[i] = va_arg(ap, char *);
    va_end(ap);

    rc = posix_spawnp(&pid, program, NULL, NULL, argv, NULL);
    free(argv);

    if (rc != 0)
        log_fatal("Could not spawn %s: %s", program, strerror(rc));

    log_info("Waiting for %s (pid %d) to finish.", program, pid);

    int wstatus;
    if (waitpid(pid, &wstatus, 0) != pid)
        log_fatal("Couldn't wait for %s: %s", program, strerror(errno));
    if (!WIFEXITED(wstatus))
        log_fatal("%s ended abnormally: %s", program, strerror(errno));
    if (WEXITSTATUS(wstatus) == 127)
        log_fatal("Failed to spawn %s", program);
    if (WEXITSTATUS(wstatus) != 0)
        log_fatal("%s ended with unexpected exit code %d", program, WEXITSTATUS(wstatus));

    log_info("%s finished successfully.", program);
}

static bool is_file_on_fs(const char *path, __fsword_t magic)
{
    struct statfs stfs;

    if (!statfs(path, &stfs))
        return stfs.f_type == magic;

    return false;
}

static struct swap_file *create_swap_file(size_t needed_size)
{
    log_info("Creating hibernation file at %s with %zu MB.", swap_file_name, needed_size / MEGA_BYTES);

    if (!create_swap_file_with_size(swap_file_name, needed_size))
        log_fatal("Could not create swap file, aborting.");

    /* Allocate the swap file with the lowest I/O priority possible to not thrash workload */
    ioprio_set(IOPRIO_WHO_PROCESS, 0, IOPRIO_PRIO_VALUE(IOPRIO_CLASS_IDLE, 7));

    /* FIXME: Would it be better to determine the block size for swap_file_name instead? */
    long block_size = determine_block_size_for_root_fs();

    log_info("Ensuring %s has no holes in it.", swap_file_name);
    if (!try_zeroing_out_with_fallocate(swap_file_name, needed_size)) {
        log_info("Fast method failed; trying a slower method.");

        if (!try_zero_out_with_write(swap_file_name, needed_size, block_size))
            log_fatal("Could not create swap file.");
    }
    if (is_file_on_fs(swap_file_name, EXT4_SUPER_MAGIC) && is_exec_in_path("e4defrag"))
        spawn_and_wait("e4defrag", 1, swap_file_name);
    if (is_file_on_fs(swap_file_name, BTRFS_SUPER_MAGIC) && is_exec_in_path("btrfs"))
        spawn_and_wait("btrfs", 3, "filesystem", "defragment", swap_file_name);

    spawn_and_wait("mkswap", 1, swap_file_name);

    struct swap_file *ret = malloc(sizeof(*ret) + sizeof(swap_file_name));
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
    int fd = open(swap->path, O_RDONLY|O_CLOEXEC);
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

    return (struct resume_swap_area) {
        .offset = offset,
        .dev = st.st_dev,
    };
}

static bool update_kernel_cmdline_params_for_grub(const char *dev_uuid,
                                                  const struct resume_swap_area swap_area,
                                                  bool has_grubby,
                                                  bool has_update_grub2)
{
    /* Doc: https://docs.fedoraproject.org/en-US/fedora/rawhide/system-administrators-guide/kernel-module-driver-configuration/Working_with_the_GRUB_2_Boot_Loader/#sec-Making_Persistent_Changes_to_a_GRUB_2_Menu_Using_the_grubby_Tool */
    log_info("Kernel command line is missing parameters to resume from hibernation.  Trying to patch grub configuration file.");

    char *args;
    if (asprintf(&args, "resume=/dev/disk/by-uuid/%s resume_offset=%lld no_console_suspend=1", dev_uuid, swap_area.offset) < 0) {
        log_info("Could not allocate memory for kernel argument");
        return false;
    }

    if (is_exec_in_path("update-initramfs")) {
        log_info("Updating initramfs to include resume stuff");

        FILE *conf = fopen("/etc/initramfs-tools/conf.d/resume", "we");
        if (!conf)
            log_fatal("Could not open initramfs-toosl configuration file: %s", strerror(errno));

        fprintf(conf, "# Updated automatically by az-hibernate-agent. Do not modify.\n");
        fprintf(conf, "RESUME=UUID=%s\n", dev_uuid);
        fclose(conf);
        spawn_and_wait("update-initramfs", 1, "-u");
    }

    if (has_grubby) { 
        log_info("Using grubby to patch GRUB configuration");
        spawn_and_wait("grubby", 3, "--update-kernel=ALL", "--args", args);
    }

    if (has_update_grub2) {
        static const char grub_cfg_path[] = "/etc/default/grub";
        FILE *resume_cfg;
        char *old_contents = NULL;
        size_t old_contents_len = 0;
        char buffer[1024];

        log_info("Using update-grub2 to patch GRUB configuration");

        resume_cfg = fopen(grub_cfg_path, "re");
        if (!resume_cfg)
            log_fatal("Could not open %s for reading: %s", grub_cfg_path, strerror(errno));

        bool in_az_hibernate_agent_block = false;
        while (fgets(buffer, sizeof(buffer), resume_cfg)) {
            if (in_az_hibernate_agent_block) {
                if (strstr(buffer, "# az-hibernate-agent:end"))
                    in_az_hibernate_agent_block = false;
                continue;
            }

            if (strstr(buffer, "# az-hibernate-agent:start")) {
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
        
        resume_cfg = fopen(grub_cfg_path, "we");
        if (!resume_cfg)
            log_fatal("Could not open %s for writing: %s", grub_cfg_path, strerror(errno));

        if (old_contents) {
            fwrite(old_contents, old_contents_len, 1, resume_cfg);
            free(old_contents);
        }

        fprintf(resume_cfg, "# az-hibernate-agent:start\n");
        fprintf(resume_cfg, "GRUB_CMDLINE_LINUX_DEFAULT=\"$GRUB_CMDLINE_LINUX_DEFAULT %s\"\n", args);
        fprintf(resume_cfg, "# az-hibernate-agent:end\n");

        fclose(resume_cfg);

        spawn_and_wait("update-grub2", 0);
    }

    free(args);

    return true;
}

static bool update_swap_offset(const struct swap_file *swap)
{
    bool ret = true;

    log_info("Updating swap offset");

    int fd = open("/dev/snapshot", O_RDONLY|O_CLOEXEC);
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
        if (has_grubby || has_update_grub2) {
            ret = update_kernel_cmdline_params_for_grub(dev_uuid, swap_area, has_grubby, has_update_grub2);
        } else {
            log_info("Could not determine how system was booted to update kernel parameters for next boot.  System won't be able to resume until you fix this.");
            ret = false;
        }
    }

    free(dev_uuid);
    return ret;
}

static void ensure_swap_is_enabled(const struct swap_file *swap)
{
    FILE *fstab;
    char *old_contents = NULL;
    size_t old_contents_len = 0;
    char buffer[1024];

    log_info("Ensuring swap file %s is enabled", swap->path);

    if (swapon(swap->path, 0) < 0) {
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
    fprintf(fstab, "%s\tnone\tswap\tswap\t0\t0\n", swap->path);

    fclose(fstab);
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    if (!is_hibernation_enabled_for_vm()) {
        log_info("Hibernation not enabled for this VM.");
        return 0;
    }

    size_t total_ram = physical_memory();
    if (!total_ram)
        log_fatal("Could not obtain memory total from this computer");

    size_t needed_swap = swap_needed_size(total_ram);

    log_info("System has %zu MB of RAM; needs a swap area of %zu MB",
        total_ram / MEGA_BYTES, needed_swap / MEGA_BYTES);

    struct swap_file *swap = find_swap_file(needed_swap);

    if (swap) {
        log_info("Swap file found with size %zu MB at %s", swap->capacity / MEGA_BYTES, swap->path);
    } else {
        log_info("Swap file not found");
    }

    if (swap && swap->capacity < needed_swap) {
        /* FIXME: maybe do the destroy/create dance only if expanding the file results
         * in a file with holes?  Should be more efficient.  */
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

    if (!swap) {
        log_info("Creating swap file with %zu MB", needed_swap / MEGA_BYTES);

        swap = create_swap_file(needed_swap);
        if (!swap)
            log_fatal("Could not create swap file");
    }

    ensure_swap_is_enabled(swap);
    if (!update_swap_offset(swap))
        log_fatal("Could not update swap offset.");

    log_info("Swap file for VM hibernation set up successfully");

    free(swap);

    return 0;
}
