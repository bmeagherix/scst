/*
 *  scst_disk_session - manage open-scsi disk sessions
 *
 *  Copyright (C) 2023 Brian Meagher <brian.meagher@ixsystems.com>
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 */
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <glob.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <linux/limits.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>

#define INITIATORNAME_PREFIX "iface.initiatorname = "
#define END_RECORD "# END RECORD"
#define SCST_LOCK_DIR "/var/lock/scst"
#define CONN_D_PAT "/sys/devices/platform/host*/session%d/connection*/iscsi_connection/connection*"

/* To rename a temp file we must be on the same filesystem */
#define SCST_TMP_DIR "/etc/iscsi/scst-tmp"

static const char program_name[] = "scst-disk-session";

static const struct option long_options[] = {
	{"duplicate", required_argument, NULL, 'd'},
	{"initiatorname", required_argument, NULL, 'i'},
	{"sessionname", required_argument, NULL, 'n'},
	{"output", required_argument, NULL, 'o'},
	{"stop", required_argument, NULL, 's'},
	{"help", no_argument, NULL, 'h'},
	{NULL, 0, NULL, 0},
};

static void usage(int status)
{
	fprintf(status ? stderr : stdout, "Usage: %s [OPTION]\n", program_name);
	fprintf(status ? stderr : stdout, "Helper utility for open-iscsi sessions.\n"
		"\n"
		"  -d, --duplicate=<DISKNAME>	duplicate the underlying session.\n"
		"  -i, --initiatorname=<NAME>	initiator name to use during duplicate.\n"
		"  -n, --sessionname=<NAME>	session name to use the resulting duplicate.\n"
		"  -o, --output=<FILENAME>	write duplicate result to file.\n"
		"  -s, --stop=<DISKNAME>		stop the underlying session.\n"
		"  -h, --help			display this help and exit.\n"
		"\n  where <DISKNAME> has the format, e.g. 3:0:0:0\n"
		"\n"
		"Report bugs to <scst-devel@lists.sourceforge.net>.\n");
	exit(status == 0 ? 0 : -1);
}



static int _open_target_lockfile(const char *targetname)
{
	char lockfile[PATH_MAX] = SCST_LOCK_DIR"/";
	int fd;
	struct stat statbuf;

	strncat(lockfile, targetname, sizeof(lockfile) - sizeof(SCST_LOCK_DIR"/"));

	fd = open(lockfile, O_RDONLY);
	if (-1 != fd)
		return fd;

	if (stat(SCST_LOCK_DIR, &statbuf) && errno == ENOENT) {
		mkdir(SCST_LOCK_DIR, 0700);
	} else if (!S_ISDIR(statbuf.st_mode)) {
		unlink(SCST_LOCK_DIR);
		mkdir(SCST_LOCK_DIR, 0700);
	}

	fd = open(lockfile, O_CREAT | O_WRONLY | O_EXCL, 0666);
	if (-1 == fd)
		return fd;

	close(fd);
	fd = open(lockfile, O_RDONLY);

	return fd;
}

static int _lock_target(const char *targetname)
{
	int fd = _open_target_lockfile(targetname);

	if (fd < 0)
		return -1;

	if (flock(fd, LOCK_EX)) {
		close(fd);
		return -1;
	}

	return fd;
}

/*
 * Get sid underlying the specified disk (e.g. "3:0:0:0")
 */
int diskname_to_session(const char *diskname)
{
	char fullpath[PATH_MAX];
	char resolved_path[PATH_MAX];
	char *checkpath, *session_ptr;
	int sid;

	if (*diskname != '/') {
		int len = snprintf(fullpath, sizeof(fullpath), "/sys/class/scsi_device/%s",
				   diskname);

		if ((len < 0) || (size_t)len >= sizeof(fullpath)) {
			fprintf(stderr, "Error generating path for: %s\n", diskname);
			return -1;
		}
		checkpath = fullpath;
	} else {
		checkpath = (char *)diskname;
	}

	if (!realpath(checkpath, resolved_path)) {
		fprintf(stderr, "Invalid path %s: %d (%s)\n", checkpath, errno, strerror(errno));
		return -1;
	}

	session_ptr = strstr(resolved_path, "/session");
	if (NULL == session_ptr) {
		fprintf(stderr, "Could not locate session: %s\n", resolved_path);
		return -1;
	}

	if (1 != sscanf(session_ptr, "/session%d/", &sid)) {
		fprintf(stderr, "Could not extract sid: %s\n", resolved_path);
		return -1;
	}

	return sid;
}

static char *_read_line_from_filepath(const char *filepath)
{
	char *result = NULL;
	FILE *fp = fopen(filepath, "r");

	if (fp) {
		size_t len = 0;
		ssize_t count;

		count = getline(&result, &len, fp);
		if (count <= 0) {
			if (result) {
				free(result);
				result = NULL;
			}
		} else {
			if (result[count-1] == '\n')
				result[count-1] = '\0';
		}
		fclose(fp);
	}

	return result;
}

/*
 * Get targetname (aka IQN) for the specified sid.
 *
 * Caller must free returned value.
 */
char *session_id_to_targetname(int sid)
{
	char sysname[128];

	sprintf(sysname, "/sys/class/iscsi_session/session%d/targetname", sid);
	return _read_line_from_filepath(sysname);
}


/*
 * Get persistent address (aka IP address) for the specified sid.
 *
 * Caller must free returned value.
 */
char *session_id_to_persistent_address(int sid)
{
	char pattern[256];
	char *result = NULL;
	glob_t globbuf;
	int count;

	count = snprintf(pattern, sizeof(pattern), CONN_D_PAT"/persistent_address", sid);
	if ((count < 0) || ((size_t)count >= sizeof(pattern)))
		return NULL;

	if (0 == glob(pattern, 0, NULL, &globbuf)) {
		if (globbuf.gl_pathc > 0)
			result = _read_line_from_filepath(globbuf.gl_pathv[0]);
		globfree(&globbuf);
	}

	return result;
}

int session_id_to_persistent_port(int sid)
{
	char pattern[256];
	int result = -1;
	glob_t globbuf;
	int count;

	count = snprintf(pattern, sizeof(pattern), CONN_D_PAT"/persistent_port", sid);
	if ((count < 0) || ((size_t)count >= sizeof(pattern)))
		return result;

	if (0 == glob(pattern, 0, NULL, &globbuf)) {
		if (globbuf.gl_pathc > 0) {
			char *portstr = _read_line_from_filepath(globbuf.gl_pathv[0]);

			if (portstr) {
				char *endptr;
				long val;

				errno = 0;
				val = strtol(portstr, &endptr, 10);
				if ((errno == 0) && (endptr != portstr) && (val == (val & 0xFFFF)))
					result = val;
				free(portstr);
			}
		}
		globfree(&globbuf);
	}

	return result;
}


/*
 * Add (or remove) initiator name for the target config
 *
 * Modifies the file used by open-iscsi when establishing a new session.
 */
int add_initiator_name_to_config(const char *iqn, char *ipaddress,
				 int port, const char *initiator_name)
{
	char filepath[PATH_MAX];
	int len = snprintf(filepath, sizeof(filepath), "/etc/iscsi/nodes/%s/%s,%d,1/default",
			   iqn, ipaddress, port);
	FILE *fp;
	int fd, result = -1;
	struct stat statbuf;
	char *tmppath = NULL;

	if (stat(SCST_TMP_DIR, &statbuf) && errno == ENOENT)
		mkdir(SCST_TMP_DIR, 0700);

	if ((len < 0) || (size_t)len >= sizeof(filepath))
		return -1;

	fp = fopen(filepath, "r");
	if (!fp)
		return -1;

	if (-1 == asprintf(&tmppath, "%s/default-%s-%s-%d-XXXXXX", SCST_TMP_DIR, iqn,
			   ipaddress, port)) {
		fclose(fp);
		return -1;
	}

	fd = mkstemp(tmppath);
	if (-1 != fd) {
		char *line = NULL;
		size_t len = 0;
		ssize_t nread;

		while ((nread = getline(&line, &len, fp)) != -1) {
			if (0 == strncmp(line, INITIATORNAME_PREFIX,
					 sizeof(INITIATORNAME_PREFIX) - 1))
				continue;
			if (initiator_name &&
			    (0 == strncmp(line, END_RECORD, sizeof(END_RECORD) - 1))) {
				write(fd, INITIATORNAME_PREFIX, sizeof(INITIATORNAME_PREFIX) - 1);
				write(fd, initiator_name, strlen(initiator_name));
				write(fd, "\n", 1);
			}
			write(fd, line, strlen(line));
		}
		free(line);
		close(fd);
		result = 0;
	}

	fclose(fp);

	/* Rename to replace the file */
	if (!result && tmppath) {
		result = rename(tmppath, filepath);
		if (result)
			fprintf(stderr, "rename failed: %s -> %s (%d, %s)\n", tmppath,
				filepath, errno, strerror(errno));
	}

	if (tmppath)
		free(tmppath);

	return result;
}

int run_command(unsigned int max_time, const char *command)
{
	pid_t pid;
	int status = 0;

	pid = fork();
	if (pid == 0) {
		int fd;
		struct timespec waittime;

		close_range(0, ~0U, CLOSE_RANGE_UNSHARE);
		alarm(max_time);
		fd = open("/dev/null", O_RDWR);
		dup(fd);
		dup(fd);
		dup(fd);
		waittime.tv_sec = 0;
		waittime.tv_nsec = (1000 * 1000);
		nanosleep(&waittime, NULL);

		exit(execl("/bin/sh", "sh", "-c", command, NULL));
	}

	if (pid < 0)
		return -errno;

	if (waitpid(pid, &status, 0) != pid)
		return -1;

	if (SIGALRM == WTERMSIG(status))
		return -ETIMEDOUT;

	return WEXITSTATUS(status);
}

char *duplicate_session(int sid, const char *initiatorname, const char *targetname)
{
	/* iscsiadm -m session -r <sid> --op new */
	char *address = NULL, *command = NULL;
	int port = session_id_to_persistent_port(sid);
	int lock_fd = -1;
	char *result = NULL;
	int ret = -1;
	time_t before_dup;

	if (port < 0) {
		fprintf(stderr, "Failed to read port\n");
		syslog(LOG_ERR, "Failed to read port");
		goto out;
	}

	address = session_id_to_persistent_address(sid);
	if (!address) {
		fprintf(stderr, "Failed to read address\n");
		syslog(LOG_ERR, "Failed to read address");
		goto out;
	}

	if (-1 == asprintf(&command, "iscsiadm -m session -r %d --op new", sid)) {
		fprintf(stderr, "Failed to generate duplicate command\n");
		syslog(LOG_ERR, "Failed to generate duplicate command");
		goto out;
	}

	lock_fd = _lock_target(targetname);
	if (lock_fd < 0) {
		fprintf(stderr, "Failed to obtain lock\n");
		syslog(LOG_ERR, "Failed to obtain lock");
		goto out;
	}

	if (initiatorname) {
		if (add_initiator_name_to_config(targetname, address, port, initiatorname)) {
			fprintf(stderr, "Failed to update initiator name\n");
			syslog(LOG_ERR, "Failed to update initiator name");
			goto out;
		}
	}

	before_dup = time(NULL);

	ret = run_command(30 /* seconds */, command);

	if (initiatorname) {
		if (add_initiator_name_to_config(targetname, address, port, NULL)) {
			fprintf(stderr, "Failed to restore initiator name\n");
			syslog(LOG_ERR, "Failed to restore initiator name");
			/* Don't quit */
		}
	}

	/*
	 * Now try to determine which disk we just created.  Unfortunately, iscsiadm
	 * doesn't return a useful value (e.g. the new sid).
	 */
	if (!ret) {
		char diskname[128];
		FILE *fp;
		char *newtargetname;

		fp = popen("ls -1t /sys/class/scsi_device", "r");
		if (!fp) {
			fprintf(stderr, "Failed to determine recent disks\n");
			syslog(LOG_ERR, "Failed to determine recent disks");
			goto out;
		}

		while (fgets(diskname, sizeof(diskname), fp)) {
			int len = strlen(diskname);
			int newsid;

			if (len && diskname[len-1] == '\n')
				diskname[len-1] = '\0';

			newsid = diskname_to_session(diskname);
			if (newsid < 0)
				continue;

			newtargetname = session_id_to_targetname(newsid);
			if (!newtargetname)
				continue;

			if (!strcmp(targetname, newtargetname)) {
				struct stat statbuf;
				char filepath[PATH_MAX];

				free(newtargetname);
				/*
				 * We flock'ed the target, so we should be good, but let's stat the
				 * file, just to be sure its not an old target.
				 */
				len = snprintf(filepath, sizeof(filepath),
					       "/sys/class/scsi_device/%s", diskname);
				if ((len > 0) &&
				    ((size_t)len < sizeof(filepath)) &&
				    !stat(filepath, &statbuf)) {
					if (statbuf.st_ctime >= before_dup)
						result = strdup(diskname);
					break;
				}
			} else {
				free(newtargetname);
			}
		}
	} else {
		syslog(LOG_ERR, "Command failed with status %d: %s", ret, command);
	}

out:
	if (address)
		free(address);

	if (command)
		free(command);

	if (lock_fd != -1)
		close(lock_fd);

	return result;
}

int add_disk_to_handler(const char *diskname)
{
	int len, count;
	char command[128];
	int fd = open("/sys/kernel/scst_tgt/handlers/dev_disk_iscsi/mgmt", O_WRONLY);

	if (fd < 0) {
		fprintf(stderr, "Failed to open dev_disk_iscsi/mgmt\n");
		syslog(LOG_ERR, "Failed to open dev_disk_iscsi/mgmt");
		return fd;
	}

	len = snprintf(command, sizeof(command), "add_device %s", diskname);
	if ((len < 0) || (size_t)len >= sizeof(command)) {
		fprintf(stderr, "Error generating add_device for %s\n", diskname);
		syslog(LOG_ERR, "Error generating add_device for %s", diskname);
		return -1;
	}

	count = write(fd, command, len);
	close(fd);

	if (count < len) {
		fprintf(stderr, "Only wrote %d bytes to dev_disk_iscsi/mgmt (expected %d)\n",
			count, len);
		syslog(LOG_ERR, "Only wrote %d bytes to dev_disk_iscsi/mgmt (expected %d)",
			count, len);
		return -1;
	}

	// fprintf(stderr, "Did: %s\n", command);
	// syslog(LOG_INFO, "Command successful: %s", command);
	return 0;
}

int change_session_to_disk(const char *diskname, const char *sessionname, const char *targetname)
{
	char *mgmt_path = NULL;
	char *command = NULL;
	int len, count, fd, result = -1;

	if (-1 == asprintf(&mgmt_path,
			   "/sys/kernel/scst_tgt/targets/iscsi/%s/luns/mgmt",
			   targetname)) {
		fprintf(stderr, "Failed to generate mgmt_path for change_path command\n");
		syslog(LOG_ERR, "Failed to generate mgmt_path for change_path command");
		free(command);
		return -1;
	}

	fd = open(mgmt_path, O_WRONLY);
	if (fd < 0) {
		fprintf(stderr, "Failed to open %s\n", mgmt_path);
		syslog(LOG_ERR, "Failed to open %s", mgmt_path);
		free(mgmt_path);
		return fd;
	}
	free(mgmt_path);

	len = asprintf(&command, "change_path %s %s 0", sessionname, diskname);
	if (-1 == len) {
		fprintf(stderr, "Failed to generate change_path command\n");
		syslog(LOG_ERR, "Failed to generate change_path command");
		close(fd);
		return -1;
	}

	count = write(fd, command, len);
	close(fd);

	if (count < len) {
		fprintf(stderr, "Only wrote %d bytes to mgmt for change_path (expected %d)\n",
			count, len);
		syslog(LOG_ERR, "Only wrote %d bytes to mgmt for change_path (expected %d)",
			count, len);
	} else {
		// fprintf(stderr, "Did: %s\n", command);
		syslog(LOG_INFO, "Command successful: %s", command);
		result = 0;
	}

	free(command);
	return result;
}

int main(int argc, char **argv)
{
	char *diskname = NULL;
	char *initiatorname = NULL;
	char *sessionname = NULL;
	char *output = NULL;
	int ch, longindex;
	bool do_duplicate = false, do_stop = false;
	int sid, ret=-1;

	openlog(program_name, 0, LOG_DAEMON);

	while ((ch = getopt_long(argc, argv, "d:s:i:n:o:h",
				 long_options, &longindex)) >= 0) {
		switch (ch) {
		case 'd':
			do_duplicate = true;
			diskname = optarg;
			break;
		case 's':
			do_stop = true;
			diskname = optarg;
			break;
		case 'i':
			initiatorname = optarg;
			break;
		case 'n':
			sessionname = optarg;
			break;
		case 'o':
			output = optarg;
			break;
		case 'h':
			usage(0);
			break;
		default:
			usage(-1);
		}
	}

	if (do_duplicate && do_stop) {
		fprintf(stderr, "May only specify one operation: duplicate or stop\n");
		syslog(LOG_ERR, "May only specify one operation: duplicate or stop");
		usage(-1);
	}

	if ((!do_duplicate && !do_stop) || (NULL == diskname)) {
		fprintf(stderr, "Must specify an operation: duplicate or stop\n");
		syslog(LOG_ERR, "Must specify an operation: duplicate or stop");
		usage(-1);
	}

	sid = diskname_to_session(diskname);
	if (sid < 0) {
		syslog(LOG_ERR, "Could not find SID for disk %s", diskname);
		exit(-1);
	}

	if (do_duplicate) {
		char *newdisk;
		char *targetname = session_id_to_targetname(sid);

		if (!targetname) {
			fprintf(stderr, "Failed to read targetname\n");
			syslog(LOG_ERR, "Failed to read targetname");
			exit(-1);
		}

		newdisk = duplicate_session(sid, initiatorname, targetname);
		if (!newdisk) {
			syslog(LOG_ERR, "Could not duplicate session %d", sid);
			exit(-1);
		}

		if (add_disk_to_handler(newdisk) < 0)
			exit(-1);

		if (sessionname) {
			if (change_session_to_disk(newdisk, sessionname, targetname) < 0)
				exit(-1);
		}

		if (!output) {
			printf("%s\n", newdisk);
			ret = 0;
		} else {
			FILE *fp = fopen(output, "w");

			if (fp) {
				int len = strlen(newdisk);

				if ((len > 0) && ((size_t)len == fwrite(newdisk, 1, len, fp)))
					ret = 0;
				fclose(fp);
			} else {
				syslog(LOG_ERR, "Could not open output file %s", output);
			}
		}

		free(targetname);
		free(newdisk);
	}

	if (do_stop) {
		/* iscsiadm -m session -r <sid> --logout */
		char *command = NULL;

		if (-1 == asprintf(&command, "iscsiadm -m session -r %d --logout", sid)) {
			fprintf(stderr, "Failed to generate stop command\n");
			syslog(LOG_ERR, "Failed to generate stop command");
			exit(-1);
		}
		ret = run_command(30 /* seconds */, command);
		free(command);
	}

	closelog();

	return ret;
}
