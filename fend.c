#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>   
#include <sys/stat.h>
#include <sys/reg.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <glob.h>
#include <fnmatch.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>



extern char **environ;
// char *program;

struct word
{
    char *filename;
    int rwx;
};
typedef struct word Words;

Words *words;


int pattern_size;

void get_whole_filepath();


void clear_array(char arr[]) {
    int len = sizeof(arr);
    memset(&arr[0], 0, len);
}


void read_config(char *filename)
{
    // int i;
    words = (Words*)malloc(1024*sizeof(Words)); 
    //read into configure file
    FILE *in = fopen(filename, "r");
    
    pattern_size = 0;
    while(1) {
        words[pattern_size].filename = (char*)malloc(sizeof(in));
        if (fscanf(in, "%d", &words[pattern_size].rwx) != 1) {
            break;
        }
        fscanf(in, "%s", words[pattern_size].filename);
        pattern_size++;
    }

    fclose(in);
}

int exists(const char *fname)
{
    FILE *file;
    file = fopen(fname, "r");
    if (file)
    {
        fclose(file);
        return 1;
    }
    return 0;
}

int find_config(int argc, char *argv[]) {
    int pattern;
    if (argc < 2) {
        //Must provide a config file., exit
        fprintf(stderr, "Must provide a config file.\n");
        exit(-1);
    }
    //vars
    char *home = getenv("HOME");
    char *path = (char *)malloc(strlen(home)+strlen("/.fendrc")+1);
    strcpy(path, home);
    strcat(path, "/.fendrc");
    char option[2];
    strcpy(option, "-c");

    //find in config
    if (strcmp(argv[1], option) == 0) {
        if (argc < 3) {
            exit(-1);
        }
        else if (exists(argv[2])){
            read_config(argv[2]);
            pattern = 1;
        }

        else {
            exit(-1);
        }

    } 

    //find in current dir
    else if (exists(".fendrc")) {
        // read fendrc
        read_config(".fendrc");
        pattern = 2;
    }

    //find in home dir
    else if (exists(path)) {
        read_config(path);      
        pattern = 2;
    }

    //no config found
    else {
        //Must provide aconfig file, exit
        fprintf(stderr, "Must provide a config file.\n");
        printf("lalsl\n");
        exit(-1);
    }

    free(path);
    return pattern;
}

int check_filename(char filename[]) {
    int i;
    int permit = 111;
    char whole_path[PATH_MAX + 1];
    for (i = 0; i < pattern_size; i++){
        get_whole_filepath(words[i].filename, whole_path);
        int match = fnmatch(whole_path, filename, FNM_PATHNAME);
        if (match == 0) {
            permit = words[i].rwx;
        }
    }  


    return permit;
}



const int SIZEOF_LONG = sizeof(long);
const int long_size = sizeof(long);
void getdata(pid_t child, long addr, char* str) {
    typedef union _data
    {
        long val;
        char chars[SIZEOF_LONG];
    } Data;


    Data data;
    // int i = 0;
    int read = 0;

    while (1) {
        data.val = ptrace(PTRACE_PEEKDATA, child, addr + read, NULL);
        memcpy(str + read, &data.val, long_size);
        if (memchr(&data.val, 0, sizeof(data.val))) {
            break;
        }
        read = read + sizeof(data.val);
    }
    str += '\0';
}


void putdata(pid_t child, long addr, char *str, int len) {   
    char *laddr;
    int i, j;
    union u {
        long val;
        char chars[long_size];
    }data;
    i = 0;
    j = len / long_size;
    laddr = str;
    while(i < j) {
        memcpy(&data.val, laddr, long_size);
        ptrace(PTRACE_POKEDATA, child, addr + i * 8, data.val);
        ++i;
        laddr += long_size;
    }
    j = len % long_size;
    if(j != 0) {
        memcpy(data.chars, laddr, j);
        ptrace(PTRACE_POKEDATA, child, addr + i * 8, data.val);
    }
}


void get_whole_filepath(char *file_buf, char *filename) {
    realpath(file_buf, filename);
}

void sand_kill(char filename[], char *program, pid_t child) {
    fprintf(stderr, "Terminating %s: unauthorized access of %s\n", program, filename);
    kill(child, SIGKILL);
    wait(NULL);
    exit(-1);    

}

void check_file_read(long addr, char *program, pid_t child) {
    char *file_buf = (char *)malloc(sizeof(char) *(PATH_MAX));
    char *filename = (char *)malloc(sizeof(char) *(PATH_MAX));
    getdata(child, addr, file_buf);
    get_whole_filepath(file_buf, filename);
    int code = check_filename(filename);
    int read_permit = code / 100;
    if (read_permit == 0) {
        sand_kill(filename, program, child);
    }
    free(file_buf);
    free(filename);
}

void check_file_write(long addr, char *program, pid_t child) {
    char *file_buf = (char *)malloc(sizeof(char) *(PATH_MAX));
    char *filename = (char *)malloc(sizeof(char) *(PATH_MAX));
    getdata(child, addr, file_buf);
    get_whole_filepath(file_buf, filename);
    int code = check_filename(filename);
    int write_permit = (code % 100) / 10;
    if (write_permit == 0) {
        sand_kill(filename, program, child);
    }
    free(file_buf);
    free(filename);
}

void check_file_exe(long addr, char *program, pid_t child) {
    char *file_buf = (char *)malloc(sizeof(char) *(PATH_MAX));
    char *filename = (char *)malloc(sizeof(char) *(PATH_MAX));
    getdata(child, addr, file_buf);
    get_whole_filepath(file_buf, filename);
    int code = check_filename(filename);
    int exe_permit = (code % 100) % 10;
    if (exe_permit == 0) {
        sand_kill(filename, program, child);
    }
    free(file_buf);
    free(filename);
}

void check_parent_read(long addr, char *program, pid_t child) {
    char file_buf[PATH_MAX];
    char parent_buf[PATH_MAX];
    char filename[PATH_MAX];
    getdata(child, addr, file_buf);
    get_whole_filepath(file_buf, filename);
    char *ret;
    ret = strrchr(filename, '/');
    size_t len = ret - filename;
    strncpy(parent_buf, filename, len);
    *parent_buf += '\0';
    int code = check_filename(parent_buf);
    int read_permit = code / 100;
    if (read_permit == 0) {
        sand_kill(parent_buf, program, child);
    }
    clear_array(file_buf);
    clear_array(parent_buf);
    clear_array(filename);
}

void check_parent_write(long addr, char *program, pid_t child) {
    char file_buf[PATH_MAX];
    char parent_buf[PATH_MAX];
    char filename[PATH_MAX];
    getdata(child, addr, file_buf);
    get_whole_filepath(file_buf, filename);
    char *ret;
    ret = strrchr(filename, '/');
    size_t len = ret - filename;
    strncpy(parent_buf, filename, len);
    *parent_buf += '\0';
    int code = check_filename(parent_buf);
    int write_permit = (code % 100) / 10;
    if (write_permit == 0) {
        sand_kill(parent_buf, program, child);
    }
    clear_array(file_buf);
    clear_array(parent_buf);
    clear_array(filename);
}

void check_parent_exe(long addr, char *program, pid_t child) {
    char file_buf[PATH_MAX];
    char parent_buf[PATH_MAX];
    char filename[PATH_MAX];
    getdata(child, addr, file_buf);
    get_whole_filepath(file_buf, filename);
    char *ret;
    ret = strrchr(filename, '/');
    size_t len = ret - filename;
    strncpy(parent_buf, filename, len);
    *parent_buf += '\0';
    int code = check_filename(parent_buf);
    int exe_permit = (code % 100) % 10;
    if (exe_permit == 0) {
        sand_kill(parent_buf, program, child);
    }
    clear_array(file_buf);
    clear_array(parent_buf);
    clear_array(filename);
}


int main(int argc,char *argv[]) {
    int pattern;
    char *program = NULL;
    pattern = find_config(argc, argv);


    pid_t child;
    long params[3];
    int status;

    if (pattern == 1) {
        program = (char *)malloc(sizeof(char)*sizeof(argv[3]));
        strcpy(program, argv[3]);
    }

    else if (pattern == 2) {
        program = (char *)malloc(sizeof(char)*sizeof(argv[1]));
        strcpy(program, argv[1]);
    }

    // int insyscall = 0;
    child = fork();
    if(child == 0) {
        if (pattern == 1) {
            ptrace(PTRACE_TRACEME, 0, NULL, NULL);
            if (execve(argv[3], argv + 3, environ) < 0) {
                printf("error in hello\n");
            }
        }

        else if (pattern == 2) {
            ptrace(PTRACE_TRACEME, 0, NULL, NULL);
            if (execve(argv[1], argv + 1, environ) < 0) {
                printf("error in hello\n");
            }
        }
    }
    else {
        while(1) {
            wait(&status);  
            if(WIFEXITED(status))
                break;
            struct user* user_space = (struct user*)0;
            long original_rax = ptrace(PTRACE_PEEKUSER, child, &user_space->regs.orig_rax, NULL);

            if (original_rax == SYS_open) {
                params[0] = ptrace(PTRACE_PEEKUSER, child, &user_space->regs.rdi, NULL);                
                params[1] = ptrace(PTRACE_PEEKUSER, child, &user_space->regs.rsi, NULL);
                int open_flag = params[1];
                if ((open_flag & 0x40) == 64) {
                    check_parent_write(params[0], program, child);
                    check_parent_exe(params[0], program, child);
                }
                //read permission of file
                if ((open_flag & 0x01) == 0 || (open_flag & 0x03) == 2) {
                    check_file_read(params[0], program, child);
                    check_parent_exe(params[0], program, child);
                }
                //write permission of file
                if ((open_flag & 0x01) == 1 || (open_flag & 0x03) == 2) {
                    check_file_write(params[0], program, child);
                    check_parent_exe(params[0], program, child);
                }

            }

            else if (original_rax == SYS_openat) {
                params[0] = ptrace(PTRACE_PEEKUSER, child, &user_space->regs.rsi, NULL);
                params[1] = ptrace(PTRACE_PEEKUSER, child, &user_space->regs.rdx, NULL);
                int open_flag = params[1];
                if ((open_flag & 0x01) == 0 || (open_flag & 0x03) == 2) {
                    check_file_read(params[0], program, child);
                    check_parent_exe(params[0], program, child);
                }

                //write permission of file
                if ((open_flag & 0x01) == 1 || (open_flag & 0x03) == 2) {
                    check_file_write(params[0], program, child);
                    check_parent_exe(params[0], program, child);
                }
            }


            else if (original_rax == SYS_faccessat) {
                params[0] = ptrace(PTRACE_PEEKUSER, child, &user_space->regs.rsi, NULL);
                params[1] = ptrace(PTRACE_PEEKUSER, child, &user_space->regs.rdx, NULL);
                int open_flag = params[1];
                if ((open_flag & 0x07) == 4) {
                    check_file_read(params[0], program, child);
                    check_parent_exe(params[0], program, child);
                }
                //write permission of file
                if ((open_flag & 0x07) == 2) {
                    check_file_write(params[0], program, child);
                    check_parent_exe(params[0], program, child);
                }

                if ((open_flag & 0x07) == 1) {
                    check_file_exe(params[0], program, child);
                    check_parent_exe(params[0], program, child);
                }
            }

            else if (original_rax == SYS_creat) {
                params[0] = ptrace(PTRACE_PEEKUSER, child, &user_space->regs.rdi, NULL);
                check_parent_exe(params[0], program, child);
                check_parent_write(params[0], program, child);
            }


            else if (original_rax == SYS_unlink) {
                params[0] = ptrace(PTRACE_PEEKUSER, child, &user_space->regs.rdi, NULL);
                check_parent_exe(params[0], program, child);
                check_parent_write(params[0], program, child);
            }

            else if (original_rax == SYS_stat) {
                params[0] = ptrace(PTRACE_PEEKUSER, child, &user_space->regs.rdi, NULL);
                check_parent_exe(params[0], program, child);
            }

          

            else if (original_rax == SYS_link) {
                params[0] = ptrace(PTRACE_PEEKUSER, child, &user_space->regs.rsi, NULL);
                params[1] = ptrace(PTRACE_PEEKUSER, child, &user_space->regs.rdi, NULL);
                check_parent_write(params[0], program, child);
                check_parent_exe(params[0], program, child);
                check_parent_exe(params[1], program, child);
            }

            
            
            else if(original_rax == SYS_execve) {
                params[0] = ptrace(PTRACE_PEEKUSER, child, &user_space->regs.rdi, NULL);
                if (params[0] != 0) {
                    check_file_exe(params[0], program, child);
                }
            }


            ptrace(PTRACE_SYSCALL, child, NULL, NULL);
        }
    }
    return 0;
}