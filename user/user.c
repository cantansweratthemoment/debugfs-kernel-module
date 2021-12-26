#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char *argv[]) {
    char* fdesc;
    char* pid;
    if (argc < 3) {
        fprintf( stderr, "not enough args\n" );
        return -1;
    }
    fdesc = argv[1];
    pid = argv[2];
    printf("fdesc = %s, pid = %s\n", fdesc, pid);

    FILE *kmod_args = fopen("/sys/kernel/debug/kmod/kmod_args", "w");
    fprintf(kmod_args, "%s %s\n ", fdesc, pid);
    fclose(kmod_args);

    FILE *kmod_result = fopen("/sys/kernel/debug/kmod/kmod_result", "r");
    char c;
    while (fscanf(kmod_result, "%c", &c) != EOF) {
        printf("%c", c);
    }
    fclose(kmod_result);
    return 0;
}


