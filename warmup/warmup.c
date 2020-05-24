#include <stdio.h>
#include <string.h>

int exploitingcl(){
    printf("YAY!, ya eres un pwner!\n");
    fflush(stdout);
    system("/bin/sh");
}


int vuln(){

    char buf[25];
    printf("Algo?\n");
    fflush(stdout);
    gets(buf);
}

int main(){

    vuln();
}