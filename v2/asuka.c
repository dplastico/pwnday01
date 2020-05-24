#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

void baka(){
    char nombre[256];
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
    memset(nombre, 0, sizeof(nombre));
    printf("Que buscas? ah? \nID? \n");
    read(0,nombre,256);
    printf(nombre);
    
}


void nerv(){

    char buf[25];
    printf("¿Eres un chico, no shinji?\n");
    fflush(stdout);
    read(0,buf,256);
    if(strcmp(buf, "asuka") == 0) {
        printf("¡Está corrompiendo mi mente!\n");
        fflush(stdout);
    } else {
        printf("shinji... Tonto\n");
        fflush(stdout);
        
        _exit(0);
    }
}


int main(void){
    printf("El mundo parece un lugar cruel\n");
    fflush(stdout);
    baka();
    nerv();
    
}