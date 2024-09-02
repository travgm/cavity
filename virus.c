#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    FILE *fd = NULL;
    if ((fd = fopen("INFECTED", "w+")) == NULL) {
	    return -1;
    } else {
	    fwrite("Just kidding", 12, 1, fd);
    }
    fclose(fd);
    return 0;
}
