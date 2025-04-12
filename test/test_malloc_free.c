#include <stdlib.h>
#include <stdio.h>
#include <unistd.h> // For sleep()

int main() {
    printf("Allocating memory...\n");
    void *ptr = malloc(4096); // Allocate 4096 bytes
    if (ptr == NULL) {
        perror("malloc failed");
        return 1;
    }

    printf("Memory allocated at %p\n", ptr);

    printf("Waiting for 2 seconds...\n");
    sleep(2); // Wait for 2 seconds

    printf("Freeing memory...\n");
    free(ptr); // Free the allocated memory
    printf("Memory freed.\n");

    return 0;
}