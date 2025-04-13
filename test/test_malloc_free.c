#include <stdlib.h>
#include <stdio.h>
#include <unistd.h> // For sleep()

int main() {
    while (1) {
        printf("Allocating memory...\n");
        size_t size = (rand() % 20 + 1) * 1024; // Random size between 1 and 20 KB
        void *ptr = malloc(size); // Allocate random size
        if (ptr == NULL) {
            perror("malloc failed");
            return 1;
        }

        printf("Memory allocated at %p\n", ptr);

        printf("Waiting for 5 seconds...\n");
        sleep(5); // Wait for 5 seconds

        printf("Freeing memory...\n");
        free(ptr); // Free the allocated memory
        printf("Memory freed.\n");
        sleep(5);
    }

    return 0;
}