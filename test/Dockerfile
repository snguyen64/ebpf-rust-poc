# Use a lightweight base image with a C compiler
FROM debian:bookworm-slim

# Install build tools
RUN apt-get update && apt-get install -y gcc libc6-dev && apt-get clean

# Set the working directory
WORKDIR /app

# Copy the C source code into the container
COPY test_malloc_free.c .

# Compile the C program
RUN gcc -o test_malloc_free test_malloc_free.c

# Create a script to run the program every 10 seconds
RUN echo '#!/bin/sh' > run.sh && \
    echo 'while true; do ./test_malloc_free; sleep 10; done' >> run.sh && \
    chmod +x run.sh

# Set the default command to run the script
CMD ["./run.sh"]