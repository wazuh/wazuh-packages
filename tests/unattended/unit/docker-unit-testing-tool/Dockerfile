FROM alpine:latest
RUN apk add --no-cache bash coreutils diffutils
RUN mkdir -p /tests/unattended/

COPY entrypoint.sh /usr/local/bin/test_file
RUN chmod +x /usr/local/bin/test_file

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/test_file"]