FROM alpine
RUN apk add --no-cache bash coreutils diffutils
RUN mkdir -p /tests/unattended/

ADD entrypoint.sh /usr/local/bin/test_file
RUN chmod +x /usr/local/bin/test_file

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/test_file"]