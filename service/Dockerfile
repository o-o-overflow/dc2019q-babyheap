from ubuntu:19.04
run echo "travis_fold:start:Dapt\033[33;1mservice Dockerfile apt\033[0m" && \
    apt-get update && apt-get install -y python xinetd libssl-dev netcat && \
    echo "\ntravis_fold:end:Dapt\r"

copy src/service /service
copy service.conf /service.conf
copy src/wrapper /wrapper

run touch /flag && chmod 644 /flag && echo "OOO{pr0f35510n4l_r54_br34k3r}" > /flag

expose 5000
cmd ["/usr/sbin/xinetd", "-filelog", "log", "-dontfork", "-f", "/service.conf"]
