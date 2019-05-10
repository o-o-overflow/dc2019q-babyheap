from ubuntu:19.04
run echo "travis_fold:start:Dapt\033[33;1mservice Dockerfile apt\033[0m" && \
    apt-get update && apt-get install -y python xinetd libssl-dev netcat && \
    echo "\ntravis_fold:end:Dapt\r"

copy src/babyheap /babyheap
copy service.conf /service.conf
copy banner_fail /
copy src/wrapper /wrapper

run touch /flag && chmod 644 /flag && echo "OOO{4_b4byh34p_h45_nOOO_n4m3}" > /flag

expose 5000
cmd ["/usr/sbin/xinetd", "-filelog", "log", "-dontfork", "-f", "/service.conf"]
