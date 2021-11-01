FROM ubuntu:21.04

RUN apt update; apt install -y libelf-dev
COPY build/hello_kp.o /hello_kp.o
COPY build/libbpf_go /libbpf_go

WORKDIR /

# ENTRYPOINT libbpf_go