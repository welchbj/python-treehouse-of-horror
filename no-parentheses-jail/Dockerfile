FROM python:3.8.1-buster

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    gcc socat && \
    rm -rf /var/lib/apt/lists

RUN useradd --create-home --shell /bin/bash ctf
RUN echo "ctf:ctf" | chpasswd
WORKDIR /home/ctf

# Since the goal of this challenge is to achieve RCE, we make the flag only
# readable through the execution of the /readflag setuid binary.
COPY flag /flag
RUN chown root:root /flag && \
    chmod 000 /flag
RUN echo 'int main() {setuid(0);system("cat /flag");return 0;}' | gcc -xc - -o /readflag 2>/dev/null
RUN chown root:root /readflag && \
    chmod 4001 /readflag

COPY server.py .
RUN chmod 555 /home/ctf && \
    chown -R root:root /home/ctf && \
    chmod -R 000 /home/ctf/* && \
    chmod 005 /home/ctf/server.py

EXPOSE 4444

USER ctf
CMD while true; do \
        socat TCP-LISTEN:4444,reuseaddr,fork EXEC:"python server.py",stderr; \
    done
