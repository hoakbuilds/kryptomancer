FROM alpine

RUN apk update

RUN apk add --no-cache python3 openssl && \
    apk add --no-cache --update python3 && \
    pip3 install --upgrade pip setuptools
COPY Requirements.txt /

RUN pip install -r /Requirements.txt

COPY . /kryptoflask
WORKDIR /kryptoflask

RUN mkdir /temp /uploads /openssl_out

EXPOSE 5000

ENTRYPOINT [ "python3", "kryptomancer.py" ]