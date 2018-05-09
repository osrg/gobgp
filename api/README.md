# gobgp.proto

## Install

-   Install protoc (from https://gist.github.com/sofyanhadia/37787e5ed098c97919b8c593f0ec44d8):

    ```
    # (optional)
    cd /tmp

    # Make sure you grab the latest version
    curl -OL https://github.com/google/protobuf/releases/download/v3.2.0/protoc-3.2.0-linux-x86_64.zip

    # Unzip
    unzip protoc-3.2.0-linux-x86_64.zip -d protoc3

    # Move protoc to /usr/local/bin/
    sudo mv protoc3/bin/* /usr/local/bin/

    # Move protoc3/include to /usr/local/include/
    sudo mv protoc3/include/* /usr/local/include/
    ```

-   Install Protobuf Go plugin
    ```
    go get -u github.com/golang/protobuf/protoc-gen-go
    ```

## Build

```
cd api
protoc --go_out=plugins=grpc:. *.proto
```
