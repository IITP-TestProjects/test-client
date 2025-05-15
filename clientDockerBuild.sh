 #!/bin/bash


echo "version: $1"

docker build --tag bcclient:$1 .