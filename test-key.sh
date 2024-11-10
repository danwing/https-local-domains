#!/bin/sh

set -e
name="test-key"

if [ ! -f $name.pem ]; then
    openssl genrsa -out $name.pem 2048
fi

openssl rsa -in $name.pem -pubout > $name.pub
openssl rsa -in $name.pem -pubout -outform der > $name.der


sha256hash=$(shasum -b -a 256 < $name.der | awk '{print $1}')
sha256url=$(echo -n $sha256hash | xxd -r -p | base64 | tr '+/' '-_' | tr -d "=")

echo "sha256 hash is $sha256hash"
echo "sha256 url safe is $sha256url"
echo 

sha512256hash=$(shasum -b -a 512256 < $name.der | awk '{print $1}')
sha512246url=$(echo -n $sha512256hash | xxd -r -p | base64 | tr '+/' '-_' | tr -d "=")

echo "sha512/256 hash is $sha512256hash"
echo "sha512/256 url safe is $sha512246url"

exit



 
