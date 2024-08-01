#!/bin/bash

image=999424586482.dkr.ecr.sa-east-1.amazonaws.com/sefaz-ce-sophia/auth:1.0-RC

aws --profile sefazce-mfa ecr get-login-password --region sa-east-1 | docker login --username AWS --password-stdin 999424586482.dkr.ecr.sa-east-1.amazonaws.com

docker build -t $image .

docker push $image
