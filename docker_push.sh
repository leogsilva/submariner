#!/bin/bash

docker tag quay.io/submariner/submariner-networkplugin-syncer:dev docker.io/leogsilva/submariner-networkplugin-syncer:dev            
docker tag quay.io/submariner/submariner-globalnet:dev docker.io/leogsilva/submariner-globalnet:dev                        
docker tag quay.io/submariner/submariner-route-agent:dev docker.io/leogsilva/submariner-route-agent:dev
docker tag quay.io/submariner/submariner-gateway:dev docker.io/leogsilva/submariner-gateway:dev

docker push docker.io/leogsilva/submariner-networkplugin-syncer:dev
docker push docker.io/leogsilva/submariner-globalnet:dev
docker push docker.io/leogsilva/submariner-route-agent:dev
docker push docker.io/leogsilva/submariner-gateway:dev