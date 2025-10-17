#!/bin/bash
# 
cd osavroute_dns && go build -o osavroute_dns
cd ..
cd osavroute_tcp && go build -o osavroute_tcp
cd ..