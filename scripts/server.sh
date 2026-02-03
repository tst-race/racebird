#!/bin/bash

docker exec -it rbserver bash -c 'nc -l -v localhost 7777'
