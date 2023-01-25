#!/bin/sh

apk update
apk add bash
apk add docker docker-compose
apk add openrc
service docker start
