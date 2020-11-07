# kcare-uchecker

[![CircleCI](https://circleci.com/gh/circleci/circleci-docs.svg?style=svg)](https://circleci.com/gh/circleci/circleci-docs)

A simple tool to detect outdated shared libraries still linked to processes in memory

## Usage

Simple script run will looks like

``` bash
$ curl -s -L https://kernelcare.com/uchecker | sudo python
[*] Process httpd[15516] linked to the `libc-2.17.so` that is not up to date.

You may want to update libraries above and restart corresponding processes.

KernelCare+ allows to resolve such issues with no process downtime. To find 
out more, please, visit https://lp.kernelcare.com/kernelcare-early-access?
```

## Troubleshooting

For more verbose output you can choose logging level from ERROR, WARNING, INFO and DEBUG. For example

``` bash
$ curl -s -L https://kernelcare.com/uchecker | sudo LOGLEVEL=debug python
```

## About
The project is part of [kernelcare.com](https://kernelcare.com "KernelCare") - livepatching solution for linux kernels as well as shared libraries like glibc and openssl
