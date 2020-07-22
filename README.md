# Rundeck HTTP Workflow Step Plugin
This plugin provides a way to send HTTP requests as part of
a [Rundeck](http://rundeck.org) workflow step. It is somewhat
based on https://github.com/rvs-fluid-it/rundeck-httppost-plugin.

![Project unmaintained](https://img.shields.io/badge/project-unmaintained-red.svg)

## Project Unmaintained

We've moved our scheduling system to a Kubernetes based solution rather than Rundeck and so are no longer able to maintain this project unfortunately.

## Features

- GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS
- Authentication: BASIC or OAuth 2.0
- Project or Framework level configuration
- Support for Self Signed SSL Certificates

## Caveats

OAuth 2.0 only supports the Client Credentials Grant Type. The OAuth
configuration is per-project or per-framework. This means that each job
will share the entire project or entire frameworks credentials. However,
this allows those credentials to be externalized into the framework
configuration and avoids them being exported with projects.

## Todo

- Support request parameters from config and/or data
- Support request body from config and/or data
- Find a way to support per-job authentication settings?
