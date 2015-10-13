# Rundeck HTTP Workflow Step Plugin
This plugin provides a way to send HTTP requests as part of
a [Rundeck](http://rundeck.org) workflow step. It is somewhat
based on https://github.com/rvs-fluid-it/rundeck-httppost-plugin.

## Features

- GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS
- Authentication: BASIC or OAuth 2.0
- Project or Framework level configuration

## Caveats

OAuth 2.0 only supports the Client Credentials Grant Type. The OAuth
configuration is per-project or per-framework. This means that each job
will share the entire project or entire frameworks credentials. However,
this allows those credentials to be externalized into the framework
configuration and avoids them being exported with projects.