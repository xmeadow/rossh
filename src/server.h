/*
 * The server loop, callable from two places: the console entry point in main.c
 * and the Windows service (src/service.c). It owns the listener so a stop
 * request can close it and unblock accept().
 */

#ifndef ROSSH_SERVER_H
#define ROSSH_SERVER_H

#include "config.h"

/*
 * Set up the wolfSSH context, load the host key and authorised keys, listen on
 * cfg->bind:cfg->port and serve until asked to stop. `once` serves a single
 * connection and returns (the test scripts rely on it). Returns 0 on a clean
 * stop, non-zero on a start-up failure.
 */
int server_run(const config_t *cfg, int once);

/* Ask a running server_run() to return. Safe to call from another thread; this
 * is how the service control handler stops the server. */
void server_request_stop(void);

#endif /* ROSSH_SERVER_H */
