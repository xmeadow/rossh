/*
 * Windows service support (spec.md §4.2): install, remove, and run under the
 * service controller as LocalSystem with auto-start.
 *
 * On any other platform the functions report the failure and do nothing — the
 * module is here so the server binary stays one binary on every target.
 */

#ifndef ROSSH_SERVICE_H
#define ROSSH_SERVICE_H

#define ROSSH_SERVICE_NAME    "rossh"
#define ROSSH_SERVICE_DISPLAY "rossh SSH server"

/*
 * Register the running executable as a service, auto-start, LocalSystem:
 *
 *     rossh --install <config>
 *
 * The recorded command line is "<this exe> --service --config <config>", so
 * `rossh --service` is what the controller launches. Needs administrator rights;
 * the service is started right away. Returns 0 on success (already installed
 * counts as success).
 */
int service_install(const char *config_path);

/* Stop the service if it is running, then delete it. Returns 0 on success. */
int service_uninstall(void);

/* Hand control to the service controller and run the server. This is the body
 * of `rossh --service`; when run from a console it fails cleanly. */
int service_run(const char *config_path);

#endif /* ROSSH_SERVICE_H */
