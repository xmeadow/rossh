#include "service.h"

#include <stdio.h>
#include <string.h>

#ifdef _WIN32

#include "config.h"
#include "log.h"
#include "server.h"

#include <windows.h>

static SERVICE_STATUS_HANDLE g_status_handle;
static SERVICE_STATUS        g_status;
static char                  g_config_path[CONFIG_PATH_MAX];

static void service_report(DWORD state, DWORD exit_code, DWORD wait_hint)
{
    g_status.dwCurrentState = state;
    if (state == SERVICE_START_PENDING) {
        g_status.dwControlsAccepted = 0;
        g_status.dwCheckPoint       = 1;
    }
    else {
        g_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
        g_status.dwCheckPoint       = 0;
    }
    g_status.dwWin32ExitCode = exit_code;
    g_status.dwWaitHint      = wait_hint;
    SetServiceStatus(g_status_handle, &g_status);
}

static DWORD WINAPI service_ctrl(DWORD ctrl, DWORD event, void *data, void *ctx)
{
    (void)event;
    (void)data;
    (void)ctx;

    if (ctrl == SERVICE_CONTROL_STOP || ctrl == SERVICE_CONTROL_SHUTDOWN) {
        service_report(SERVICE_STOP_PENDING, NO_ERROR, 3000);
        server_request_stop();
    }
    return NO_ERROR;
}

static void WINAPI service_main(DWORD argc, char **argv)
{
    config_t cfg;

    (void)argc;
    (void)argv;

    g_status_handle = RegisterServiceCtrlHandlerExA(ROSSH_SERVICE_NAME,
                                                    service_ctrl, NULL);
    if (g_status_handle == NULL)
        return;

    memset(&g_status, 0, sizeof g_status);
    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    service_report(SERVICE_START_PENDING, NO_ERROR, 3000);

    /* The service controller started us from a binPath that carried the config
     * path, so there is nothing to parse here. */
    config_defaults(&cfg);
    config_load(&cfg, g_config_path);
    log_open(cfg.log_file);
    log_set_level(cfg.log_level);
    log_info("rossh service starting");

    service_report(SERVICE_RUNNING, NO_ERROR, 0);
    server_run(&cfg, 0);
    log_info("rossh service stopped");

    service_report(SERVICE_STOPPED, NO_ERROR, 0);
    log_close();
}

int service_run(const char *config_path)
{
    SERVICE_TABLE_ENTRYA table[2];

    if (config_path != NULL)
        snprintf(g_config_path, sizeof g_config_path, "%s", config_path);
    else
        g_config_path[0] = '\0';

    table[0].lpServiceName = (LPSTR)ROSSH_SERVICE_NAME;
    table[0].lpServiceProc = service_main;
    table[1].lpServiceName = NULL;
    table[1].lpServiceProc = NULL;

    if (!StartServiceCtrlDispatcherA(table)) {
        log_error("not started by the service controller (%lu)", GetLastError());
        return 1;
    }
    return 0;
}

/* This executable's absolute path — what CreateService has to record. */
static int own_path(char *out, DWORD cap)
{
    DWORD n = GetModuleFileNameA(NULL, out, cap);

    if (n == 0 || n >= cap) {
        log_error("cannot determine the executable path (%lu)", GetLastError());
        return -1;
    }
    return 0;
}

int service_install(const char *config_path)
{
    SC_HANDLE scm, svc;
    char      exe[MAX_PATH];
    char      bin[MAX_PATH * 2];

    if (own_path(exe, sizeof exe) != 0)
        return 1;

    if (config_path != NULL && config_path[0] != '\0')
        snprintf(bin, sizeof bin, "\"%s\" --service --config \"%s\"",
                 exe, config_path);
    else
        snprintf(bin, sizeof bin, "\"%s\" --service", exe);

    scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (scm == NULL) {
        log_error("OpenSCManager failed (%lu) — run this as an administrator",
                  GetLastError());
        return 1;
    }

    svc = CreateServiceA(scm, ROSSH_SERVICE_NAME, ROSSH_SERVICE_DISPLAY,
                         SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                         SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
                         bin, NULL, NULL, NULL, NULL /* LocalSystem */, NULL);
    if (svc == NULL) {
        DWORD err = GetLastError();

        if (err == ERROR_SERVICE_EXISTS) {
            log_info("service '%s' is already installed", ROSSH_SERVICE_NAME);
            CloseServiceHandle(scm);
            return 0;
        }
        log_error("CreateService failed (%lu)", err);
        CloseServiceHandle(scm);
        return 1;
    }
    CloseServiceHandle(svc);

    log_info("installed service '%s' (auto-start, LocalSystem)", ROSSH_SERVICE_NAME);
    log_info("  command  %s", bin);

    /* Bring it up now, so the machine is serving without a reboot. */
    svc = OpenServiceA(scm, ROSSH_SERVICE_NAME, SERVICE_START);
    if (svc != NULL) {
        if (StartServiceA(svc, 0, NULL))
            log_info("service started");
        else if (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING)
            log_info("service was already running");
        else
            log_warn("could not start the service (%lu); try `net start %s`",
                     GetLastError(), ROSSH_SERVICE_NAME);
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
    return 0;
}

int service_uninstall(void)
{
    SC_HANDLE      scm, svc;
    SERVICE_STATUS st;

    scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (scm == NULL) {
        log_error("OpenSCManager failed (%lu) — run this as an administrator",
                  GetLastError());
        return 1;
    }

    svc = OpenServiceA(scm, ROSSH_SERVICE_NAME,
                       SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
    if (svc == NULL) {
        log_error("service '%s' is not installed (%lu)",
                  ROSSH_SERVICE_NAME, GetLastError());
        CloseServiceHandle(scm);
        return 1;
    }

    if (ControlService(svc, SERVICE_CONTROL_STOP, &st))
        log_info("stopping service");
    else if (GetLastError() == ERROR_SERVICE_NOT_ACTIVE)
        ;                               /* already stopped, fine */
    else
        log_warn("could not stop the service (%lu)", GetLastError());

    if (DeleteService(svc))
        log_info("removed service '%s'", ROSSH_SERVICE_NAME);
    else
        log_error("DeleteService failed (%lu)", GetLastError());

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return 0;
}

#else  /* ------------------------------------------------------------- POSIX */

int service_install(const char *config_path)
{
    (void)config_path;
    fprintf(stderr, "rossh: services are a Windows concept\n");
    return 1;
}

int service_uninstall(void)
{
    fprintf(stderr, "rossh: services are a Windows concept\n");
    return 1;
}

int service_run(const char *config_path)
{
    (void)config_path;
    fprintf(stderr, "rossh: services are a Windows concept\n");
    return 1;
}

#endif /* _WIN32 */
