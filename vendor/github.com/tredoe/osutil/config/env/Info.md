Persistent variables shell
==========================

Environment variables are a per process thing. So something needs to store the
state to disk and load it in to it's environment and pass that environment on to
it's child processes.

This is generally done by the shell, I don't think there is a cross shell way to
tell a shell to persist an environment variable to it's configuration.


https://help.ubuntu.com/community/EnvironmentVariables


## Persistent environment variables

The names of environment variables are case sensitive.

It is a common practice to name all environment variables with only English
capital letters and underscore (_) signs.

Note: The shell techniques explained in the following sections apply to the
Bourne Shell family of command line shells, which includes sh, ksh, and bash,
which is the default shell shipped with Ubuntu. The commands may be different on
other shells such as csh.

### System-wide environment variables

Environment variable settings that affect the system as a whole (rather than
just a particular user) should not be placed in any of the many system-level
scripts that get executed when the system or the desktop session are loaded, but
into

    /etc/environment - This file is specifically meant for system-wide
    environment variable settings. It is not a script file, but rather consists
    of assignment expressions, one per line. Specifically, this file stores the
    system-wide locale and path settings. 

Note: Any variables added to these locations will not be reflected when invoking
them with a sudo command, as sudo has a default policy of resetting the
Environment and setting a secure path (this behavior is defined in
/etc/sudoers). As a workaround, you can use "sudo su" that will provide a shell
with root privileges but retaining any modified PATH variables.

Note: When dealing with end-user/home desktop systems may be appropriate to
place settings in the user's ~/.pam_environment files discussed above rather
than the system-wide ones, since those files do not require one to utilize root
privileges in order to edit and are easily moved between systems.

Note: Some systems now use an envvar.sh placed in the /etc/profile.d/ directory
to set system wide environment strings.

### Session-wide environment variables

Environment variable settings that should affect just a particular user (rather
than the system as a whole) should be set into:

    ~/.pam_environment - This file is specifically meant for setting a user's
    environment. It is not a script file, but rather consists of assignment
    expressions, one per line. 

PATH DEFAULT=${PATH}:${HOME}/MyPrograms

Note: Using .pam_environment requires a re-login in order to initialize the
variables. Restarting just the terminal is not sufficient to be able to use the
variables. 

If you are using KDE, see http://userbase.kde.org/Session_Environment_Variables/en


## Windows

http://support.microsoft.com/kb/310519

