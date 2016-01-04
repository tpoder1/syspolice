# Content #


# Preface #

SysPolice is the system for securing and managing Unix based servers. The main idea is periodically checking content of the file system on a client side (eg. web server, mail server) and compare this content with content which should be on the client side. If content on the client side is valid then nothing happens, however the content is different an administrator of the system is alerted. Alert could be done by many ways - eg. an email, nagios, zabbix.

System checking is not only one thing which SysPolice can do. The data base also provide many other features to make an administrator's life easier.

Basic SysPolice features are follow:
  * Scan local file system on the client side and compare the file list with the list provided by the server.
  * System compare changed files on the client system and alerts user, until changes are confirmed by user or administrator.
  * Provide output for an administrator with state of the system.
  * Perform backups of the local configuration files. The list of files to backup are defined on the server's config file.
  * On the server side accept differed forms of package source (.rpm, .tgz. directory). The system allows extend to any type of the package type.
  * Provide environment for automatized installations through kickstart.
  * Internal modular and open architecture which allows extend the system (web interface, monitoring system, ...).
  * The client side is simple as much as possible. That means that installation on the client do not require any special packages, libraries, tools.
  * Server communicates with the clients through secured SSH protocol. Root access is not nessesary on client system.

The follow image shows basic finctionality:

<img src='http://syspolice.googlecode.com/svn/wiki/img01.gif' />

1. SysPolice server reads config file and connect to the client. Client run process which check files on the client side. Determine basic informations (permisions, modify time, md5 checksum, ...)

2. Client send the file list back to the server.

3. Server compare results from the client and compare with configured package database, internal database. If there is a reason server send differences to an administrator.

4. Depends on the result administrator can decide what he will do. He could inspect client (eg. apply updates), update client's configuration on the server. Another way how he coult proceed - accept the changes through command on the server. The last possibility is avalaible only if the **historycheck** mode is enabled.

# Client side #
The client side is the most sensitive part of the system. All client system is represented by **one** binary file, which do all important things. The client works with configuration data enquired from the server, perform file system scanning and
returns output of this scanning back to the server.

# Server side #
The server performs almost all tasks provided by SysPolice. All necessarily information are stored on server side. The SysPolice could be also used for some tasks regarding software distribution and client system maintenance. This section describes in detail the server side organization.

## Directory structure ##
SysPolice is on the server organized into directory structure. The structure contains client configurations, package repository and status information.

```
/<sysfink root>                         - basic police system directory
  + config/                             - configurations for systems
      + include/                        - global configurations which are included from the system configs
         + general.conf
         + base.pkgs
         + application1.pkgs
      + system1
      + system2
      + system3
      + ...
  + dirpkg/                              - basic directory with dir based packages
      + myapp1/
      + myapp2.tar.gz
  + rpmpkg/                              - basic directory with rpm based packages
     + i386/
        + CentOS5/
            base/
            updates/
            rpmforge/
            ...
     + amd64/
        + CentOS5/
            base/
            updates/
            rpmforge/
            ...
       ...
  ....
```

## Config files syntax ##

The basic path for config files is **/<sysfink root>/config** (typically **/home/sysfink/config**). In this directory config file or config directory for each client system have to be placed. Each system is defined by separated configuration file or set of configuration files. The files using a simple .ini style syntax. The config file is divided into several sections. Data inf config file could be also used by other systems  like nagios, zabbix, backup system, ....

Some section could have a special part with a time condition. This condition tells when the section is active (hourly, weakly, daily, monthly).

The example config file is shown.

```
# cat /police/config/webserver

# basic includes 
use         includes/options.cfg
use         includes/arch-i386.cfg

# hostname and an administrator email
hostname    webserver.foo.bar.com
email       tpoder@cis.vutbr.cz

use         includes/base.pkgs
pkg:dir     cvis-shared
use         includes/apache.pkgs
use         includes/mysql.pkgs
use         includes/x11.pkgs
use         includes/devel.pkgs
use         includes/samba.pkgs
use         includes/vsftpd.pkgs
pkg:dir     linuxdcpp

pkg:tgz     %{backupfile}
pkg:lst     %{commitdir}


path        [+B]/etc/passwd
path        [+B]/etc/shadow
path        [+B]/etc/hosts.allow

path        [-X]/data/*
path        [-X]/home/*
path        [-X]/usr/src/*
path        [-X]/var/cache/imgcache/*


```

Each section allows to use different configuration options. Basic options are described above:

| **option**       | **default value, example of use**                   |  **description**   |
|:-----------------|:----------------------------------------------------|:-------------------|
| **General options** |
| basedir          | /police                                             | The base dir where basic police structure is placed. |
| dbdir            || /var/police/%{system}/|
| silenterr        | false                                               | If set to true error messages are not reported to the administrator (eg. when host is down) |
| Directory where the scan database  is stored. |
| use              | Example: includes/base.pkgs                         | load configuration from the file and place into current position |
| **Options uses generaly by scanning the clinet** |
| hostname         | Example: webserver.foo.vutbr.cz                     | The client hostname. This hostname have to be used in DNS and have to be set as hostname on the client side.  |
| basearch         | i386                                                | The client's basic architecture |
| arch             | i386 i686 noarch  - depends on basearch             | List if client architectures supported by client. |
| scancmd          | police-client                                       | The command to perfomed on the client side to scan the client's directory structure. |
| email            | Example: admin@foo.vutbr.cz                         | List of administrators address. This address will be used to send reports. |
| maxlines         | 3000                                                | The max number of lines to send through an email . |
| subject          | [POLICE](POLICE.md) report for %{system}                     | An email subject with the police report (see -m option ) |
| mailfrom         | police%{servername}                                 | The from address used in the mail reports |
| **Package base directory and repositories definition** |
| rpmrepos         | %{basedir}/repos                                    | paths to .rpm repositories |
| pkgdir           | %{basedir}/pkgdir                                   | base path where dir, tgz and lst are searched |
| **Packages definition** |
| pkg:rpm          |  Example: samba-client                              | name of .rpm package |
| pkg:dir          |  Example: myconf                                    | name of dir package |
| pkg:tgz          |  Example: myconf.tgz                                | name of tgz package |
| pkg:lst          |  Example: lists/files.xml                           | name of file (or direcotry) where list (or lists) of files are placed |
| path             |  Example: [-X]/var/run                              | see section paths  |
|| **Backup and commit definitions**
| backupfile       | %{dbdir}/backup.tgz                                 | Where the result of the backup is stored.        |
| commitdir        | %{dbdir}/commits/                                   | Where the result of the manul or autocommit are stored. |
| **Advance checks** |
| rpmdiff          | Example: yes                                        | Add installed rpms diff into scan report  |
| servicesdiff     | Example: yes                                        | Add installed startup services diff into scan report  |
| **Kicstart preparation procedure** |
| ksfile           | %{basedir}/install/kickstart/%{system}.cfg          | Where police install cmd will create the installation kicstart file. |
| kstemplate       | %{basedir}/install/kickstart/kicstart-teplate.cfg   | Where police install cmd should look for the kicstart template file. |
| ksdata           | %{dbdir}/install.tgz                                | Where the post installation files are prepared. |



**The macro expansion**
The the config file you can use an macro. The macros simplyfies the complex configuration of syspolice. On any place in the config file you can you %{macro\_name} syntax.
As the macro you can use any option from the config file. There are also some pred-defined macros. In general there is no difference between options and predefined macros.
The only diffrence is that predefined values can't be changed in the config file.

| **macro**      | **meaning** |
|:---------------|:------------|
| servername     | The hostname of the police server |
| system         | The current system name |
| datetime       | Current date and time in YYYY-MM-DD.HH:MM:SS format |

The special directive **use** can by used to include content of the the other file. The way how the included file is expanded depends the format of the included file. If the file is divided into sections the sections are placed into the place
where the directive is called. If the included file does not contain section all options are placed into the section
where directive is called.

In many cases the list of values is used. For example the **rpm** option can define multiple packages. In this case
we can write more values on single line or we can split values to multiple lines.

**Example:**

```
pkg:rpm   samba-client samba-server samba-common
```

is equivalent with:

```
pkg:rpm   samba-client 
pkg:rpm   samba-server
pkg:rpm   saba-common
```


## Paths definition ##
There are several options in check section which require special attention. The name
of the options are path and equivalent aliases - include, exclude, backup. This
options describes which attributes should be checked and reported.

The level of the file checking can be affected by the path option. Through this option we can
define how to check a file or a directory. Many option could be switched off or switched on
by this directive. See follow example:

```
01: path      [-X]/home* [-X]/var/log/**
02: path      [+X]/home/cfg1/*
03: path      [-M5]/var/run/test
04: path      [+B]/etc/sysconfig/network 
```

In this example directories /home and /var/log/ will be excluded from the checking. Any
changes in those directories will not be reported to an administrator. Although
the /home directory will not be checked, the content of dir /home/cfg1/ will
be included into check report. In this directory all available options
will be checked (size, mtime, ...).  Line 03 shows how to define some special
options. In this case all options will be checked beyond md5 checksum
and modification time.

The path can have more complex options. The syntax is follow:

```
path  [<flags>]<pattern>
```

Each option could be prefixed by + or - flag. Sign '+' enable the option and '-' disable the option.

| **option** | **meaning** |
|:-----------|:------------|
| M          | check mtime |
| 5          | check file md5 sum |
| S          | check file size |
| H          | check hard links number |
| L          | check symlink path |
| U          | check user owner |
| G          | check group owner |
| D          | check major and minor device number |
| B          | do backup this file or directory |
| F          | do backup this file or directory and do not send the diff file compared with the last backup option F have the same meaning as FB |
| A          | perform the autocommit operation |
| X          | same as M5SHLUGD |


One directory can have multiple options. All this options are evaluated in defined order and last used value is applied.

**Example 1:**
```
path  [-M5SHLUGD]/usr/*
path  [+UG]/usr/dir1/*
```

the result on /usr/dir1 is :
```
[-M5SHLUGD] & [+UG] = *[-M-5-S-H-L+U+G-D]*
```

**Example 2:**
```
exclude   [+5S]/usr/dir2/*
```

have the same result as:
```
exclude   /usr/dir2/*
path      [+5S]/usr/dir2/*
```

so the finnal result is:
```
[-M5SHLUGD] & [+5S] = [-M+5+S-H-L-U-G-D] = *[-M+5S-HLUGD]*
```

## Command options ##
All operation in syspolice can be performed using one comman on the syspolice server. This command supports another sub-commands. The command can be used in the follow way:

```

 police [<options>] <sub-command> <system> <system> ... | all 

```

As the sub-command can be one of the follow:

  * check : the sub-command performs the basic scan on the client system including backups, performs scan of the packages on the syspolice server and compare outputs. The report is either printed in the stdout or send via an email (depend on -m switch).

  * getlst : Get listfile in xml format. Tahat list file can by used as the kind of the package type (pkg:lst).

  * commit : Very similar to getlst. The only difference is that result is stored into %{dbdir}/commits/ direcory. The command is useful for the system where the packages are not maintained by the police system. This allows confirm changes in the files system on monitored system.

  * sync : This command performs the changes on the client to update the client system according to the information obtained from the server. This command can by also used to perform command on the multiple systems or distribute new files.

  * download : Download files that are differed from the client system. The command makes easier maintenance packages on the syspolice server. The result are stored into download.tgz file.

  * ksinstall : prepare installation files for the kinckstart installation procedure.

## System maintenance ##


## Install operations ##


## Operations ##

TODO

  * File system check (CMD police client on the client side)
    * [CLIENT](CLIENT.md) Download system configuration from the server.
    * [SERVER](SERVER.md) Check hostname and address. If those items are correct provide configuration data.
    * [CLIENT](CLIENT.md) Traverse file system. Obtain detailed information regarding to files (size, right, ownership, cheksum) with respect to scan definition provide by server.
    * [CLIENT](CLIENT.md) Send the result of the scan to the server.
    * [SERVER](SERVER.md) Accept data from the client and compare it with expected list.
    * [SERVER](SERVER.md) Create output with differences. Alternatively send difference through an email, and update status data for monitoring system.
  * Configuration file backup
    * [CLIENT](CLIENT.md) Download system configuration from the server.
    * [SERVER](SERVER.md) Check hostname and adders. If those items are correct provide configuration data.
    * [CLIENT](CLIENT.md) Traverse file system and take content of files which should be backuped.
    * [CLIENT](CLIENT.md) Send data to the server.
    * [SERVER](SERVER.md) Process data received from the client, compare backuped data with the previous one.
    * [SERVER](SERVER.md) Send data to administrator if it is required.
  * Software distribution
    * [SERVER](SERVER.md) TODO: tool which helps distribute new software on the clients.
  * Software download
    * [CLIENT](CLIENT.md) TODO: tool to synchronize/update client in accordance with the server.
  * Prepare data for installation
    * [SERVER](SERVER.md) Depend on the request prepare configuration file for the installation through kickstart.
  * General backup
    * [SERVER](SERVER.md) TODO prepare data for the general backup of the client system.

User (administrator) interface
  * [CLIENT](CLIENT.md) CMD police scan    - scan local system and send data to the server
  * [CLIENT](CLIENT.md) CMD police backup  - perform client backup
  * [CLIENT](CLIENT.md) CMD police client  - police client + police scan
  * [CLIENT](CLIENT.md) CMD police diff    - show differences on the client side
  * [CLIENT](CLIENT.md) CMD police sync    - synchronize current client with source
  * [SERVER](SERVER.md) CMD police distribute - distribute sw to the client or clients
  * [SERVER](SERVER.md) system config file structure and options

Implementation details
  * Written in Perl 5, using common utilities and modules available in CentOS system.
  * Documentation is written as a part of source code in the perl-doc language.
  * Output in the .tar.gz and .rpm form available through sourceforge or googlecode web site.
  * System divided into the server and client part. Communication between those two must not endanger both of them.

Communication protocol
The server and client comunicate inside of the SSH protocol. The communication is based on XML exchange. The protocol uses a simple query-response interaction. The server which connects to the client sends the configuration content and waits for the client response. The client perform actions required by server and returns the output data or error code with description.

The example of the data sent by the server:
```
 <server>
   <paths>
      <path flags="[+M-5]">path_Pattern2</path>
      <path flags="[+5-UG]">path_pattern2</path>
      ...
   </paths>
   <actions>
     <scan/>
     <backup/>
   </actions>
 </server>
```

The server/paths/path define flags for a path.
The second part of the file defines actions to perform on the client side.
  * server/actions/scan - tell to the client to perform scan directory structure and send the output report to the server
  * server/actions/backup - tell to the client to perform backup of the configuration files (paths defined with +B flag)

After that communication part the server still keep the connection and wait for the client outputs. The output is dependend on the actions reqired by the server.

```
  SERVER: open connection
  SERVER: sned request to the client 
  CLIENT: returns required data or errors
  SERVER: close connection 
```

The output from the client side for the previous request might by follow:

```
 <client>
   <capabilites> 
     <scan/>
     <backup/>
   </capabilities> 
   <scan>
      <file name="/usr/local/etc" cksum="sxxxx" size="1000" guid="0" ....>
   </scan> 
   <backup>
      tgz of the binnary data
   </backup>
   <services>
      <service name="service_name" levels="0123456"/>
   </services>
   <rpms>
      <rpm name="package_name">
   </rpms>
 </client>
```

There are also error output in the response:

```
 <client>
   <capabilites> 
     <backup/>
   </capabilities> 
   <error>No scan allowed - see client cpabilities</error> 
   <backup>
      tgz of the binnary data
   </backup>
 </client>
```

or:

```
 <client>
   <capabilites> 
     <backup/>
     <scan/>
     <services/>
     <rpms/>
   </capabilities> 
   <error>The client is already in progres</error> 
 </client>
```


The meaning of the items is follow:
> clinet/capabilites - the list of the capabilities (actions) supported by the client
> client/scan/file   - the output data for the scanning process. As the attributes the values of the scanned items are returned
> client/backup      - data of the backup process
> client/error       - this tag is send when the error ocures on the client side. The errors are passed as the textual information.