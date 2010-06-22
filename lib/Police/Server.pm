
package Police::Server;

use strict;
use warnings;

use POSIX qw(strftime setsid);
use File::Basename;
use Police::Log;
use Police::Scan::Dir;
use Police::Scan::Rpm;
use Police::Scan::Tgz;
use Police::Scan::Lst;
use Data::Dumper;
use MLDBM qw (DB_File Storable);
use XML::Parser;
use Mail::Send;
#use File::Glob ':globally';


# flags definition
# M,5,U,G,S,L,D,T - inconsistent value (Mode, md5, User, Group, Size, Link path, Dev id, mTime)
my %FLAGSMAP = (
	'M' => 'mode',
	'5' => 'md5',
	'U' => 'user',
	'G' => 'group',
	'S' => 'size',
	'L' => 'symlink',
	'D' => 'dev',
	'T' => 'mtime'
	);

# defines file types and output format definition
# the first item describes fields to compare and the secon print format for this fields
# output format will be used in report
# the first filed is also determine which fields will be used for compare
#my %FTYPEMAP = (
#   '-' => [ 'UGTMS5',  '%s:%s %10s  %s %6sB %s' ],
#   'd' => [ 'UGTM',    '%s:%s %10s  %s' ],
#   'l' => [ 'L',       '---> %s' ],
#   'c' => [ 'UGMD',    '%s:%s %s' ]
#   );

my %FTYPEFMT = (
	'-' => [ 'UGMS5',   '%s:%s  %s %6sB %s' ],
	'd' => [ 'UGM',     '%s:%s  %s' ],
	'l' => [ 'L',       '---> %s' ],
	'c' => [ 'UGMD',    '%s:%s %s' ]
	);


=head1 NAME

Server - layer privides police server functionlity (scanning hosts, scanning packages, create diffs, ...)

=head1 SYNOPSIS

=head1 DESCRIPTION

=head1 METHODS

=head2 new
 Condtructor - arg 
  new($hostid, CfgDir => dir , WorkDir => dir, Log => log_handle ); 
  $file => <file name in the base dir> 
  CfgDir => <base_config_directory> (deflault /etc/police)
  WorkDir => working directory (directory where the database and other files are stored)
  Log => reference to log class 

=cut

sub new {
	my ($self, $hostid, %params) = @_;
	my ($class) = {};
	bless($class);

	$class->{HostId} = $hostid;

	# set log handle  or create the new one 
	if (!defined($params{Log})) {
		$class->{Log} = Police::Log->new();
	} else {
		$class->{Log} = $params{Log};
	}

	$class->{Log}->Prefix($hostid." > ");

	# set base dir
	$class->{CfgDir} = defined($params{CfgDir}) ? $params{CfgDir} : "/etc/police/";

	# sewt workdir, add hostid and create the directory if doesn't not exists
	$class->{WorkDir} = defined($params{WorkDir}) ? $params{WorkDir} : "/tmp";
	$class->{WorkDir} .= "/".$hostid;
	if ( ! -d $class->{WorkDir} ) {
		$class->{Log}->Log("Creating working directory %s", $class->{WorkDir});
		if ( ! mkdir($class->{WorkDir}) ) {
			$class->{Log}->Error("ERR can not create directory %s ($!) ", $class->{WorkDir});
			return undef;
		}
	} 

	# load host config 
	$class->{Config} = Police::Conf->new($hostid, BaseDir => $class->{CfgDir}, Log => $class->{Log} );	

	my @paths = $class->{Config}->GetVal("path");
	$class->{PathsDef} = [ @paths ];

	$class->{BackupFile} = $class->{WorkDir}.'/backup.tgz.b64';

	# tie some hash variables
	my (%client, %server, %diff);
	tie %client, 'MLDBM', $class->{WorkDir}.'/client.db';
	tie %server, 'MLDBM', $class->{WorkDir}.'/server.db';
	tie %diff, 'MLDBM', $class->{WorkDir}.'/diff.db';
	$class->{ClientDb} = \%client;
	$class->{ServerDb} = \%server;
	$class->{DiffDb} = \%diff;
	
	return $class;
}


sub DESTROY {
    my ($self) = @_;

	untie  %{$self->{ClientDb}};
	untie  %{$self->{ServerDb}};
	untie  %{$self->{DiffDb}};
	
}

sub test() {
	my ($self, $key) = @_;

	printf "XXX %s XXX\n", join(",", $self->{Config}->GetVal("rpmpkg"));

}



##########################################################
# XML Parser Handlers                                    #
##########################################################
# XML server parsing hooks
sub HandleXmlBegin {
	my ($expat, $element, %attrs ) = @_;
	my $path = join('/', (@{$expat->{'Context'}}, $element));
	my $self = $expat->{'Self'};

	if ($path eq "client/scan/file") {
		my $name = $attrs{"name"};
		my %hash;
		$self->{ClientDb}->{$name} = { %attrs };
		if ($attrs{'mode'} =~ /^d.+/) {
			$self->{Log}->Progress("scanning the clinet... dir:%s", $name);
		}
#		printf "XXX: %s | %s | %s \n", $path, $element, join(" : ", %attrs);
	}
}

sub HandleXmlChar {
	my ($expat, $char) = @_;
	my $path = join('/', @{$expat->{'Context'}});
	my $self = $expat->{'Self'};

	if ($path eq "client/backup") {
		my $handle;
		if (!defined($self->{BackupHandle})) {
			open $handle, "> $self->{BackupFile}";
			$self->{BackupHandle} = $handle;
			$self->{BackupReceived} = 0;
			$self->{Log}->Debug(10, "Creating the backup file '%s'", $self->{BackupFile}); 
		} else {
			$handle = $self->{BackupHandle};
		}
#		printf "YYY: %s | %s | %s \n", $path, $element, join(" : ", %attrs);
		$self->{BackupReceived} += length($char);
		$self->{Log}->Progress("retreiving backup data... (%sB)", HSize($self->{BackupReceived})); 
		print $handle $char;
	}
}


=head2 RemoteCmd

Perform cmd on the remote host defined by config file.  
# $cmd - command to execute
# $input - file name which shoul be used as input to execute command 
Returns handle where the output from the client is passed or undef if the command wasn't successfull.

=cut

sub RemoteCmd {
	my ($self, $cmd, $input) = @_;

	my ($hostname) = $self->{Config}->GetVal("hostname"); 
	if (!defined($hostname) || $hostname eq "") {
		$self->{Log}->Error("ERR can not determine the hostname");
		return undef;
	}

	my $rcmd = sprintf("ssh %s  \"(%s)\" ", $hostname, $cmd);
	if (defined($input) && $input ne "") {
		$rcmd .= sprintf(" < %s ", $input);
	}
	$self->{Log}->Log("Connecting to the host %s ", $hostname); 
	$self->{Log}->Debug(10, "Conncet comand '%s'", $rcmd); 
	$self->{Log}->Progress("connecting to the host %s... ", $hostname); 
	my $handle;
	if (! open $handle, "$rcmd |" ) {
		$self->{Log}->Error("ERR can not execute command %s (%s).", $rcmd, $!); 
		return undef;
	}
	$self->{Log}->Progress("connecting to the host %s... done\n", $hostname); 

	return $handle;
	
}


=head2 ScanClient

Connect to the host and perform scanning, fill in $seld->{ClientDb} structure 

=cut

sub ScanClient {
	my ($self) = @_;

	# prepare request for the client 
	my $reqfile = sprintf("%s/request.xml", $self->{WorkDir} );
	open REQF, ">$reqfile";
	printf REQF "\n";
	printf REQF "<server>\n";
	printf REQF "\t<paths>\n";
	foreach  ($self->{Config}->GetVal("path")) {
		printf REQF "\t\t<path>%s</path>\n", $_;
	}
	printf REQF "\t</paths>\n";
	printf REQF "\t<actions>\n";
	printf REQF "\t\t<scan/>\n";
	printf REQF "\t\t<backup/>\n";
	printf REQF "\t</actions>\n";
	printf REQF "</server>\n";
	close REQF;

	# clean-up the client database
	(tied(%{$self->{ClientDb}}))->CLEAR();

	# connect to the host and run command 
	my $sstart = time();

	# repair XXX
	my $handle = $self->RemoteCmd("police-client", $reqfile);

	if (defined($handle)) { 
		sleep(5);

		# parse the XML input from the client
		my $xmlhnd = new XML::Parser(Handlers => {
   	             'Start' => \&Police::Server::HandleXmlBegin ,
   	             'Char' => \&Police::Server::HandleXmlChar
   	             });

		my $res = $xmlhnd->parse($handle, ErrorContext => 3, Self => $self );
		$self->{Log}->Log("Host %s scanned in %d secs", $self->{HostId}, time() - $sstart); 
		
	}
	$self->{Log}->Progress("scanning the clinet... done\n");
	
}

=head2 ScanPackages

Perform package scanning on the server side, fill in $self->{ServerDb} structure 

=cut

sub ScanPackages {
	my ($self) = @_;

	# clean-up the client database
	(tied(%{$self->{ServerDb}}))->CLEAR();

	my %scan;

	$scan{'dir'} = Police::Scan::Dir->new(Log => $self->{Log}, Config=> $self->{Config}, FilesRef => \%{$self->{ServerDb}});
	$scan{'rpm'} = Police::Scan::Rpm->new(Log => $self->{Log}, Config=> $self->{Config}, FilesRef => \%{$self->{ServerDb}});
	$scan{'tgz'} = Police::Scan::Tgz->new(Log => $self->{Log}, Config=> $self->{Config}, FilesRef => \%{$self->{ServerDb}});
	$scan{'lst'} = Police::Scan::Lst->new(Log => $self->{Log}, Config=> $self->{Config}, FilesRef => \%{$self->{ServerDb}});

#	$scan{'dir'}->SetPathsDef($self->{Config}->GetVal("path"));
#	$scan{'rpm'}->SetPathsDef($self->{Config}->GetVal("path"));

	$self->{Log}->Progress("scnanning packages...");

	my @dirpkgs = $self->{Config}->GetVal("pkg");
	foreach (@dirpkgs) {
		my ($type, $pkg) = split(/:/, $_);

		$self->{Log}->Progress("scanning packages... %s:%s", $type, $pkg);
		# rpm package type
		if ($type eq "rpm") {
			$scan{'rpm'}->ScanPkg($pkg);
		# dir package type 
		} elsif ($type eq "dir") {
			$scan{'dir'}->ScanPkg($pkg);
		} elsif ($type eq "tgz") {
			$scan{'tgz'}->ScanPkg($pkg);
		} elsif ($type eq "lst") {
			$scan{'lst'}->ScanPkg($pkg);
		} elsif ($type eq "xxxpkg") {

		# unknown package type 
		} else {
			$self->{Log}->Error("ERR unknown a package type %s:%s", $type, $pkg); 
		}
#		$self->{Log}->Debug(10, "Conncet comand %s", $cmd); 
	}

	$self->{Log}->Progress("scanning packages... done\n");

#	$self->{Log}->Log("Host %s scanned in %d secs", $self->{HostId}, time() - $sstart); 
	
}

#######################################################################
# Email and report rutines 
#######################################################################

=head2 Report

Add string into the report. If the SendEmail flag is set then add into report file. If not print to stdout.

=cut

sub Report {
	my ($self, $fmt, @arg) = @_;

	my $str = sprintf($fmt, @arg); 
	
	if (!defined($self->{RepHandle})) {
		$self->{RepFile} = $self->{WorkDir}."/report.txt.$$";
		open $self->{RepHandle}, "> $self->{RepFile}";
	}
	my $handle = $self->{RepHandle};
	printf $handle $str;
}

=head2 SendReport

Send the report to the users (if any)
@ send the report throuhh an eail 
@ sent the report either it contains only info data

=cut

sub SendReport {
	my ($self, $sendemail, $sendempty) = @_;

	if (defined($self->{RepFile})) {
		close $self->{RepHandle};
		my $fs;
		open $fs, "< $self->{RepFile}";

		# the report to stdout is only required
		if (!defined($sendemail) || !$sendemail) {
			while (<$fs>) {
				print $_;
			}
			close $fs;
			return; 
		}

		my @mails = $self->{Config}->GetVal('email');

		#check if the any mail address is set 
		if (@mails == 0 || $mails[0] eq "") {
			$self->{Log}->Error("ERR no recipients defined\n");
			return 0;
		}
		my ($subject) = $self->{Config}->GetVal("email:subject"); 
		my ($lines) = $self->{Config}->GetVal("email:lines"); 
		my ($from) = $self->{Config}->GetVal("email:from"); 

		$subject = sprintf("[POLICE] report for %s", $self->{HostId}) if ($subject eq "");
		$lines = 1000 if ($lines eq "");

		foreach my $mail (@mails) {	
			$self->{Log}->Progress("sending the report... recipient:%s", $mail);

			my  $msg = Mail::Send->new(Subject => $subject, To => $mail);
			$msg->set('From', $from) if ($from ne "");
			my $fd = $msg->open;

			while (<$fs>) {
				print $fd $_ if ($lines-- > 0);
			}

			if ($lines < 0 ) {
				printf $fd "\n\n\n....\n\nWARNING: %d lines has been truncated.\n", -1 * $lines;
			}
			close $fd;
			close $fs;
		}

		$self->{Log}->Progress("sending the report... done\n");
	}	

}

#######################################################################
# Diff and report part 
#######################################################################


# add flags into the path, compute flags to the path
# @ arg        - flags prefix also possible (eg. "/usr", "[+M+G]/usr", "[+M-G+U+T]", "[-M+T]", ...)
# return flags - result flags enclosed in []
# return path  - path in clear forrmat  - if input path not defined returns undef
#
sub AddFlags {
	my ($self, @args) = @_;

	my $path = undef;
	my %flags;

	# traverse all arguments
	foreach my $arg (@args) {
		# try to split the path and flags from arguments
		if ($arg =~ /\[(.+)\](.*)/) {
			if (defined($2) && $2 ne "") {
				$path = $2;
			}
			%flags = $self->GetFlags($1);
		} else {
			$path = $arg;
		}
	}

	my $sflags = "";
	while (my ($key, $val) = each %flags) {
		$sflags .= sprintf("%1s%1s", $val, $key);
	}

	$sflags = "[".$sflags."]";

	return ($sflags, $path);
}

# return hash with possitive flags set
# @ flags - input string with flags inf ormat [+x+x...]
# @ mask  - +      return only possive flags,
#           -      return only negative flags,
#           undef  return the positive and negative flags
sub GetFlags {
	my ($self, $flags, $mask) = @_;

	my %flags;

	$flags =~ s/^\[//;
	$flags =~ s/\]$//;

	my $sign = undef;
	foreach (split(//, $flags)) {
		# the sign symbol
		if ($_ eq "+" || $_ eq "-") {
			$sign = $_;
		} else {
			if (defined($sign) && (!defined($mask) || $sign eq $mask)) {
				$flags{uc($_)} = $sign;
			}
		}
	}

	return %flags;
}

=head2 Glob2Pat

Converts the shell pattern to the regexp pattern

=cut

sub Glob2Pat {
	my ($self, $globstr) = @_;

	my %patmap = (
		'*' => '.*',
		'?' => '.',
		'[' => '[',
		']' => ']',
	);
	$globstr =~ s{(.)} { $patmap{$1} || "\Q$1" }ge;
	return '^' . $globstr . '$';
}


=head2 GetPathFlags

Returns flags list for the particular directory

=cut

# return flags for particular dir
# @ path
# @ hashref to path definition
# return - hash array with positive flags
sub GetPathFlags {
	my ($self, $path) = @_;

	my $resflags = '[+UGM5TL]';
	foreach my $flagpath (@{$self->{PathsDef}}) {
		my ($flags, $pattern) = $self->AddFlags($flagpath);
		$pattern = $self->Glob2Pat($pattern);
		if ($path =~ /$pattern/) {
			($resflags) = $self->AddFlags($resflags, $flags);
		}
	}

	my %flags = $self->GetFlags($resflags, '+');

	return %flags;
}

# convert value to human readable string
sub HSize($) {
	my ($size) = @_;
	if (!defined($size) || $size eq "") {
		return "-";
	}
	my $str = $size;
	if ($size > 1000) {
		$str = sprintf("%3.1fk", $size / 1000);
		if ($size > 1000 * 1000) {
			$str = sprintf("%3.1fM", $size / (1000 * 1000));
			if ($size > 1000 * 1000 * 1000) {
				$str = sprintf("%3.1fG", $size / (1000 * 1000 * 1000));
				if ($size > 1000 * 1000 * 1000 * 1000) {
					$str = sprintf("%3.1fT", $size / (1000 * 1000 * 1000 * 1000));
				}
			}
		}
	}
	return $str;
}


# create file description (format information)
sub DescribeFile {
	my (%at) = @_;

	my $type = substr($at{'mode'}, 0, 1);
	my $str;

	# prepare some fields
	if (defined($at{'mtime'})) {
		$at{'mtime'} = strftime("%Y-%m-%d.%T", localtime($at{'mtime'}));
	}
	if (defined($at{'size'})) {
		$at{'size'} = HSize($at{'size'});
	}

	# load data FTMAP and prepare the output
	if (defined($FTYPEFMT{$type})) {
		my ($fields, $format)  =  (@{$FTYPEFMT{$type}});
		my @vals = ();
		foreach my $flagname ( split(//, $fields) ) {
			my $attname = $FLAGSMAP{$flagname};
			if (defined($at{$attname})) {
				push(@vals, $at{$attname});
			} else {
				push(@vals, '-:-');
			}
		}

		$str = sprintf($format, @vals);
	} else {
		$str = sprintf("Unknown type %s !", $type);
	}

	return $str;
}



=head2 MkDiff

check serverlist and clientlist and add flags

=cut
sub MkDiff {
	my ($self) = @_;

	# traverse client list and set a flag
	# the flags are
	# + file is missing on client side
	# - file is left over on client side

	my %stats = ( 'client' => 0, 'server' => 0, 'skipped' => 0, 'same' => 0, 'missed' => 0, 'dwelled' => 0, 'differend' => 0 );

	$self->{Log}->Progress("creating the diff report...");
	(tied(%{$self->{DiffDb}}))->CLEAR();

	# blend the client and the server list into ones 
	while ( my($file, $atts) =  each  %{$self->{'ServerDb'}}) {
		my %diff;
		$diff{'Server'} = { %{$atts} };
		$self->{'DiffDb'}->{$file} = \%diff ;
		$stats{'server'}++;
	}
	
	while ( my($file, $atts) =  each  %{$self->{'ClientDb'}}) {
		my %diff;
		if (defined($self->{'DiffDb'}->{$file})) {
			%diff = %{$self->{'DiffDb'}->{$file}};
		}
		$diff{'Client'} = { %{$atts} };
		$self->{'DiffDb'}->{$file} = \%diff;
		$stats{'client'}++;
	}

	# traverse all files from both the client and the side
	my $cnt = 0;
	my $maxcnt = $stats{'server'} > $stats{'client'} ? $stats{'server'} : $stats{'client'};
	while ( my ($file, $diff) = each %{$self->{'DiffDb'}}) {

		$self->{Log}->Progress("creating the diff report... %d%%",  $cnt++ / $maxcnt * 100);

		my $client =  $diff->{Client} if (defined($diff->{Client}));
		my $server =  $diff->{Server} if (defined($diff->{Server}));

		# determine file type, load flags and dterine flags to check
		my $type = substr(defined($server) ? $server->{'mode'} : $client->{'mode'} , 0, 1);
		my %setflags = $self->GetPathFlags($file);
		my $chkflags =  $FTYPEFMT{$type}->[0];
		my %flags = ();

# 		printf "XXXX $file: $chkflags %s\n", join('', %setflags);

		foreach (split(//, $chkflags)) {
			if (defined($setflags{$_})) {
				$flags{$_} = $FLAGSMAP{$_};
			}
		}

		# go to a next file if there are no flags to check
		if (keys %flags == 0) {
			delete($self->{'DiffDb'}->{$file});
			$stats{'skipped'}++;
			next;
		}

		#  we are going to test 3 states 
		# 1. the file is on both the server and the client side
		# 2. the file is only on server side 
		# 3.  e is only on client side 
		if (defined($server) && defined($client)) {
			# test which flags are differend
			while (my ($flag, $att) = each %flags) {
				if (defined($server->{$att}) && defined($client->{$att}) && $server->{$att} eq $client->{$att}) {
					delete($flags{$flag});
				}
			}
			# remove from diffile if there are no any differences
			if ( keys(%flags) == 0 ) {
				delete($self->{'DiffDb'}->{$file});
					$stats{'same'}++;
				next;	# skip to an another file
			} else {
					$stats{'differend'}++;
			}
		} elsif (defined($server) && !defined($client)) {
			$flags{'-'} = 'miss';
			$stats{'missed'}++;
		} elsif (!defined($server) && defined($client)) {
			$flags{'+'} = 'dwell';
			$stats{'dwelled'}++;
		} else {
			$self->{Log}->Error("ERR file %s was not found ither client or server side", $file);
			next;
		}
		
		$self->Report("$file  [%s]\n", sort join("", keys %flags));
		$self->Report("   C %s \n", DescribeFile(%{$client})) if (defined($client));
		$self->Report("   S %s [%s]\n", DescribeFile(%{$server}), $server->{'package'}) if (defined($server));
		$self->Report("\n");
	}

	$self->Report("\n\nStatistics:\n");
	while (my ($key, $val) = each %stats) {
		$self->Report(" %s -> %s \n", $key, $val);
	}

	$self->{Log}->Progress("creating the diff report... done\n");
}

=head2 InitList

Open handle to edit list, empty the file and set $self->{EdList}

=cut
sub InitList {
	my ($self) = @_;

	$self->{EdFile} = $self->{WorkDir}.'/EdList.'.$$;
	open $self->{EdHandle}, "> $self->{EdFile}";
	my $handle = $self->{EdHandle};
	printf $handle "# All data after a hash sign (#) or empty lines will be ignored.\n";
	printf $handle "# \n";

	return $handle;

}

=head2 EditList

Edit list and return true or false the changes has been accepted
During editing all textt after # are removed

=cut
sub EditList {
	my ($self) = @_;

	close $self->{EdHandle};

	system("vim $self->{EdFile}");

	printf "Do you accept changes (y/N) ? ";
	my $input = <STDIN> ;
	printf "\n";
	if ( $input !~ /y|Y/ ) {
		return 0;
	}
	
	# remove empty lines and data after hash 
	my $tmpfile = $self->{EdFile}.".tmp";
	my ($in, $out);
	rename($self->{EdFile}, $tmpfile);
	open $in, "< $tmpfile";
	open $out, "> $self->{EdFile}";
	while (<$in>) {
		chomp;
		my ($line) = split(/#/); 
		$line =~ s/\s+$//g; 		# remove spaces at the end of the string
		if ($line ne "") {
			printf $out "%s\n", $line;
		}
	}
	close $in;
	close $out;

	open $self->{EdHandle}, "< $self->{EdFile}";

	return 1;
}


=head2 Download

Download files which are differend to server
@masks - list of masks to match files 

=cut
sub Download {
	my ($self, @masks) = @_;

	my $flist = $self->InitList();

	while ( my ($file, $diff) = each %{$self->{'DiffDb'}}) {
		if (defined($diff->{Client})) {
			printf $flist "%-60s   # %s\n", $file, DescribeFile(%{$diff->{Client}});
		}
	}

	if (!$self->EditList()) {
		return 0;
	}

	my $handle = $self->RemoteCmd("tar -c -z --no-recursion --numeric-owner -T- -f- ", $self->{EdFile});
	open FOUT, "> download.tgz";
	while (<$handle>) {
		print FOUT $_;
	}	
	close FOUT;
	close $handle;
}

1;

