
package Police::Server;

use strict;
use warnings;

use POSIX qw(strftime setsid);
use File::Basename;
use Police::Log;
use Police::Paths;
use Police::Edit;
use Police::Scan::Dir;
use Police::Scan::Rpm;
use Police::Scan::Tgz;
use Police::Scan::Lst;
use Data::Dumper;
use MLDBM qw (DB_File Storable);
use XML::Parser;
use Mail::Send;
use MIME::Base64 qw(decode_base64 encode_base64);
use Sys::Hostname;
use Fcntl qw/:seek/;
use IPC::Open3;
use Cwd;

#use File::Glob ':globally';


# flags definition
# M,5,U,G,S,L,D,T - inconsistent value (Mode, md5, User, Group, Size, Link path, Dev id, mTime)
# special flags 
# A - autocommit file
# B - perform backup on the file
# F - send difference butween corrent and prevous backup through email
my %FLAGSMAP = (
	'N' => 'name',
	'M' => 'mode',
	'5' => 'md5',
	'U' => 'user',
	'G' => 'group',
	'S' => 'size',
	'L' => 'symlink',
	'D' => 'dev',
	'T' => 'mtime',
	'A' => 'autocommit',
	'B' => 'backup',
	'F' => 'senddiff'
	);

# defines file types and output format definition
# the first item describes fields to compare and the secon print format for this fields
# output format will be used in report
# the first filed is also determine which fields will be used for compare
my %FTYPEFMT = (
	'-' => [ 'UGMS5',   '%s:%s  %s %6sB %s' ],
	'd' => [ 'UGM',     '%s:%s  %s' ],
	'l' => [ 'L',       '---> %s' ],
	'c' => [ 'UGMD',    '%s:%s %s' ],
	's' => [ 'UGMS',   '%s:%s  %s %6sB' ],
	'p' => [ 'UGMS',   '%s:%s  %s %6sB' ],
	'b' => [ 'UGMD',   '%s:%s  %s %s' ],
	'n' => [ 'N',      '%s: nonexists' ]
	);

# the definition of the statistics, defines 
# types, output formats, ...
# items : type, description , order
# available types: 
# t      - timestamp, for this type the start date/time and duration is stored 
#          the firist using of StatSet stores the inital date and the second stores diff time
#          other use of the StatAdd stores the difference between last and previous measure
#		   If the value is not handed ovet the actual timestamp is used. 
# T      - pure date time including date and time
# s      - string value (the simple tex value is stored into statistics)
# <type> - any format which can be used in the printf function 
my %STATSDEF = (
	'files_client'    => [ 'd',   'Client files',         110 ],
	'files_server'    => [ 'd',   'Server files',         120 ],
	'files_same'      => [ 'd',   'Same files',           130 ],
	'files_differend' => [ 'd',   'Differend files',      140 ],
	'files_missed'    => [ 'd',   'Missed files',         160 ],
	'files_dwelled'   => [ 'd',   'Dwelled files',        170 ],
	'files_skipped'   => [ 'd',   'Skipped files',        180 ],
	'time_client'     => [ 't',   'Client scan time',     210 ],
	'time_server'     => [ 't',   'Server scan time',     220 ],
	'time_report'     => [ 't',   'Report creating time', 240 ],
	'time_total'      => [ 't',   'Total check time',     300 ]
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

	# set list handle  or create the new one 
	if (!defined($params{Edit})) {
		$class->{Edit} = Police::Edit->new();
	} else {
		$class->{Edit} = $params{Edit};
	}
#	$class->{Log}->Prefix($hostid.": ");

	# set base dir
	$class->{CfgDir} = defined($params{CfgDir}) ? $params{CfgDir} : "/etc/police/";

	# load host config 
	$class->{Config} = Police::Conf->new($hostid, BaseDir => $class->{CfgDir}, Log => $class->{Log} );	

	$class->{Config}->SetMacro("system", $hostid);
	$class->{Config}->SetMacro("servername", hostname());

	my ($wrkdir) = $class->{Config}->GetVal("dbdir");	
	# sewt workdir, add hostid and create the directory if doesn't not exists
	if (!defined($wrkdir)) {
		$class->{WorkDir} =  "/var/police/".$hostid;
	} else {
		$class->{WorkDir} = $wrkdir;
	}

	if ( ! -d $class->{WorkDir} ) {
		$class->{Log}->Log("Creating working directory %s", $class->{WorkDir});
		if ( ! mkdir($class->{WorkDir}) ) {
			$class->{Log}->Error("ERR can not create directory %s ($!) ", $class->{WorkDir});
			return undef;
		}
	}

	# where the paths definition are stored
	$class->{Paths} = Police::Paths->new();	
	my @paths = $class->{Config}->GetVal("path");
	foreach (@paths) {
		$class->{Paths}->AddPath($_);
	}

	# get current directory
	$class->{CurrDir} = cwd(); 

	$class->{BackupFile} = $class->{WorkDir}.'/backup.tgz';
	$class->{Config}->SetMacro("backupfile", $class->{BackupFile});

	# tie some hash variables
	my (%client, %server, %diff, %statistics);
	tie %diff, 'MLDBM', $class->{WorkDir}.'/diff.db';
	tie %statistics, 'MLDBM', $class->{WorkDir}.'/statistics.db';
	$class->{DiffDb} = \%diff;
	$class->{Statistics} = \%statistics;
	
	return $class;
}


sub DESTROY {
    my ($self) = @_;

	untie  %{$self->{DiffDb}};
	untie  %{$self->{Statistics}};
	
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
		$name =~ s/\%([A-Fa-f0-9]{2})/pack('C', hex($1))/seg;
		$self->DbAddFile('C', $name, \%attrs);
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
			$self->{Log}->Progress("scanning the clinet... done\n");
			$self->{Log}->Debug(10, "creating the backup file '%s'", $self->{BackupFile}); 
		} else {
			$handle = $self->{BackupHandle};
		}
#		printf "YYY: %s | %s | %s \n", $path, $element, join(" : ", %attrs);
		$self->{BseackupReceived} += length($char);
		$self->{Log}->Progress("retreiving backup data... %sB", HSize($self->{BackupReceived})); 

		if (defined($self->{BackupBuffer})) {
			$self->{BackupBuffer} .= $char;
		} else {
			$self->{BackupBuffer} = $char;
		}

	
		if ($char eq "\n" && defined($self->{BackupBuffer})) {
			print $handle decode_base64($self->{BackupBuffer});
			$self->{BackupBuffer} = undef;
		}
	} elsif ($path eq "client/errors/error") {
		chomp $char;
		$self->{Log}->Error("CLIENT: %s", $char);
	} elsif ($path eq "client/messages/mssage") {
		chomp $char;
		$self->{Log}->Progress("CLIENT: %s", $char);
	}
}

##########################################################
# Statistics routines                                    #
##########################################################
=head2 StatSet

# set value to statistics
# $item -  a name of the item
# $value - a value of the intem

=cut

sub StatSet {
	my ($self, $item, $val) = @_;

	# check id data type is defined for item, if not the default type (s) is being used
	if (defined($STATSDEF{$item}->[0]) && $STATSDEF{$item}->[0] eq 't') {
		$val = time() if (!defined($val));
	} elsif (defined($STATSDEF{$item}->[0]) && $STATSDEF{$item}->[0] eq 'T') {
		$val = time() if (!defined($val));
	} else {
		$val = 0 if (!defined($val));
	}
	$self->{Statistics}->{$item} = $val;
}

=head2 StatAdd

# Add value to statistics
# $item -  a name of the item
# $value - a value of the intem

=cut
sub StatAdd {
	my ($self, $item, $val) = @_;

	# check id data type is defined for item, if not the default type (s) is being used
	my $type = "s";
	if (defined($STATSDEF{$item}->[0])) {
		$type = $STATSDEF{$item}->[0];
	}

	# the type 't' have a little bit differend behaviour
	if ($type eq 't') {
		$val = time()  if (!defined($val));
		if (defined($self->{Statistics}->{$item})) {
			$self->{Statistics}->{$item} = $val - $self->{Statistics}->{$item};
		} else {
			$self->{Statistics}->{$item} = 0;
		}
	} elsif ($type eq 's' || $type eq 'T') {
		$self->{Statistics}->{$item} = $val;
	} else {
		if (defined($self->{Statistics}->{$item})) {
			$self->{Statistics}->{$item} += $val;
		} else {
			$self->{Statistics}->{$item} = 1;
		}
	}
}

=head2 StatGeItem

# Add value to statistics
# $item -  a name of the item
# $value - a value of the intem

=cut
sub StatGetItem {
	my ($self, $item) = @_;

	if (defined($self->{Statistics}->{$item})) {
		return $self->{Statistics}->{$item};
	} else {
		return "?";
	}
}

=head2 StatPrint

# Print all stattistics

=cut
sub StatPrint {
	my ($self, @list) = @_;

	sub srt {
		return 0 if (!defined($STATSDEF{$a}->[2]) || !defined($STATSDEF{$b}->[2]));
		return $STATSDEF{$a}->[2] <=> $STATSDEF{$b}->[2];
	}

	my $res = "";
	foreach my $item ( sort srt keys %{$self->{Statistics}} ) {
		# check id data type is defined for item, if not the default type (s) is being used
		my ($type, $descr) = ('s', $item);
		if (defined($STATSDEF{$item}->[0])) {
			$type = $STATSDEF{$item}->[0];
			$descr = $STATSDEF{$item}->[1];
		}

		if ($type eq 't') {
			my $diff = $self->{Statistics}->{$item};
			$res .= sprintf "  %-20s : %02d:%02ds\n", $descr, ($diff / 60), ($diff % 60);
		} elsif ($type eq 'T') {
			my $tm = $self->{Statistics}->{$item};
			$res .= sprintf "  %-20s : %02d:%02ds\n", $descr, strftime("%Y-%m-%d %H:%S", localtime($tm));
		} else {
			$res .= sprintf "  %-20s : %6s\n", $descr, $self->StatGetItem($item);
		}
	}
	return $res;
}

=head2 PkgScanHook

This subroutine is called when the file is scanned 
# $cmd - command to execute
# $input - file name which shoul be used as input to execute command 
Returns handle where the output from the client is passed or undef if the command wasn't successfull.

=cut

sub PkgScanHook {
	my ($self, $file, $atts) = @_;

	$self->{Parrent}->DbAddFile('S', $file, $atts);
}

=head2 DbAddFile

Add file into File databas
# $type -  Client | Server
# $name -  file name
# $atts -  sttributes - reference

=cut

sub DbAddFile {
	my ($self, $type, $file, $atts) = @_;

	my %diff;

	# load current record from databse (if exists)
	if (exists($self->{'DiffDb'}->{$file})) {
		%diff = %{$self->{'DiffDb'}->{$file}};
	}

	if ($type eq 'S') {		# server side
		$self->StatAdd('files_server', 1);
		$diff{'Server'} = { %{$atts} };
	} else {				# client side
		$self->StatAdd('files_client', 1);
		$diff{'Client'} = { %{$atts} };
		$self->{Log}->Progress("scanning the client ... path:%s", $file);
	}

	# determine type and flags onfly if the fiels id not defined yet

	if (!exists $diff{'Flags'}) {

		# determine file type, load flags and dterine flags to check
		my $mtype = substr(exists $diff{'Client'} ? $diff{'Client'}->{'mode'} : $diff{'Server'}->{'mode'} , 0, 1);
		my $mtypeflags =  $FTYPEFMT{$mtype}->[0];			# flags to be check (depends on file type)

		if (!defined($mtypeflags)) {
			$self->{Log}->Error("Unknown outuput format (\$FTYPEFMT) for '%s' (file: %s)", $mtype, $file);
			print Dumper(\%diff);
			return;
		}

		# determine flags to be checked... (depends on path) 
		my %flags =  $self->{Paths}->GetPathFlags($file, $mtypeflags.'A') ;
		$diff{'Flags'} = { %flags };
	} 

	# there are no flags to chek - we'll continune with another file
	if (keys %{$diff{'Flags'}} == 0 || (keys %{$diff{'Flags'}} == 1 && exists $diff{'Flags'}->{'A'}) ) {
		$self->StatAdd('files_skipped', 1);
		$diff{'Flags'} = { };
		# update recort in DB and continue with another file
		$self->{'DiffDb'}->{$file} = \%diff;
		return;
	}

	# if tehere is both client and server side defined try to determine diffrence
	if ( exists $diff{'Client'} && exists $diff{'Server'} ) {

		# determine wchich attributes are differend 
		delete($diff{'Flags'}->{'+'}) if defined $diff{'Flags'}->{'+'};
		delete($diff{'Flags'}->{'-'}) if defined $diff{'Flags'}->{'-'};
		foreach my $flag (keys %{$diff{'Flags'}} ) {
			my $att = $FLAGSMAP{$flag};		# deterine the attribute name
			if (exists($diff{'Server'}->{$att}) && exists($diff{'Client'}->{$att}) && $diff{'Server'}->{$att} eq $diff{'Client'}->{$att}) {
				delete($diff{'Flags'}->{$flag});
			}
		}

		# there are no differences between server and client 
		if (keys %{$diff{'Flags'}} == 0 || (keys %{$diff{'Flags'}} == 1 && exists $diff{'Flags'}->{'A'}) ) {
			$diff{'Flags'} = { };
		} 
	} elsif (!exists $diff{'Client'} && exists $diff{'Server'}) {
		$diff{'Flags'}->{'-'} = 1;
	} elsif (exists $diff{'Client'} && !exists $diff{'Server'}) {
		$diff{'Flags'}->{'+'} = 1;
	}

	# update recort in DB
	$self->{'DiffDb'}->{$file} = \%diff;
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

	# change the current directory
	chdir($self->{CurrDir});

	my $rcmd = sprintf("ssh -o BatchMode=yes %s \"(%s)\" ", $hostname, $cmd);
	if (defined($input) && $input ne "") {
		$rcmd .= sprintf(" < %s ", $input);
	}


	$self->{Log}->Log("Connecting to the host %s ", $hostname); 
	$self->{Log}->Debug(10, "Conncet comand '%s'", $rcmd); 
	$self->{Log}->Progress("connecting to the host %s... ", $hostname); 

	# prepre handles 
	my $hin;
	my $hout;
	my $herr = IO::File->new_tmpfile;
	my $pid = open3($hin, $hout, $herr, $rcmd);
	if (! $pid ) {
		$self->{Log}->Error("ERR can not execute command %s (%s).", $rcmd, $!); 
		return undef;
	}

	# timeout for ssh connect XXX
#	my $forked = fork();
#	die "fork() failed: $!" unless defined $forked;
#	if ( $forked == 0 ) {
#		sleep 1200;
#		kill(9, $pid);
#		print "\n\n\nTIMEOUTED\n\n\n";
#		exit;
#	}

	$self->{Log}->Progress("connecting to the host %s... done\n", $hostname); 

	return ($hout, $herr, $hin);
	
}


=head2 Check

Perform client checks

=cut

sub Check {
	my ($self) = @_;



	# remove the old diff.db and statistics.db files
	untie $self->{DiffDb};
	untie $self->{Statistics};
	unlink($self->{WorkDir}.'/diff.db');
	unlink($self->{WorkDir}.'/statistics.db');
	my (%diff, %statistics);
	tie %diff, 'MLDBM', $self->{WorkDir}.'/diff.db';
	tie %statistics, 'MLDBM', $self->{WorkDir}.'/statistics.db';
	$self->{DiffDb} = \%diff;
	$self->{Statistics} = \%statistics;

	$self->StatSet('files_differend');
	$self->StatSet('files_missed');
	$self->StatSet('files_same');
	$self->StatSet('files_dwelled');
	$self->StatSet('files_skipped');

	if ($self->ScanClient()) {
		$self->ScanPackages();
		$self->MkReport();
	}


}


=head2 ScanClient

Connect to the host and perform scanning, fill in $seld->{DiffDb}->{Client} structure 

=cut

sub ScanClient {
	my ($self) = @_;

	$self->StatSet('time_client');
	$self->StatSet('time_total');
	$self->StatSet('files_client');

	(tied(%{$self->{DiffDb}}))->CLEAR();		# clear database

	my @request = ();
	# prepare request for the client 
	push(@request, "\t<paths>");
	my @paths = $self->{Config}->GetVal("path");
	foreach (@paths) {
		push(@request, sprintf "\t\t<path>%s</path>", $_) if(defined($_) && $_ ne "");
	}
	push(@request, "\t</paths>");
	push(@request, "\t<actions>");
	push(@request, "\t\t<scan/><backup/>");
	push(@request, "\t</actions>");

	# connect to the host and run command 
	my $sstart = time();

	my $ret = $self->RequestClient(@request);

	$self->{Log}->Log("Host %s scanned in %d secs", $self->{HostId}, time() - $sstart); 

	$self->StatAdd('time_client');
	return $ret;
}

=head2  RequestClient

Prepare basic XML request, send to the client and parse the output

=cut

sub RequestClient {
	my ($self, @requestcmd) = @_;

	# prepare request for the client 
	my $reqfile = sprintf("%s/request.xml", $self->{WorkDir} );
	open REQF, ">$reqfile";
	printf REQF "\n";
	printf REQF "<server>\n";
	foreach (@requestcmd) {
		if (/^FILE: (.+)$/) {
			open F1, "< $1";
			my $buf;
			while (read(F1, $buf, 60*57)) {
				print REQF encode_base64($buf);
			} 
			close F1; 
		} else {
			print REQF $_."\n";
		}
	}
	printf REQF "</server>\n";
	close REQF;

	# repair XXX
	my ($cmd) = $self->{Config}->GetVal("scancmd");
	if (!defined($cmd) || $cmd eq "") {
		$cmd = "police-client";
	}
	my ($hout, $herr) = $self->RemoteCmd($cmd, $reqfile);


	if (defined($hout)) { 
		sleep(2);

		# parse the XML input from the client
		my $xmlhnd = new XML::Parser(Handlers => {
   	             'Start' => \&Police::Server::HandleXmlBegin ,
   	             'Char' => \&Police::Server::HandleXmlChar
   	             });

		eval { my $res = $xmlhnd->parse($hout, ErrorContext => 3, Self => $self ); };
		if ($@) { 
			$self->ErrReport("Error when parsing the client output");
		}
	}

	my $buf;
#	$herr |= O_NONBLOCK;
	while (read($herr, $buf, 1024)) {
		chomp $buf;
		if ($buf =~ /\n/) {
			$buf = "\n".$buf;
			$buf = join("\n   ", split("\n", $buf));
		}
		$self->ErrReport("Error when connecting the host, msg: %s", $buf); 
		return 0;
	}

	return 1;
}

=head2 ScanPackages

Perform package scanning on the server side, fill in $self->{ServerDb} structure 

=cut

sub ScanPackages {
	my ($self) = @_;

	$self->StatSet('time_server');
	$self->StatSet('files_server');

	# clean-up the client database
	my %scan;

	$scan{'dir'} = Police::Scan::Dir->new(Log => $self->{Log}, Config => $self->{Config}, ScanHook => \&PkgScanHook, Parrent => $self );
	$scan{'rpm'} = Police::Scan::Rpm->new(Log => $self->{Log}, Config => $self->{Config}, ScanHook => \&PkgScanHook, Parrent => $self );
	$scan{'tgz'} = Police::Scan::Tgz->new(Log => $self->{Log}, Config => $self->{Config}, ScanHook => \&PkgScanHook, Parrent => $self );
	$scan{'lst'} = Police::Scan::Lst->new(Log => $self->{Log}, Config => $self->{Config}, ScanHook => \&PkgScanHook, Parrent => $self );

#	$scan{'dir'}->SetPathsDef($self->{Config}->GetVal("path"));
#	$scan{'rpm'}->SetPathsDef($self->{Config}->GetVal("path"));

	my @dirpkgs = $self->{Config}->GetVal("pkg");
	foreach (@dirpkgs) {
		my ($type, $pkg) = split(/:/, $_);

		if (defined($scan{$type})) {
			$self->{Log}->Progress("scanning packages... %s:%s", $type, $pkg);
			$scan{$type}->ScanPkg($pkg);
		# unknown package type 
		} else {
			$self->{Log}->Error("ERR unknown the package type %s:%s", $type, $pkg); 
		}
		$self->{Log}->Progress("scanning packages... done");
#		$self->{Log}->Debug(10, "Conncet comand %s", $cmd); 
	}

	$self->StatAdd('time_server');
#	$self->{Log}->Log("Host %s scanned in %d secs", $self->{HostId}, time() - $sstart); 
	
}

#######################################################################
# Email and report rutines 
#######################################################################

=head2 InfoReport

Add string into the report. If the SendEmail flag is set then add into report file. If not print to stdout.

=cut

sub InfoReport {
	my ($self, $fmt, @arg) = @_;

	my $str = sprintf($fmt, @arg); 
	
	if (!defined($self->{RepHandle})) {
		$self->{RepFile} = $self->{WorkDir}."/report.txt.$$";
		open $self->{RepHandle}, "> $self->{RepFile}";
	}
	my $handle = $self->{RepHandle};
	print $handle $str;
}

=head2 Report

Add string into the report. If the SendEmail flag is set then add into report file. If not print to stdout.

=cut

sub Report {
	my ($self, $fmt, @arg) = @_;

	$self->{NonEmptyReport} = 1;
	$self->InfoReport($fmt, @arg);
}


=head2 ErrReport

Add string into the report. If the SendEmail flag is set then add into report file. If not print to stdout.

=cut

sub ErrReport {
	my ($self, $fmt, @arg) = @_;
	$self->{Log}->Error($fmt, @arg);
	$self->Report($fmt."\n", @arg);

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

		if ( -f $self->{RepFile} ) {
			open $fs, "< $self->{RepFile}";
		} else {
			$self->{Log}->Error("can not open report file %s", $self->{RepFile});
			return;
		}

		# the report to stdout is only required
		if (!defined($sendemail) || !$sendemail) {
			while (<$fs>) {
				print $_;
			}
			close $fs;
			return; 
		}


		# test if the report is empty and shuld be send 
		if (!defined($self->{NonEmptyReport}) && (defined($sendempty) && $sendempty)  ) {
			$self->{Log}->Progress("Empty report, no data to send\n");
			return;
		}

		my @mails = $self->{Config}->GetVal('email');

		#check if the any mail address is set 
		if (@mails == 0 || $mails[0] eq "") {
			$self->{Log}->Error("ERR no recipients defined\n");
			return 0;
		}
		my ($subject) = $self->{Config}->GetVal("subject"); 
		my ($lines) = $self->{Config}->GetVal("maxlines"); 
		my ($from) = $self->{Config}->GetVal("mailfrom"); 

		$subject = sprintf("[POLICE] report for %s", $self->{HostId}) if (!defined($subject) || $subject eq "");
		$lines = 4000 if (!defined($lines) || $lines eq "");

		my %rcpts;
		foreach my $mail (@mails) {	
			next if (defined($rcpts{$mail}));
			$self->{Log}->Progress("sending the report... recipient:%s", $mail);

			my  $msg = Mail::Send->new(Subject => $subject, To => $mail);
			$msg->set('From', $from) if (!defined($from) || $from ne "");
			my $fd = $msg->open;

			while (<$fs>) {
				print $fd $_ if ($lines-- > 0);
			}

			if ($lines < 0 ) {
				printf $fd "\n\n\n....\n\nWARNING: %d lines has been truncated.\n", -1 * $lines;
			}
			close $fd;
			seek $fs, 0, SEEK_SET;
			$rcpts{$mail} = 1;
		}

		close $fs;
		$self->{Log}->Progress("sending the report... done\n");
	}	
	unlink($self->{RepFile}) if defined($self->{RepFile});

}

#######################################################################
# Diff and report part 
#######################################################################

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

	# missing description 
	#if (!defined($at{'mode'}) && defined($at{'nonexists'})) {
	if (!defined($at{'mode'})) {
		return sprintf "missing (%s)", join(':', %at);
	}

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



=head2 MkReport

check serverlist and clientlist and add flags

=cut
sub MkReport {
	my ($self) = @_;

	# traverse client list and set a flag
	# the flags are
	# + file is missing on client side
	# - file is left over on client side

	$self->StatSet('time_report');

	$self->{Log}->Progress("creating the diff report...");

	# traverse all files from both the client and the side
	my $cnt = 0;
	my $maxcnt = keys %{$self->{'DiffDb'}};

#	while ( my ($file, $diff) = each %{$self->{'DiffDb'}}) {
	foreach my $file (sort keys %{$self->{'DiffDb'}}) {
		my $diff = $self->{'DiffDb'}->{$file};
 
		$self->{Log}->Progress("creating the diff report... %d%%",  $cnt++ / $maxcnt * 100);

		# tehere in nothing to report
		if (keys %{$diff->{'Flags'}} == 0) {
			$self->StatAdd('files_same', 1);
			next;
		}


		# skip files which are defined as nonexists and are not on the client side
		next if ( exists $diff->{'Server'} && exists $diff->{'Server'}->{'nonexists'} && !exists $diff->{'Client'} );

		# add to autocommit
		$self->AutoCommitAdd($file) if exists $diff->{'Flags'}->{'A'};

		# update statistics
		if (exists $diff->{'Flags'}->{'-'}) {
			$self->StatAdd('files_missed', 1);
		} elsif (exists $diff->{'Flags'}->{'+'}) {
			$self->StatAdd('files_dwelled', 1);
		} else {
			$self->StatAdd('files_differend', 1);
		}

		$self->Report("%s  [%s]\n", $file, join("", sort keys %{$diff->{'Flags'}}));
		$self->Report("   C %s \n", DescribeFile(%{$diff->{'Client'}}) ) if exists $diff->{'Client'};
		$self->Report("   S %s [%s]\n", DescribeFile(%{$diff->{'Server'}}), $diff->{'Server'}->{'package'} ) if exists $diff->{'Server'};
		$self->Report("\n");

	}

	$self->AutoCommitFinish();

	# close total statistics
	$self->StatAdd('time_total');
	$self->StatAdd('time_report');

	$self->InfoReport("\n\nStatistics:\n");
	$self->InfoReport($self->StatPrint());

	$self->{Log}->Progress("creating the diff report... done\n");
}

=head2 Download

Download files which are differend to server
@masks - list of masks to match files 

=cut
sub Download {
	my ($self, @masks) = @_;

	my $flist = $self->{List}->InitList();

#	while ( my ($file, $diff) = each %{$self->{'DiffDb'}}) {
	foreach my $file (sort keys %{$self->{'DiffDb'}}) {
		my $diff = $self->{'DiffDb'}->{$file};

		# skip files which are defined as nonexists and are not on the client side
		next if (keys %{$diff->{'Flags'}} == 0);
		next if ( exists $diff->{'Server'} && exists $diff->{'Server'}->{'nonexists'} && !exists $diff->{'Client'} );

		if (defined($diff->{Client})) {
			printf $flist "%-60s   # %s\n", $file, DescribeFile(%{$diff->{Client}});
		}
	}

	if (!$self->EditList()) {
		return 0;
	}

	chdir($self->{CurrDir});
	my ($hout, $herr) = $self->RemoteCmd("tar -c -z --no-recursion --numeric-owner -T- -f- ", $self->{Edit}->GetEdFile($self->{HostID}));
	open FOUT, "> download.tgz";
	while (<$hout>) {
		print FOUT $_;
	}	
	close FOUT;
	close $hout;
}

=head2 GetConfig

Print parsed config file - this output is used to install a new system

=cut
sub GetConfig {
	my ($self) = @_;

	printf "\n# config for %s\n", $self->{HostId};
	my @atts = $self->{Config}->GetAtts();
	foreach my $att (@atts) {
		my @vals = $self->{Config}->GetVal($att);
		foreach my $val (@vals) {
			printf "%-25s%s\n", $att, $val;
		}
		printf "\n";
	}
	printf "\n# end config for %s\n\n", $self->{HostId};

}

=head2 PrepareInstall

Prepare files nescesary for instaltion

=cut
sub PrepareInstall {
	my ($self) = @_;
	
	# ksfile
	# kstemplate
	my ($ks) = $self->{Config}->GetVal("ksfile");
	my ($kst) = $self->{Config}->GetVal("kstemplate");
	my ($ksdata) = $self->{Config}->GetVal("ksdata");

	if (!defined($kst) || $kst eq "" || ! -f $kst) {
		$self->{Log}->Error("The option \"kstemplate\" not defined or file does not exists");
		return;
	}

	# get package list 
	my @pkgs = $self->{Config}->GetVal("pkg");

	# preparing kickstart file 
	$self->{Log}->Progress("Preparing kickstart file %s...", $ks);
	open F1, "< $kst";
	open F2, "> $ks";
	while (<F1>) {
		if (/(.*)%{(.*)}(.*)/) {
			my ($pre, $key, $post) = ($1, $2, $3);
			my @vals;
			if ($2 eq "pkg:rpm") {
				foreach (@pkgs) {
					my ($type, $pkg) = split(":");
					if ($type eq "rpm") {
						push(@vals, $pkg);
					}
				}
			} else {
				@vals = $self->{Config}->GetVal($2);
			}

			if (@vals > 0) {
				printf F2 "%s%s%s", $pre, join("\n", @vals), $post;
			}
			
		} else {
			print F2 $_;
		}
	}
	close F1;
	close F2;
	
	$self->{Log}->Progress("Preparing kickstart file %s... done\n", $ks);

	# preparing dir and tgz packages 
	my ($tmpdir) = $self->{Config}->GetVal("dbdir");

	my $tdir = $tmpdir."/_tmp.tar.$$.".time();
	mkdir $tdir;
	if (! chdir $tdir) {
		$self->{Log}->Error("ERR can not change the directory to %s/%s", $tmpdir, $tdir);
		return;
	}

	if (!defined($ksdata) || $ksdata eq "") {
		return;
	}

	my %tgz;
	$tgz{'dir'} = Police::Scan::Dir->new(Log => $self->{Log}, Config=> $self->{Config});
	$tgz{'tgz'} = Police::Scan::Tgz->new(Log => $self->{Log}, Config=> $self->{Config});
	foreach (@pkgs) {
		my ($type, $pkg) = split(":");
		if (defined($tgz{$type})) {
			my $cmd = $tgz{$type}->GetTgzCmd($pkg);
			if (defined($cmd)) {
				my $fcmd = sprintf("%s | tar xzvf - --numeric-owner  ", $cmd);
				$self->{Log}->Progress("Preparing kickstart arvhive for %s:%s...", $type, $pkg);
				open F1, "$fcmd 2>&1 | "; 
				while (<F1>) {
					chomp;
					$self->{Log}->Progress("Preparing kickstart arvhive for %s:%s... %s", $type, $pkg, $_);
				}
				close F1;
				$self->{Log}->Progress("Preparing kickstart arvhive for %s:%s... done\n", $type, $pkg);
			}
		}
	}

	$self->{Log}->Progress("Creating output archive %s...", $ksdata);
	my $packcmd = sprintf("tar czf %s -C %s .", $ksdata, $tdir);
	system($packcmd); 
	system("rm -rf \"$tdir\"");
	$self->{Log}->Progress("Creating output archive %s... done\n", $ksdata);

}


=head2 GetLst

Prepare lst file based on diff from the prevous run 

=cut
sub GetLst {
	my ($self, $filename) = @_;

	my $flist = $self->InitList();

	#while ( my ($file, $diff) = each %{$self->{'DiffDb'}}) {
	foreach my $file (sort keys %{$self->{'DiffDb'}}) {
		my $diff = $self->{'DiffDb'}->{$file};

		# skip files which are defined as nonexists and are not on the client side
		next if (keys %{$diff->{'Flags'}} == 0);
		next if ( exists $diff->{'Server'} && exists $diff->{'Server'}->{'nonexists'} && !exists $diff->{'Client'} );

		printf $flist "%-60s   # %s\n", $file, DescribeFile(%{$diff->{Client}});
	}

	if (!$self->EditList()) {
		return 0;
	}

	$filename = "filelist.xml" if (!defined($filename) || $filename eq "");

	open FLIST, $self->{Edit}->GetEdFile($self->{HostID});
	open FOUT, ">$filename";

	printf FOUT "<listfile created=\"%s\">\n", strftime("%Y-%m-%dT%H:%M:%S", localtime);

	while (my $file = <FLIST>) {
		chomp $file;	
		my $diff = $self->{'DiffDb'}->{$file};

    	my $atts = "";
		if (defined($diff->{Client})) {
			while (my ($key, $val) = each %{$diff->{Client}}) {
				$atts .= sprintf("%s=\"%s\" ", $key, $val) if (defined($val) && $key ne "name");
			} 
		} else {
			$atts = "nonexists=\"1\"";
		}
		
	
		# encode file name
		$file =~ s/([^-_.~A-Za-z0-9\/ \+\:\@])/sprintf("%%%02X", ord($1))/seg;
	    printf FOUT "\t<file name=\"%s\" %s/>\n", $file, $atts;
	}
	print FOUT "</listfile>\n";
	close FOUT;
	close FLIST;
	$self->{Log}->Progress("Data has been writen into %s...\n", $filename);

}

=head2 SyncClient

Sync client according to the server

=cut
sub SyncClient {
	my ($self, $filename) = @_;

	my $flist = $self->{Edit}->InitList();

	printf $flist "\n";
	printf $flist "# switch to the system \n";
	printf $flist "system %-18s  \n\n", $self->{HostId} ;

	#while ( my ($file, $diff) = each %{$self->{'DiffDb'}}) {
	foreach my $file (sort keys %{$self->{'DiffDb'}}) {
		my $diff = $self->{'DiffDb'}->{$file};

		# skip same files
		next if ( keys %{$diff->{'Flags'}} == 0 );
		next if ( exists $diff->{'Flags'}->{'A'} );
		next if ( exists $diff->{'Server'} && exists $diff->{'Server'}->{'nonexists'} && !exists $diff->{'Client'} );

		my @cmd = ();
		my $qfile = $file;
		$qfile = sprintf('"%s"', $file) if ($file =~ /\s/);;

		# dwelled file  - we have to remove them
		if ( exists $diff->{'Flags'}->{'+'} ) {
			push(@cmd, [ "remove", "", $qfile ]);	
#			if ($diff->{Client}->{'mode'} =~ /^d.+/) {
#				push(@cmd, [ "remove", "", $qfile ]);	
#			} else {
#				push(@cmd, [ "remove", "", $qfile ] );	
#			}
		# missed & differend file
		} else {
			if ( (exists $diff->{'Flags'}->{'-'} || exists $diff->{'Flags'}->{'5'} ) && !exists $diff->{'Flags'}->{'L'} ) {
				if ($diff->{'Server'}->{'package'} =~ /dir:|tgz:/ ) {
					push(@cmd, [ "get", $diff->{'Server'}->{'package'}, $qfile ] );
				} else {
					push(@cmd, [ "# ?", "", $qfile ] );
				}
			}
			if ( exists $diff->{'Flags'}->{'U'} || exists $diff->{'Flags'}->{'G'} ) {
				my $ugr = $diff->{'Server'}->{'user'}.":".$diff->{'Server'}->{'group'};
				push(@cmd, [ "chown", $ugr, $qfile ] );
			}
			if ( exists $diff->{'Flags'}->{'M'} ) {
				my $perm = "";	
				if ( $diff->{'Server'}->{'mode'} =~ /.(...)(...)(...)/ ) {
					$perm = "u=$1,g=$2,o=$3";
				}
				$perm =~ s/\-//g;

				push(@cmd, [ "chmod", $perm, $qfile ] );
			}
			if ( exists $diff->{'Flags'}->{'L'} ) {
				push(@cmd, [ "link", $diff->{'Server'}->{'symlink'}, $qfile ] );
			} 

			if (@cmd == 0) {
				push(@cmd, [ "#nocmd", "", $qfile ] );
			}
		}	

		#printf $flist "%-60s   # [%s] \n", $cmd, join("", sort keys %{$diff->{'Flags'}}) ;
		printf $flist "\n# %s \n", $file if (@cmd > 1);
		my $pkg = "";
		$pkg = $diff->{'Server'}->{'package'} if ( exists $diff->{'Server'} );
		foreach (@cmd) {
			printf $flist "%-6s %-18s %-60s   # [%5s] %s \n", $_->[0], $_->[1], $_->[2],  join('', sort keys %{$diff->{'Flags'}}), $pkg;
		}	
		print $flist "\n" if (@cmd > 1);
	}

	if (!$self->{Edit}->EditList()) {
		return 0;
	}

	# prepare structures to send to the client 
	my @request = ();
	my $edlist = $self->{Edit}->GetEdFile($self->{HostID});
	open F1, "< $edlist";
	while (<F1>) {
		chomp;
		my ($cmd, $arg) = split(/\s+/, $_, 2);

		if ($cmd eq 'system') { next; }
		# we'll handle get comman in a differend way 
		if ($cmd eq 'get') { 
			my ($package, $file) = split(/\s+/, $arg, 2);
			my ($ptype, $pkg) = split(/:/, $package);
			my ($pkgdir) = $self->{Config}->GetVal("pkgdir");
			my $origfile = sprintf "%s/%s/%s", $pkgdir, $pkg, $file;

			push(@request, sprintf "<command cmd=\"%s\" arg=\"%s\">", $cmd, $file);

			# read original file and create base64 output
			push(@request, sprintf  "FILE: %s\n", $origfile);
			push(@request, "</command>\n");
		} else {
			push(@request, sprintf "<command cmd=\"%s\" arg=\"%s\"/>\n", $cmd, $arg);
		}
	}

	$self->RequestClient(@request);
	$self->{Log}->Progress("Client has been synced...\n");

}


=head2 Commit

Commit changes into %{commitdir} direcotry named as YYY-MM-DD.HH.MM.SS-commit.xml

=cut
sub Commit {
	my ($self) = @_;

	my ($commitdir) = $self->{Config}->GetVal("commitdir");

	if (!defined($commitdir) || $commitdir eq "") {
		$self->{Log}->Error("The value of %{commitdir} variable not defined");
		return undef;
	}

	if ( ! -d $commitdir ) {
		if (! mkdir $commitdir) {
			$self->{Log}->Error("Can not create the directory %s", $commitdir);
			return undef;
		}
	}

	my $filename = sprintf("%s/%s-commit.xml", $commitdir, strftime("%Y-%m-%dT%H:%M:%S", localtime));

	return $self->GetLst($filename);
	
}

=head2 AutoCommitAdd

Add the file into autocommit file 

=cut
sub AutoCommitAdd {
	my ($self, $file) = @_;

	my $handle;

	if (!defined($self->{CommitHandle})) {
			my ($commitdir) = $self->{Config}->GetVal("commitdir");
			if (!defined($commitdir) || $commitdir eq "") {
				$self->{Log}->Error("The value of %{commitdir} variable not defined");
				return undef;
			}

			if ( ! -d $commitdir ) {
				if (! mkdir $commitdir) {
					$self->{Log}->Error("Can not create the directory %s", $commitdir);
					return undef;
				}
			}

			my $filename = sprintf("%s/%s-auto-commit.xml", $commitdir, strftime("%Y-%m-%dT%H:%M:%S", localtime));
			$self->{CommitFile} = $filename;
			open $handle, "> $filename.tmp";
			$self->{CommitHandle} = $handle;

			printf $handle "<listfile created=\"%s\">\n", strftime("%Y-%m-%dT%H:%M:%S", localtime);
	} else {
		$handle = $self->{CommitHandle};
	}

	my $diff = $self->{'DiffDb'}->{$file};

   	my $atts = "";
	if (defined($diff->{Client})) {
		while (my ($key, $val) = each %{$diff->{Client}}) {
			$atts .= sprintf("%s=\"%s\" ", $key, $val) if (defined($val) && $key ne "name");
		} 
	} else {
		$atts = "nonexists=\"1\"";
	}

	# encode file name
	$file =~ s/([^-_.~A-Za-z0-9\/ \+\:\@])/sprintf("%%%02X", ord($1))/seg;
    printf $handle "\t<file name=\"%s\" %s/>\n", $file, $atts;
}

=head2 AutoCommitFinish

Close the autocommit file and release handle

=cut
sub AutoCommitFinish {
	my ($self) = @_;

	if (defined($self->{CommitHandle})) {
		my $handle = $self->{CommitHandle};
		print $handle "</listfile>\n";
		close $handle;
		rename($self->{CommitFile}.'.tmp', $self->{CommitFile});
	}
}

1;
