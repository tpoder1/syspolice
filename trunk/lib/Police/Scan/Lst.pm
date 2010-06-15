package Police::Scan::Lst;

use strict;
use warnings;

use POSIX qw(strftime setsid);
use Data::Dumper;
use File::Basename;
use Fcntl ':mode';
use Digest::MD5  qw(md5 md5_hex md5_base64);
#use File::Glob ':glob';
use File::Temp qw(tempfile);
use Police::Log;


=head1 NAME

Sacn - layer provides scannig directory functionality

=head1 SYNOPSIS

=head1 DESCRIPTION
The class provides directory scanning functionality

=head1 METHODS

=head2 new
	new->(Log => log_handle, ScanHook => &subrutine);
	Log => reference to log class
	ScanHook => reference to subrutine which is called after the file is scanned 
	FilesRef => reference to hash to fill with the scanned structure 
	the structure of the hook shoul be follow 
	sub function($$) {
		my ($class, $file, $ref) = @_;
	}
	$class - reference to class where subrutine is called
	$file - the file name
	$ref - reference to values of the scanned attributes 

=cut

sub new {
	my ($self, %params) = @_;
	my ($class) = {};
	bless($class);


	# set log handle  or create the new one
	if (!defined($params{Log})) {
		$class->{Log} = Police::Log->new();
	} else {
		$class->{Log} = $params{Log};
	}
	if (defined($params{ScanHook})) {
		$class->{ScanHook} = $params{ScanHook};
	}

	if (defined($params{FilesRef})) {
		$class->{FilesRef} = $params{FilesRef};
	}

	if (defined($params{Config})) {
		$class->{Config} = $params{Config};
	}
	return $class;
}


=head2 ScanRpm

Compare two RPM names an return result - election is based on the version number
# Try to find a rpm file specified by the name in @RPMDB
# If more files are found choose the newest one
# if any files didn't found prit error

=cut
sub ScanRpm($$$) {
	my ($self, $rpmname) = @_;

	# find the rpm file in a file system
	my $lastname = undef;
	foreach my $rpmdir ($self->{Config}->GetVal("basedir:rpm")) {
		my $cmd = sprintf("find %s -name \"%s*.rpm\" -print", $rpmdir, $rpmname);
		open F1, "$cmd|";
		while (my $file = <F1>) {
			chomp $file;

			my $found = 0;

			#check if current architecture is in supported achritectures
			foreach ($self->{Config}->GetVal("arch")) {
				$found = 1 if ($file =~ /.+\.$_\.rpm/);
			}
			if ($found) {
				$lastname = $file if (!defined($lastname) || CmpRpmName($lastname, $file, $self->{Config}->GetVal("arch")) == -1);
			}
		}
		close F1;
	}

	# check if we found any file
	if (!defined($lastname) || $lastname eq "") {
		$self->{Log}->Error("Neither RPM package %s found in %s.", $rpmname, join(", ", $self->{Config}->GetVal("basedir:rpm")));
		return 0;
	}

	# create a file list from the file

	my %rpmatts = ( 'FILESIZES' => 'size',  'FILEMODES:perms' => 'mode',
					'FILEMTIMES' => 'mtime',  'FILEMD5S' => 'md5', 'FILEUSERNAME' => 'user',
					'FILEGROUPNAME' => 'group', 'FILELINKTOS' => 'symlink' );
	my @attarr = keys(%rpmatts);

	my $tags = "%{FILENAMES}|";
	foreach (@attarr) {
		$tags .= sprintf("%%{%s}|", $_);
	}
	$self->{Log}->Debug(10, ("Loading files for from %s for %s", $lastname, $rpmname ));
	my $cmd = sprintf("rpm -q --nosignature --queryformat \"[%s\n]\" -p %s ", $tags, $lastname);

	open F1, "$cmd|";
	while (<F1>) {
		chomp;
		my ($filename, @val) = split(/\|/, $_);
		my %attrs;

		foreach my $x (0 .. @attarr - 1) {
#           printf "%s -> %s \n", $rpmatts[$x],  $val[$x - 1];
			my $att = $attarr[$x];
			my $att2 = $rpmatts{$att};
			$attrs{$att2} = $val[$x - 0] if (defined($val[$x - 0])) && $val[$x - 0] ne "";
		}
		if (defined($attrs{'symlink'})) {
			delete($attrs{'md5'});
#               delete($$f->{'mode'});
			delete($attrs{'user'});
			delete($attrs{'group'});
			delete($attrs{'size'});
			delete($attrs{'mtime'});
		}
		$attrs{'package'}        = "rpm: ".basename($rpmname);
#		$attrs{'packagetype'}    = "rpm";
#		$attrs{'packagename'}    = basename($lastname);
		$self->{FilesRef}->{$filename} = { %attrs };

		if (defined($self->{ScanHook})) {
			$self->{ScanHook}->($self, $filename, \%attrs);
		}
		if (defined($self->{FilesRef})) {
			$self->{FilesRef}->{$filename} = \%attrs;
		}
	}

	close F1;

	return $lastname;
}

=head2 ScanPkg

Public interface:
Sacn directory/add the $self->files structure
	$pkg => package name
=cut

sub ScanPkg {
	my ($self, $pkg) = @_;

	if (my $rpm = $self->ScanRpm($pkg)) {
		$self->{Log}->Debug(5, "Scanned rpm package %s for %s (rpm: %s)", $pkg, $self->{Config}->{SysName}, $rpm);
	}
}
1;

