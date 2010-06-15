package Police::Scan::Tgz;

use strict;
use warnings;

use Police::Scan::Dir;

our @ISA = qw(Police::Scan::Dir);

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
#	my ($class) = {};
	my ($class) = $self->SUPER::new(%params);
	bless($class);

#	# set log handle  or create the new one
#	if (!defined($params{Log})) {
#		$class->{Log} = CLog->new();
#	} else {
#		$class->{Log} = $params{Log};
#	}
#	if (defined($params{Config})) {
#		$class->{Config} = $params{Config};
#	}

	return $class;
}


=head2 ScanPkg

Public interface:
Sacn directory/add the $self->files structure
	$pkg => package name
=cut

sub ScanPkg {
	my ($self, $pkg) = @_;

	# find the propper path for the package  and perform scanning 
	my ($tmpdir) = $self->{Config}->GetVal("tmpdir");
	
	if (!defined($tmpdir) || $tmpdir eq "") {
		$tmpdir = "/tmp/police";
	}

	
	my ($pkgdir) = $self->{Config}->GetVal("basedir:tgz");
	
	my $pkgfile .= $pkgdir."/".$pkg;
	if  ($pkg !~ /.tgz$/) {
		$pkgfile .= ".tgz";
	}

	# test if the directory exists 
	if ( ! -f $pkgfile ) {
		$self->{Log}->Error("ERR the file %s for package %s not found", $pkgfile, $pkg, $self->{Config}->{SysName});
	} else {
		# unpack tgz file and scan 

		# check if the working directory exists a switch to them 
		mkdir $tmpdir if ( ! -d $tmpdir );
		if (! chdir $tmpdir ) {
			$self->{Log}->Error("ERR can not change the directory to %s", $tmpdir);
			return ; 
		}

		my $tdir = $tmpdir."/_tmp.tar.$$.".time();
		mkdir $tdir;
		if (! chdir $tdir) {
			$self->{Log}->Error("ERR can not change the directory to %s/%s", $tmpdir, $tdir);
			return;
		}
		
#		$self->{Log}->Progress("xtracting %s (tgz: %s)", $pkgfile, $pkg);
		system("tar xzf $pkgfile");
		$self->ScanDir($tdir, "tgz: ".$pkg);
		$self->{Log}->Debug(5, "Scanned tgz package %s for %s (tgz: %s)", $pkg, $self->{Config}->{SysName}, $pkgfile);
	}
}

1;

