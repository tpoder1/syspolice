package Police::Scan::Lst;

use strict;
use warnings;

use POSIX qw(strftime setsid);
use Data::Dumper;
use File::Basename;
use Fcntl ':mode';
use Police::Log;
use XML::Parser;


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


##########################################################
# XML Parser Handlers                                    #
##########################################################
# XML server parsing hooks
sub HandleXmlBegin {
	my ($expat, $element, %attrs ) = @_;
	my $path = join('/', (@{$expat->{'Context'}}, $element));
	my $self = $expat->{'Self'};

	if ($path eq "listfile/file") {
		my $name = $attrs{"name"};
		my %hash;
		$name =~ s/\%([A-Fa-f0-9]{2})/pack('C', hex($1))/seg;

		$attrs{"package"} = "lst:".$self->{'Package'};
		$self->{FilesRef}->{$name} = { %attrs };
		$self->{FilesRef}->{$name} = { %attrs };

		if (defined($self->{ScanHook})) {
			$self->{ScanHook}->($self, $name, \%attrs);
		}
		if (defined($self->{FilesRef})) {
			$self->{FilesRef}->{$name} = \%attrs;
		}
	}

	return 1;
}


=head2 ScanLst

Compare two RPM names an return result - election is based on the version number
# Try to find a rpm file specified by the name in @RPMDB
# If more files are found choose the newest one
# if any files didn't found prit error

=cut
sub ScanLst($$$) {
	my ($self, $lstname) = @_;

	# parse the XML input from the client
	my $xmlhnd = new XML::Parser(Handlers => {
		'Start' => \&Police::Scan::Lst::HandleXmlBegin ,
	});

	my $res = $xmlhnd->parsefile($lstname, ErrorContext => 3, Self => $self );
}

=head2 ScanPkg

Public interface:
Sacn directory/add the $self->files structure
	$pkg => package name
=cut

sub ScanPkg {
	my ($self, $pkg) = @_;

	my $lstname = $pkg;
	$self->{Package} = $pkg;

	if ($self->ScanLst($lstname)) {
		$self->{Log}->Debug(5, "Scanned lst package %s for %s (file: %s)", $pkg, $self->{Config}->{SysName}, $lstname);
	}
}


1;

