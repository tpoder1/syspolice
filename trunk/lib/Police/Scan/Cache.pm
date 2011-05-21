package Police::Scan::Cache;

use strict;
use warnings;

use POSIX qw(strftime setsid);
use Data::Dumper;
use File::Basename;
use Police::Log;
use XML::Parser;
use Digest::MD5 qw(md5_base64);


=head1 NAME

Scan::Cache - cache for package scanning 

=head1 SYNOPSIS

=head1 DESCRIPTION
 The class provides cache for package scanning 

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
	if (defined($params{Parrent})) {
		$class->{Parrent} = $params{Parrent};
	}
	if (defined($params{Config})) {
		$class->{Config} = $params{Config};
	}
	return $class;
}

##########################################################
# Hooks for scanning procedures
##########################################################
=head2 RpmPkgHook => \&RpmPkgHook

This subroutine is called when the package is found
# $pkg - package name

=cut

sub RpmPkgHook {
	my ($self, $pkg) = @_;

	if (defined($self->{RpmPkgHook})) {
		$self->{RpmPkgHook}->($self, $pkg);
	}
}

=head2 PkgScanHook

This subroutine is called when the file is scanned 
# $cmd - command to execute
# $input - file name which shoul be used as input to execute command 
Returns handle where the output from the client is passed or undef if the command wasn't successfull.

=cut

sub PkgScanHook {
	my ($self, $file, $atts) = @_;

	if (defined($self->{ScanHook})) {
		$self->{ScanHook}->($self, $file, $atts);
	}
	
	my $fh = $self->{CacheHandle};
	print $fh "AHOJ\n";
}



##########################################################
# XML Parser Handlers                                    #
##########################################################
# XML server parsing hooks
sub HandleXmlBegin {
	my ($expat, $element, %attrs ) = @_;
	my $path = join('/', (@{$expat->{'Context'}}, $element));
	my $self = $expat->{'Self'};

	if ($path eq "cache/package/file") {
		my $name = $attrs{"name"};
		my %hash;
		$name =~ s/\%([A-Fa-f0-9]{2})/pack('C', hex($1))/seg;

		if (defined($self->{ScanHook})) {
			$self->{ScanHook}->($self, $name, \%attrs);
		}
		if (defined($self->{FilesRef})) {
			$self->{FilesRef}->{$name} = \%attrs;
		}
	} elsif ($path eq "cache/package") {
		my $name = $attrs{"name"};
		# package hook 
	}

	return 1;
}

=head2 GetPkgHash

Get hash for package 

=cut

sub GetPkgHash {
	my ($self, $type, $pkg) = @_;

	my ($cachedir) = $self->{Config}->GetVal("cachedir");
	$cachedir = "/var/police/_cache/" if (!defined($cachedir));

	if ( ! -d $cachedir ) {
		$self->{Log}->Log("Creating cache directory %s", $cachedir);
        if ( ! mkdir($cachedir) ) {
            $self->{Log}->Error("ERR can not create directory %s ($!) ", $cachedir);
            return undef;
        }
	}

	# items that participates on the hash function 
	my $md5 = md5_base64("$type:$pkg");
	foreach ("basearch", "arch", "rpmrepos", "pkgdir") {
		my (@arr) = $self->{Config}->GetVal($_);
		$md5 = md5_base64(join(":", @arr, $md5));
	}

	$md5 =~ s/\//x/g;
	return $cachedir."/".$md5.".xml";

}

=head2 Init

Public interface:
Initialize cache for package (create emty cache file) 
	$type => package type (rpm, tgz, dir, lst)
	$pkg => package name
=cut

sub Init {
	my ($self, $type, $pkg) = @_;

	my $cachefile = $self->GetPkgHash($type, $pkg);

	my $fh = $self->{CacheHandle};
	open $fh, "> $cachefile";
	printf $fh "<cache>\n";
	printf $fh "    <package name=\"%s\" type=\"%s\" created=\"%s\" >\n", $pkg, $type, strftime("%Y-%m-%dT%H:%M:%S", localtime);
	$self->{CacheHandle} = $fh;
	$self->{Log}->Debug(5, "Cache file for package %s is %s.", $pkg, $cachefile);
	
}

=head2 Finish

Public interface:
Close initialized cache file and commit into the cache
=cut

sub Finish {
	my ($self) = @_;

	if (defined($self->{CacheHandle})) {
		my $fh = $self->{CacheHandle};
		printf $fh "    </package>\n";
		printf $fh "</cache>\n";
		close $fh;
	}
	$self->{CacheHandle} = undef;
}


=head2 ScanPkg

Public interface:
Sacn directory/add the $self->files structure
	$pkg => package name
=cut

sub ScanPkg {
	my ($self, $type, $pkg) = @_;

	my $cachefile = $self->GerPkgHash($type, $pkg);

	my $fromcache = 0;	
	if ( -f $cachefile ) {
		# get cache ttl 
		my ($cachettl) = $self->{Config}->GetVal("cachettl");
		$cachettl = 120 if (!defined($cachettl));

		my ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size, $atime,$mtime,$ctime,$blksize,$blocks) = stat($cachefile);	

		if ($mtime + $cachettl > time() ) {
			$self->{Log}->Debug(5, "Scanning package %s form %s from cache (%s)", $pkg, $self->{Config}->{SysName}, $cachefile);
			my $xmlhnd = new XML::Parser(Handlers => {
				'Start' => \&Police::Scan::Cache::HandleXmlBegin ,
			});
			my $res = $xmlhnd->parsefile($cachefile, ErrorContext => 3, Self => $self );
			return 1;
		} else {
			$self->{Log}->Debug(5, "Cache for package %s form %s from cache (%s) expired.", $pkg, $self->{Config}->{SysName}, $cachefile);
		}
	}  else {
		$self->{Log}->Debug(5, "Cache for package %s form %s not found.", $pkg, $self->{Config}->{SysName});
	}

	return 0;

}


1;

