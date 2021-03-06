package Police::Scan::Dir;

use strict;
use warnings;

use POSIX qw(strftime setsid);
use Data::Dumper;
use File::Basename;
use Fcntl ':mode';
#use File::Glob ':glob';
use File::Temp qw(tempfile);
use Police::Log;
use Police::Paths;


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
	if (defined($params{Parrent})) {
		$class->{Parrent} = $params{Parrent};
	}
	if (defined($params{Config})) {
		$class->{Config} = $params{Config};
	}

	$class->{Checksum} = "md5";

	# where the paths definition are stored
	$class->{Paths} = Police::Paths->new(); 

	return $class;
}

=head2 LsMode

Converts numeric file mode into text representation known from ls command

=cut

sub LsMode($$) {
	my ($self, $mode) = @_;

	if (!defined($mode)) {
		return "??????????";
	}

	my @flag;

	$flag[0] = S_ISDIR($mode) ? 'd' : '-';
	$flag[0] = 'l' if (S_ISLNK($mode));
	$flag[0] = 'b' if (S_ISBLK($mode));
	$flag[0] = 'c' if (S_ISCHR($mode)) ;
	$flag[0] = 'p' if (S_ISFIFO($mode));
	$flag[0] = 's' if (S_ISSOCK($mode));

	$flag[1] = ($mode & S_IRUSR) >> 6 ? 'r' : '-';
	$flag[2] = ($mode & S_IWUSR) >> 6 ? 'w' : '-';
	$flag[3] = ($mode & S_IXUSR) >> 6 ? 'x' : '-';
	$flag[3] = 's' if ($mode & S_ISUID);

	$flag[4] = ($mode & S_IRGRP) >> 3 ? 'r' : '-';
	$flag[5] = ($mode & S_IWGRP) >> 3 ? 'w' : '-';
	$flag[6] = ($mode & S_IXGRP) >> 3 ? 'x' : '-';
	$flag[6] = 's' if ($mode & S_ISGID);

	$flag[7] = ($mode & S_IROTH) >> 0 ? 'r' : '-';
	$flag[8] = ($mode & S_IWOTH) >> 0 ? 'w' : '-';
	$flag[9] = ($mode & S_IXOTH) >> 0 ? 'x' : '-';
	$flag[9] = 't' if ($mode & S_ISVTX);

#   ($mode & S_IRGRP) >> 3;

	return join('', @flag);
}

=head2 Md5Sum

Compute and return MD5 sum of the file

=cut
sub Md5Sum($$) {
	my ($self, $file) = @_;
	my ($fh, $digest);

	# load md5 module
	if (!$self->{Loaded}->{MD5}) {
		use Digest::MD5 qw(md5 md5_hex md5_base64);
		$self->{Loaded}->{MD5} = 1;
	}

	my $ctx = Digest::MD5->new;
	open $fh, "< $file";
	if ($fh) {
		my $ret = eval { $ctx->addfile(*$fh); };
		if (defined($ret)) {
			$digest = $ctx->hexdigest;
		} else {
			$digest = "*UNKNOWN*";
		}
	}

	return $digest;

}

=head2 ShaSum

Compute and return Sha256 sum of the file

=cut
sub ShaSum($$) {
	my ($self, $file) = @_;
	my ($fh, $digest);

	# load md5 module
	if (!$self->{Loaded}->{SHA}) {
		use Digest::SHA qw(sha256 sha256_hex sha256_base64);
		$self->{Loaded}->{SHA} = 1;
	}

	my $ctx = Digest::SHA->new(256);
	open $fh, "< $file";
	if ($fh) {
		my $ret = eval { $ctx->addfile(*$fh); };
		if (defined($ret)) {
			$digest = $ctx->hexdigest;
		} else {
			$digest = "*UNKNOWN*";
		}
	}

	return $digest;

}

=head2 RecursiveScanDir

Perform recrusive dir scanning. The method is called internally by the other functions
	@paths => list of paths in the format [+|-atts]/path where 

=cut


# scan a directory and resturn structure
# @ reference where a output structure should be stored
# @ package name
# @ start directory
# @ reference to path definition
sub RecursiveScanDir {
    my ($self, $package, $dir) = @_;

    if ($dir eq "") {
        $dir = ".* *";
    } else {
		$dir = "\"$dir/.*\" \"$dir/*\"";
    }

    while ($dir =~ /\/\//) {
        $dir =~ s/\/\//\//g;
    }

LOOP:
    foreach my $rfile (glob($dir)) {
#		printf "XXX $rfile\n";
		next if (substr($rfile, -2) eq ".." || substr($rfile, -1) eq ".");
        my $file = sprintf("/%s", $rfile);

        # get flags
        my %flags = $self->{Paths}->GetPathFlags($file);

        # skip if no flags were set
        if (keys(%flags) == 0) {
#           $self->{Log}->Progress("Skipping: %s", $file);
#           printf("\n\nSkipping: %s\n\n", $file);
            next;
        }

        # store a information about file
        my @inode = lstat($rfile);

#        $self->{Log}->Progress("Scanning: [+%s] %s", join('', sort keys %flags), $file);
#       printf("Scanning: [+@%s@] %s\n", join('@', sort keys %flags), $file);

        next if (!defined($inode[2]));

		# add files to baskup list the backu flag is set 
		if (defined($flags{'B'})) {
			push(@{$self->{BackupList}}, $rfile);
#			printf "BACKUP %s\n", $rfile;
		}

		my $ref;

        $ref->{"package"}          = $package;
#        $ref->{"packagename"}      = $package;
#        $ref->{"packagetype"}      = "dir";
        $ref->{"mode"}             = $self->LsMode($inode[2]);

        # check if file is symlink
        if (S_ISLNK($inode[2]) && defined($flags{'L'})) {
            $ref->{"symlink"}      = readlink($rfile);
        } else {
            $ref->{"size"}         = $inode[7];
            $ref->{"mtime"}        = $inode[9];

            # user and group
            if (defined($inode[4]) && defined($flags{'U'})) {
                if (defined(getpwuid($inode[4]))) {
                    $ref->{"user"} = getpwuid($inode[4]);
                } else {
                    $ref->{"user"} = $inode[4];
                }
            }

            if (defined($inode[5]) && defined($flags{'G'})) {
                if (defined(getgrgid($inode[5]))) {
                    $ref->{"group"}    = getgrgid($inode[5]);
                } else {
                    $ref->{"group"}    = $inode[5];
                }
            }

            if (S_ISDIR($inode[2])) {
                $self->RecursiveScanDir($package, $rfile);
            } 
            if (!S_ISDIR($inode[2])) {
                if (!(S_ISLNK($inode[2]) || S_ISBLK($inode[2]) ||
                    S_ISCHR($inode[2]) || S_ISFIFO($inode[2]) ||
                    S_ISSOCK($inode[2]))) {
					my $sum = "";
					if (defined $self->{Checksum} && index($self->{Checksum}, "sha") != -1) {
	                    $sum  .= $self->ShaSum($rfile) if (defined($flags{'5'}));
					} 
					if (defined $self->{Checksum} && index($self->{Checksum}, "md5") != -1) {
	                    $sum  .= $self->Md5Sum($rfile) if (defined($flags{'5'}));
					} 

					$ref->{'md5'}  = $sum;
                }
            }
        }

		if (defined($self->{ScanHook})) {
			$self->{ScanHook}->($self, $file, $ref);
		}
		if (defined($self->{FilesRef})) {
			$self->{FilesRef}->{$file} = $ref;
		}
    }
}

=head2 ScanDir

Public interface:
Sacn direcotry and fill/add the $self->files structure
	$dir => start directory 
	@paths => paths definition

=cut

sub ScanDir {
	my ($self, $dir, $package) = @_;

	if (chdir $dir) {
		$self->RecursiveScanDir($package, "");
	} else {
		$self->{Log}->Error("ERR can not switch to the directory %s", $dir);
	}

}

=head2 GetFullPath

Returns full path to tgz archive
=cut

sub GetFullPath {
	my ($self, $pkg) = @_;

	my ($pkgdir) = $pkg; 
	# if the name of tha package start with / ignore the basedir:dir option     
	if  ($pkg !~ /^\/.+/) {
		($pkgdir) = $self->{Config}->GetVal("pkgdir");
		$pkgdir .= "/".$pkg;
	}

	# find the propper path for the package  and perform scanning 
	# test if the directory exists 
	if ( ! -d $pkgdir ) {
		$self->{Log}->Error("ERR the directory %s for package %s not found", $pkgdir, $pkg, $self->{HostId});
		return undef;
	} else {
		return $pkgdir;
	}
}

=head2 ScanPkg

Public interface:
Sacn directory/add the $self->files structure
	$pkg => package name
=cut

sub ScanPkg {
	my ($self, $pkg) = @_;

	my ($pkgdir) = $self->GetFullPath($pkg); 

	if ( defined($pkgdir) ) {
		$self->ScanDir($pkgdir, "dir:".$pkg);
		$self->{Log}->Debug(5, "Scanned dir package %s for %s (dir:%s)", $pkg, $self->{Config}->{SysName}, $pkgdir);
	}
}

=head2 GetTgzCmd

Public interface:
Returns command to create tzr gzip archive 
=cut
sub GetTgzCmd() {

	my ($self, $pkg) = @_;
	my $pkgdir = $self->GetFullPath($pkg);

    if (defined($pkgdir)) {
		return sprintf "tar -czf - --numeric-owner -C %s . ", $pkgdir;
    } 
	return undef;
}

1;

