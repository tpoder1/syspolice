
package Police::Edit;

use strict;
use warnings;

use File::Temp qw/ :POSIX /;

=head1 NAME

Edit - layer privides editing of list, ...

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

	# set log handle  or create the new one 
	if (!defined($params{Log})) {
		$class->{Log} = Police::Log->new();
	} else {
		$class->{Log} = $params{Log};
	}

	$class->{EdFile} = tmpnam();

	return $class;
}


sub DESTROY {
    my ($self) = @_;

}

=head2 InitList

Open handle to edit list, empty the file and set $self->{EdList}

=cut
sub InitList {
	my ($self) = @_;

	if ( ! -f $self->{EdFile} ) {
		open $self->{EdHandle}, ">> $self->{EdFile}";
		my $handle = $self->{EdHandle};
		printf $handle "# All data after a hash sign (#) or empty lines will be ignored.\n";
		printf $handle "# \n";

	}
	return $self->{EdHandle};

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
	printf "\n\n";
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
		next if ( ! defined $line );
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

=head2 GetEdFile

Get name of Ed file for one system
=cut
sub GetEdFile {
	my ($self, $system) = @_;

	my $out = tmpnam();
	open OUT, "> $out";
	open IN, "<".$self->{EdFile};	
	
	# find section for the propper system	

	my $insys =  "..";
	while (<IN>) {
		chomp ;
		if ($_ =~ /system\s+(.+)/) { 
			$insys = $1;
			next;
		}

		if (!defined($system) || $insys eq $system || $insys eq '*' || $insys eq 'all' ) {		
			print OUT $_."\n";
		}
	}
	close OUT;
	close IN;
	
	return $out;
}

1;

