
package Police::Paths;

use strict;
use warnings;

=head1 NAME

Paths - the class which allows manipulate with paths and allows evaluate flags

=head1 SYNOPSIS

=head1 DESCRIPTION

=head1 METHODS

=head2 new
 Condtructor - arg 
  new(Log => log_handle ); 
  Log => reference to log class 

=cut

sub new {
	my ($self, $hostid, %params) = @_;
	my ($class) = {};
	bless($class);

	# The structure where the paths are stored. There is the follow structure:
    #   Paths = [ <pattern>, <reg_pattern>, { flags }, match_count }
	$class->{Paths} = [ ];		

	# default rule
	$class->AddPath('[+UGM5TL]*');

	return $class;
}

sub DESTROY {
    my ($self) = @_;
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


# add flags into the path, compute flags to the path
# @ arg        - flags prefix also possible (eg. "/usr", "[+M+G]/usr", "[+M-G+U+T]", "[-M+T]", ...)
# return flags - result flags enclosed in []
# return path  - path in clear forrmat  - if input path not defined returns undef
#
sub AddPath {
	my ($self, $arg) = @_;

	my ($path, $repath) = (undef, undef);
	my %resflags;

	# try to split the path and flags from arguments
	if ($arg =~ /\[(.+)\](.+)/) {
		if (defined($2) && $2 ne "") {
			$path = $2;
			$repath = $self->Glob2Pat($2);
		}
		my %flags = $self->GetFlags($1);
		# add parset flags into array
		push(@{$self->{Paths}}, [ $path, $repath, { %flags } , 0 ] ); 
	} 

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

	my %flags = ( );
	foreach my $ref (@{$self->{Paths}}) {

		if ($path =~ /$ref->[1]/) {
			# the path has been found - evaluate flags
			while (my ($flag, $sign) = each %{$ref->[2]}) {
				$flags{$flag} = $sign;
			}
			$ref->[3]++;
		}
	}

	foreach (keys %flags) { delete($flags{$_}) if $flags{$_} eq '-'; }

	return %flags;
}

=head2 GetUnmatchedPaths

Returns the list of the paths which hasn't been matched 

=cut

# return flags for particular dir
# return - array 
sub GetUnmatchedPaths {
	my ($self) = @_;

	my @paths = ();
	foreach my $ref (@{$self->{Paths}}) {
		push(@paths, $ref->[0]) if ($ref->[3] == 0);
	}

	return @paths;
}

1;
