package Police::Conf;

use strict;
use warnings;

use Police::Log;
use Data::Dumper;

=head1 NAME

Conf - layer to process configuration layer 

=head1 SYNOPSIS

=head1 DESCRIPTION

=head1 METHODS

=head2 new
 Condtructor - arg 
  new($file, BaseDir => dir , Log => log_handle ); 
  $file => <file name in the base dir> 
  BaseDir => <base_config_directory>
  Log => reference to log class 

=cut

sub new {
	my ($self, $file, %params) = @_;
	my ($class) = {};
	bless($class);

	# set log handle  or create the new one 
	if (!defined($params{Log})) {
		$class->{Log} = Police::Log->new();
	} else {
		$class->{Log} = $params{Log};
	}

	# set base dir
	$class->{BaseDir} = defined($params{BaseDir}) ? $params{BaseDir} : "";
	$class->{SysName} = $file;
	$class->{FileName} = $file;
		
	$class->{SetSections} = [ ('main') ];
	$class->{Data} = {};	# data in format $class->{Data}->{SectionName} = [ @list of values ]

	$class->{Macros}->{"%%"} = "%";		# define basic macros (%% is replaced by %%)

	$class->load_config($file);

	return $class;
}

=head SetMacro

Set macro definition. The macro will be replaced by his value
Examples: 
   %S -> $systemName
   %P -> $Path
   ...

=cut

sub SetMacro {
	my ($self, $macro, $value) = @_;

	$self->{Macros}->{$macro} = $value;

}


=head ApplyMacro

Expand macros in the string

=cut

sub ApplyMacro {
	my ($self, $str) = @_;

	while (my ($macro, $value) = each %{$self->{Macros}} ) {
		$str =~ s/$macro/$value/g;
	}
	
#	print "XXXX $str\n";
	return $str;
}

=head2 Sections

Set sections name to acces through GetVal function 

=cut

sub Sections {
	my ($self, @sections) = @_;

	$self->{Sections} = [ @sections ];
}

# split values with accept quotes (eg line fld1, "fld \"fld5" fld7 produces array ("fld1", "fld \fld5", "fld7")
sub splitq {
	my ($self, $str) = @_;

	my @arr = ();
	my $idx = 0;
	my $state = 0; # 0 - start, 1 - in string, 2 - in quoted string, 3 - char after slash
	foreach my $ch (split(//, $str)) {
		#char after quote 
		if ( $state == 3 ) {
			$arr[$idx] .= $ch;
			$state = 1;
		# quote
		} elsif ( $ch eq '"') {
			if ($state == 2) {
				$state = 0;
			} else {
				$state = 2;
			}
		# space, delimiter
		} elsif ($ch =~ /[\s,]/ && $state != 2) {
			if (defined($arr[$idx]) && $arr[$idx] ne "") {
				$idx++;
				$state = 0;
			}
		# slash
		} elsif ( $ch eq '\\') {
			$state = 3;
		# other
		} else {
			if (defined($arr[$idx])) {
				$arr[$idx] .= $ch;	
			} else {
				$arr[$idx] = $ch;	
			}
		}
	}

	return @arr;
}


# load and parse config file and store into %CONFIG structure 
sub load_config($$);
sub load_config($$) {
	my ($self, $file) = @_;

	my $section = 'main';
	my $fh;
	
	my $dirfile = $self->{BaseDir}."/".$file;
	$self->{FileName} = $file;

	unless ( open $fh, "< $dirfile" ) {
		$self->{Log}->Error("Can't open file %s. %s.", $dirfile, $!); 
		return;
	}

	$self->{Log}->Debug(10, "Loading data from %s.", $dirfile);
	while (<$fh>) {
		chomp;
		# ignore characters after # and ; 
		my ($line) = split(/#|;/, $_);
		next if (!defined($line) || $line eq "");

		my ($key, @val) = $self->splitq($line);

		$key = lc($key);

		# include file
		if ($key eq "use") {
			foreach (@val) { $self->load_config($_); }
			next;
		}

		# [section] - differend section 
		if ($key eq /\[(.*)\]/) {
			$section = $1;
		}

		# process fields path, include, exclude, backup, ...
		if (defined($key eq "path")) {
			foreach (0 .. @val - 1) {
				# set default flags and combine it with flags set by user
				if ($val[$_] =~ /(\[.+\])(.+)/) {
					my ($atts, $path) = ($1, $2);
					$atts =~ s/X/TM5SHLUGD/g;
					$val[$_] = $atts.$path;
				}
			}
		}

		# mode siffix placed aftet semicolon (:) to value keys
		if ($key =~ /^(pkg):(.+)$/) {
			my ($prefix, $suffix) = ($1, $2);
			$key = $1;
			foreach (0 .. @val - 1) {
				$val[$_] = $suffix.":".$val[$_];
			}
		}

#				$path = glob2pat($path);

				# combine the current flags with a previously set flags
#				push(@{$CONFIG{$sysname}->{"paths"}}, $flags.$path);
#			}
#			next;
#		}

		# add values into %CONFIG
		if (!defined($self->{Data}->{$section}->{$key})) {
			$self->{Data}->{$section}->{$key} = [ @val ];
		} else {
			push(@{$self->{Data}->{$section}->{$key}},  @val);
		}
	}
	close $fh;
}


=head2 GetVal

Return list of values for key or undef if the key is not defined 

=cut

sub GetVal {
	my ($self, $key) = @_;

	my $val = undef;
	foreach ( @{$self->{SetSections}} ) {
		if (defined($self->{Data}->{$_}->{$key})) {
			$val = $self->{Data}->{$_}->{$key};
		}
	}

	# apply macros 
	if (defined($val)) {
		foreach ( 0 .. @{$val} -  1) {
			$$val[$_] = $self->ApplyMacro($$val[$_]);
		}
		return @{$val};
	} else {
		return undef;
	}

}

1;

