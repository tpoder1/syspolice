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

	$class->{Recursion} = 0;

	$class->load_config($file);

	return $class;
}

=head SetMacro

Set macro definition. The macro will be replaced by his value
Examples: 
   %{system} -> $systemName
   %{path} -> $Path
   ...

=cut

sub SetMacro {
	my ($self, $key, @val) = @_;

	foreach my $section (@{$self->{SetSections}}) {
		# set values into %CONFIG
		$self->{Data}->{$section}->{$key} = [ @val ];
	}
}


=head ApplyMacro

Expand macros in the string

=cut

sub ApplyMacro {
	my ($self, $str) = @_;

	$self->{Recursion}++;

	if ($self->{Recursion} > 30) {
		$self->{Log}->Error("Max recursion count (30) reached for %s ", $str);
		$self->{Recursion}--;
		return "";
	}

	# parse the string and search for macros ( %{value} )
	while ($str =~ /^(.*)\%{(.+)}(.*)$/) {
		my ($p1, $p2, $p3) = ($1, $2, $3);
		my ($newval) = $self->GetVal($p2);
		$newval = "" if (!defined($newval));

		# Log unidentified macros 
		$self->{Log}->Error("ERR the macro %%{%s} not defined", $p2) if ($newval eq "");

#		printf "%s -> %s \n", $str,  $p1.$newval.$p3;

		$str = $p1.$newval.$p3;
	} 

	$self->{Recursion}--;
	return $str;
}

=head2 Sections

Set sections name to acces through GetVal function 

=cut

sub Sections {
	my ($self, @sections) = @_;

	$self->{SetSections} = [ @sections ];
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

		my $noitem = 0;

		if (defined($key) && $key eq 'no' && defined($val[0])) {
			$key  = $val[0];
			shift(@val);
			$noitem = 1;
		}

		$key = lc($key);

		# include file
		if ($key eq "use") {
			foreach (@val) { 
				$_ = $self->ApplyMacro($_);
				$self->load_config($_); 
			}
			next;
		}

		# [section] - differend section 
		if ($key eq /\[(.*)\]/) {
			$section = $1;
		}

		# process fields path, include, exclude, backup, ...
		if (defined($key) && ($key eq "path")) {
			foreach (0 .. @val - 1) {
				# set default flags and combine it with flags set by user
				if ($val[$_] =~ /(\[.+\])(.+)/) {
					my ($atts, $path) = ($1, $2);
					$atts =~ s/X/TM5SHLUGD/g;
					$atts =~ s/F/FB/g;
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


		if (!$noitem) {
			# add values into %CONFIG
			if (!defined($self->{Data}->{$section}->{$key})) {
				$self->{Data}->{$section}->{$key} = [ @val ];
			} else {
				push(@{$self->{Data}->{$section}->{$key}},  @val);
			}
		} else {
			# 'no' item  - remove from the config
			if (defined($self->{Data}->{$section}->{$key})) {
				foreach my $val (@val) {
					foreach my $x (0 .. @{$self->{Data}->{$section}->{$key}} - 1) {
						if ($self->{Data}->{$section}->{$key}->[$x] eq $val) {
							# field found - remove it 
							splice(@{$self->{Data}->{$section}->{$key}}, $x, 1);
							last;
						}
					}
					my $num = @{$self->{Data}->{$section}->{$key}};
		
					delete $self->{Data}->{$section}->{$key} if @{$self->{Data}->{$section}->{$key}} == 0;

				}
			}
			
		}

	}
	close $fh;
}

=head2 GetAtts

Return list of attributes

=cut

sub GetAtts {
	my ($self, $key) = @_;


	my %atts;
	foreach my $section ( @{$self->{SetSections}} ) {
		foreach my $key (keys %{$self->{Data}->{$section}}) {
			$atts{$key} = 1;
		}
	}

	return keys %atts;

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

