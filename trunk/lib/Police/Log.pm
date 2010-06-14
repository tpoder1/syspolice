package Police::Log;

use strict;
use warnings;

use Sys::Syslog qw(:DEFAULT setlogsock);
use POSIX qw(strftime setsid);

=head1 NAME

Log - layer provides function to logging and debuging 

=head1 SYNOPSIS

=head1 DESCRIPTION
The class provides logging support 

=head1 METHODS

=head2 new
	new->(Facility => 'daemon.info', LogPrefix => 'prefix', Ddebug => 0);
	DEBUG - set debug level to show via Debug(<num>, string);

=cut

sub new {
	my ($self, %params) = @_;
	my ($class) = {};
	bless($class);

	# defaul values
	$class->{Facility} = defined($params{Facility}) ? $params{Facility} : 'daemon.info';
	$class->{LogPrefix} = defined($params{LogPrefix}) ? $params{LogPrefix} : substr($0, rindex($0, '/') + 1, length($0));
	$class->{Prefix} = defined($params{Prefix}) ? $params{Prefix} : "";
	$class->{ShowDebug} = defined($params{ShowDebug}) ? $params{ShowDebug} : 0;
	$class->{LogStdOut} = defined($params{LogStdOut}) ? $params{LogStdout} : 0;
	$class->{ShowProgress} = defined($params{ShowProgress}) ? $params{ShowProgress} : 1;

	return $class;
}

=head2 Log

Wite information to the system log

=cut

sub Log {
	my ($self, $msg, @par) = @_;

    my $lmsg = $self->{Prefix}.sprintf($msg, @par);
    if ($self->{LogStdOut} > 0) {
        printf "%s[%d]: %s\n", strftime("%Y-%m-%d.%H:%M:%S", localtime), $$, $lmsg;
    }
    setlogsock('unix');
    openlog($self->{LogPrefix}."\[$$\]", 'ndelay', 'user');
    syslog($self->{Facility}, $lmsg);
}

=head2 Prefix

Set prefix for all messages 

=cut

sub Prefix {
	my ($self, $prefix) = @_;

	$prefix = "" if (!defined($prefix));

	$self->{Prefix} = $prefix;
}

=head2 Error

Wite information to the system log and stderr

=cut

sub Error {
	my ($self, $msg, @par) = @_;

	printf STDERR  $self->{Prefix}.$msg."\n", @par;
	$self->Log($msg, @par);
}

=head2 Debug

Write debug information to log if the number is less than ShowDebug constant

=cut

sub Debug {
	my ($self, $num, $msg, @par) = @_;
	
	return if ($num > $self->{ShowDebug});
	$self->Log($msg, @par);
}

=head2 Progress

Clear the message which was previously written on the screen and write a new one 

=cut

sub Progress {
	my ($self, $msg, @par) = @_;

	return if (!$self->{ShowProgress});

	my $lmsg = $self->{Prefix}.sprintf($msg, @par);

	$self->{PROGRESSLN} = "" if (!defined($self->{PROGRESSLN}));
    
	if ($self->{PROGRESSLN} ne $lmsg) {
		my $blank = length($self->{PROGRESSLN}) - length($lmsg);
		$blank = 0 if ($blank < 0);

		my $prev = $|;
		$| = 1;
		my $br = "";
		if ($lmsg =~ /(.*)(\n*)$/) {
			($lmsg, $br) = ($1, $2);
		}
		$lmsg =~ /(.*)(\n*)$/;
		printf("%s%s%s%s", $lmsg, " " x $blank, "\b" x (length($lmsg) + $blank), $br);
		
		$| = $prev;	
		$self->{PROGRESSLN} = $lmsg." ";
	}
}

1;

