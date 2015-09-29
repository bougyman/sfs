#!/usr/bin/perl

# $Id: upgradedb.pl,v 1.3 2002/10/19 13:03:10 max Exp $

#
# upgradedb.pl
#
# Upgrades SfS text Auth DBs (i.e. sfs_users) from v1 to v2.
#

use IO::File;
use IO::Pipe;
use POSIX qw(strftime);
use strict;

use vars qw [ $LOCATE $SFS_USERS @SFS_CONF_DIRS %FIELDS ];
$LOCATE = "locate";
$SFS_USERS = "sfs_users";
@SFS_CONF_DIRS = qw [ /etc/sfs ];
%FIELDS = ( user => 0, pubkey => 1, privs => 2, srpinfo => 3, privkey => 4); 



sub usage () {
    print <<EOF;
usage: ugradedb.pl [-a | -s] [-n] <file1> <file2> ....

    -a     Use "locate" command to find all sfs_users and sfs_users.pub
           files on the system.  Will then interactively prompt for each
           file.

    -n     Turn off interactive prompting.

    -s     (default) Look for sfs_users and sfs_users.pub files in standard
           sfs directories.

	   If neither the -a or the -s flag is provided, and specific
	   filenames are provided, then those files will be converted
	   without the interactive prompting.
EOF
    exit (0);
}

sub find_locate () {
    my @path = split /:/, $ENV{PATH};
    foreach (@path) {
	my $prog = $_ . "/" . $LOCATE;
	return $prog if -x $prog;
    }
    return "";
};

sub find () {
    my $prog = find_locate ();
    unless ($prog) {
	warn "Could not find locate command in your path.\n";
	return ();
    }
	
    my $pipe =  new IO::Pipe ();
    $pipe->reader ("$prog $SFS_USERS");
    my @ret;
    while (<$pipe>) {
	chomp;
	next unless m#(^|/)?$SFS_USERS(.pub)?$#;
	push @ret, $_;
    }
    return @ret;
}

sub find_sfs () {
    my @ret;
    foreach my $path (@SFS_CONF_DIRS) {
	foreach my $suffix ("", ".pub") {
	    my $file = $path . "/" . $SFS_USERS . $suffix;
	    push @ret, $file if -r $file;
	}
    }
    return @ret;
}


sub parse_argv (\$) {
    my ($promptr) = @_;
    my @files;
    $$promptr = 0;
    my $noprompt = 0;
    if ($#ARGV >= 0) {
	if ($ARGV[0] =~ /^-(.*)/) {
	    my $opt = $1; 
	    if ($opt eq "a") {
		@files = find ();
		$$promptr = 1;
	    } elsif ($opt eq "s") {
		@files = find_sfs ();
		$$promptr = 1;
	    } elsif ($opt eq "n") {
		$noprompt = 1;
	    } else {
		usage ();
	    }
	    usage () if $#ARGV > 0;
	} else {
	    @files = @ARGV ;
	}
    }
    if ($#files < 0) {
	@files = find_sfs ();
	$$promptr = 1;
    }
    $$promptr = 0 if $noprompt;
    return @files;
}

sub do_file ($$) {
    my ($file, $prompt) = @_;
    my $err;
    unless (-r $file) {
	warn "** $file: cannot open for reading\n";
	return 0;
    }
    if (is_v2 ($file)) {
	warn "** $file: already contains converted entries\n";
	return 0;
    } 
    my @lns;
    unless (@lns = parse_file ($file)) {
	return 0;
    }
    if ($prompt and !get_yes ($file)) {
	return 0;
    }
	
    return convert_file ($file, \@lns);
}

sub backup_file ($\$) {
    my ($fn, $nfn) = @_;
    my $n = 0;
    do {
	$$nfn = $fn . ".v1-saved-" . ++$n;
    } while ( -e $$nfn );
    rename ($fn, $$nfn);
    unless (-r $$nfn) {
	warn "** $fn: File rename ($fn to $$nfn) failed\n";
	return 0;
    }
    return 1;
}

sub sfsts () {
    return strftime "%a, %b %d %Y %H.%M.%S %z", gmtime;
}


sub convert_file ($$) {
    my ($fn, $lines) = @_;
    my $nfn;
    my @fstats = stat ($fn);
    return 0 unless backup_file ($fn, $nfn);
    umask (0077);
    my $fh = new IO::File ($fn, "w", $fstats[2] );
    foreach my $line (@$lines) {
	my $user = $line->[$FIELDS{user}];
	my @pwent = getpwnam ($user);
	my $audit = "Converted from v1 on " . sfsts ();
	my @out = ( "USER",                              # 0
		    $user,                               # 1
		    $pwent[2],                           # 2
		    1,                                   # 3 -- version
		    $pwent[3],                           # 4
		    "",                                  # 5 -- owner
		    "rabin," . $line->[$FIELDS{pubkey}], # 6
		    $line->[$FIELDS{privs}],             # 7
		    $line->[$FIELDS{srpinfo}],           # 8
		    $line->[$FIELDS{privkey}],           # 9
		    "",                                  # 10 -- srvprivkey
		    $audit );                            # 11
	print $fh join (":", @out), "\n";
	
    }
    $fh->close ();
    if ($fstats[2] & 0x77 and !($fn =~ /\.pub$/ )) {
	warn "** $fn: WARNING! File is readable by group/all\n";
    }
    chown $fstats[4], $fstats[5], $fn;
    chmod $fstats[2], $fn;
    print "$fn: converted (backup file at $nfn)\n";
    return 1;
}

sub is_v2 ($) {
    my ($fn) = @_;
    my $fh = new IO::File ("<$fn");
    return 0 unless $fh;
    my $ret = 0;
    while (<$fh>) {
	if ( m#^(USER|GROUP):[A-Za-z_/-]{0,31}:\d+:# ) {
	    $ret = 1;
	    last;
	}
    }
    $fh->close ();
    return $ret;
}

sub parse_file ($) {
    my ($fn, $arr) = @_;
    my $fh = new IO::File ("<$fn");
    unless ($fh) {
	warn "** $fn: cannot open for reading\n";
	return ();
    }
    my @lns;
    my $line;
    my $lineno = 1;
    while ($line = <$fh>) {
	chomp ($line);
	$line =~ s/#.*//;
	next unless $line =~ /\S/ ;
	my @fields = split /:/, $line;
	if ($#fields < 2 || $#fields > 4) {
	    warn "** $fn:$lineno: Parse error: wrong number of fields\n";
	    return ();
	}
	unless ( $fields[$FIELDS{user}] =~ m!^[\w_/-]+$! ) {
	    warn "** $fn:$lineno: Parse error: invalid user name";
	    return ();
	}
	unless ( $fields[$FIELDS{pubkey}] =~ m!^0x[a-f0-9]+$! ) {
	    warn "** $fn:$lineno: Parse error: invalid public key\n";
	    return ();
	}
	push @lns, [ @fields ];
	$lineno++;
    }
    return @lns;
}

sub get_yes ($) {
    my ($file) = @_;
    my $ans;
    do {
	print "Convert file $file? (yes/no) ";
	chomp ($ans = lc (<STDIN>));
    } while (!($ans eq "yes" or $ans eq "no"));
    return ($ans eq "yes");
}


my $prompt;
my @files = parse_argv ($prompt);

foreach (@files) {
    do_file ($_, $prompt);
}

