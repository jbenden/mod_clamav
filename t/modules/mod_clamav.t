#!/usr/bin/env perl

use lib qw(t/lib);
use strict;

use Test::Unit::HarnessUnit;

$| = 1;

# XXX Start clamd here

=pod
Example clamd.conf:

  LogFile /home/tj/tmp/clamd.log
  LogTime yes
  LogVerbose yes
  ExtendedDetectionInfo yes
  PidFile /home/tj/tmp/clamd.pid
  TCPSocket 8899
  Debug yes

Need to generate this config file on the fly, stick the randomly picked
port number in the CLAMD_PORT environment variable, and read the PID file to
shut the daemon down (using SIGTERM/SIGKILL).

=cut

my $r = Test::Unit::HarnessUnit->new();
$r->start("ProFTPD::Tests::Modules::mod_clamav");

# XXX Stop clamd here
