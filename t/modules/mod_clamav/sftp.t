#!/usr/bin/env perl

use lib qw(t/lib);
use strict;

use Test::Unit::HarnessUnit;

$| = 1;

# XXX Start clamd here

my $r = Test::Unit::HarnessUnit->new();
$r->start("ProFTPD::Tests::Modules::mod_clamav::sftp");

# XXX Stop clamd here
