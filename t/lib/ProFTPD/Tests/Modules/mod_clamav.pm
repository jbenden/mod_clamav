package ProFTPD::Tests::Modules::mod_clamav;

use lib qw(t/lib);
use base qw(ProFTPD::TestSuite::Child);
use strict;

use File::Path qw(mkpath);
use File::Spec;
use IO::Handle;

use ProFTPD::TestSuite::FTP;
use ProFTPD::TestSuite::Utils qw(:auth :config :running :test :testsuite);

$| = 1;

my $order = 0;

my $TESTS_ROOT = {
  clamav_upload_file_ok => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  clamav_upload_eicar_fails => {
    order => ++$order,
    test_class => [qw(forking)],
  },
};

my $TESTS = {
  clamav_config_maxsize => {
    order => ++$order,
    test_class => [qw(bug forking)],
  },

  clamav_vroot => {
      order => ++$order,
      test_class => [qw(bug forking mod_vroot)],
  },

  clamav_vroot_homedir => {
      order => ++$order,
      test_class => [qw(bug forking mod_vroot)],
  },

  clamav_stream => {
      order => ++$order,
      test_class => [qw(forking)],
  },

};

# If running as root, add the tests which require root privs.
if ($< == 0) {
  @$TESTS{keys($TESTS_ROOT)} = values($TESTS_ROOT);
}

sub new {
  return shift()->SUPER::new(@_);
}

sub set_up {
  my $self = shift;
  $self->SUPER::set_up(@_);

  my $pid_file = "/tmp/clamd.pid";
  my $config_file = File::Spec->rel2abs("t/etc/modules/mod_clamav/clamav-scanner.conf");

  if (-e $pid_file) {
    my $pid;
    if (open(my $fh, "< $pid_file")) {
      $pid = <$fh>;
      chomp($pid);
      close($fh);
    }

    my $cmd = "kill -TERM $pid 2> /dev/null";

    my @output = `$cmd`;

    my $now = time();
    while ((time() - $now) < 240 && -e $pid_file) {
      select(undef, undef, undef, 1.0);

      @output = `$cmd`;
    }
  }

  my $cmd = "/usr/sbin/clamd -c $config_file";

  unless ($ENV{TEST_VERBOSE}) {
    $cmd .= " >/dev/null 2>&1";
  }

  if ($ENV{TEST_VERBOSE}) {
    print STDERR "Starting ClamAV scanner: $cmd\n";
  }

  my @output = `$cmd`;

  if ($ENV{TEST_VERBOSE}) {
    foreach my $o (@output) {
      print STDERR "$o\n";
    }
  }

  my $now = time();
  while ((time() - $now) < 240 && ! -e $pid_file) {
    select(undef, undef, undef, 1.0);

    if ($ENV{TEST_VERBOSE}) {
      print STDERR "Waiting for PID file to exist.\n";
    }
  }

  my $pid;
  if (open(my $fh, "< $pid_file")) {
    $pid = <$fh>;
    chomp($pid);
    close($fh);
  }

  $cmd = "kill -0 $pid";

  if ($ENV{TEST_VERBOSE}) {
    print STDERR "Testing server: $cmd\n";
  } else {
    $cmd .= " 2>/dev/null";
  }

  @output = `$cmd`;
  if ($? != 0) {
    foreach my $o (@output) {
      print STDERR "$o\n";
    }
    # die("ClamAV scanner is not responding.");
  }
}

sub tear_down {
  my $self = shift;
  $self->SUPER::tear_down(@_);

  my $pid_file = "/tmp/clamd.pid";

  my $pid;
  if (open(my $fh, "< $pid_file")) {
    $pid = <$fh>;
    chomp($pid);
    close($fh);
  }

  my $cmd = "kill -TERM $pid";

  if ($ENV{TEST_VERBOSE}) {
    print STDERR "Stopping ClamAV scanner: $cmd\n";
  }

  my @output = `$cmd`;

  if ($ENV{TEST_VERBOSE}) {
    foreach my $o (@output) {
      print STDERR "$o\n";
    }
  }

  my $now = time();

  while ((time() - $now) < 120 && -e $pid_file) {
    select(undef, undef, undef, 1.0);

    @output = `$cmd 2> /dev/null`;
  }

  if (-e $pid_file) {
    die("Could not stop clamav scanner!");
  }
}

sub list_tests {
  return testsuite_get_runnable_tests($TESTS);
}

sub get_server_version {
  my $proftpd_bin = ProFTPD::TestSuite::Utils::get_proftpd_bin();

  my @res = `$proftpd_bin -v`;
  if ($? != 0) {
    return undef;
  }

  my $res = $res[0];
  chomp($res);

  if ($res =~ /^ProFTPD Version ([0-9]+)\.([0-9]+)\.([0-9]+)[a-z]?$/) {
    return ($1, $2, $3);
  }

  return undef;
}

sub clamav_upload_file_ok {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/clamav.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/clamav.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/clamav.scoreboard");

  my $log_file = test_get_logfile();

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/clamav.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/clamav.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Bail test if not running as root
  if ($< > 0) {
    print STDERR "Must be root for this test to succeed.\n";
    return;
  }

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  # my $clamd_port = $ENV{CLAMD_PORT};
  my $clamd_port = 3310;

  my $test_file = File::Spec->rel2abs("$tmpdir/test.dat");

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 clamav:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    MaxLoginAttempts => 2,

    DefaultRoot => "~",

    IfModules => {
      'mod_clamav.c' => {
        ClamAV => 'on',
        ClamServer => '127.0.0.1',
        ClamPort => $clamd_port,
        ClamFailsafe => 'on',
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 1);

      $client->login($user, $passwd);

      my $conn = $client->stor_raw('test.dat');
      unless ($conn) {
        die("Failed to STOR: " . $client->response_code() . " " .
          $client->response_msg());
      }

      my $buf = "Hello, World!\n";
      $conn->write($buf, length($buf), 25);
      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();

      my $expected;

      $expected = 226;
      $self->assert($expected == $resp_code,
        test_msg("Expected $expected, got $resp_code"));

      $expected = "Transfer complete";
      $self->assert($expected eq $resp_msg,
        test_msg("Expected '$expected', got '$resp_msg'"));

      $client->quit();

      $self->assert(-f $test_file,
        test_msg("File '$test_file' does not exist as expected"));
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    test_append_logfile($log_file, $ex);
    unlink($log_file);

    die($ex);
  }

  unlink($log_file);
}

sub clamav_upload_eicar_fails {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/clamav.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/clamav.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/clamav.scoreboard");

  my $log_file = test_get_logfile();

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/clamav.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/clamav.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Bail test if not running as root
  if ($< > 0) {
    print STDERR "Must be root for this test to succeed.\n";
    return;
  }

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  # my $clamd_port = $ENV{CLAMD_PORT};
  my $clamd_port = 3310;

  my $eicar_file = File::Spec->rel2abs('t/etc/modules/mod_clamav/eicar.dat');
  my $eicar_data;
  if (open(my $fh, "< $eicar_file")) {
     local $/;
     $eicar_data = <$fh>;
     close($fh);

  } else {
    die("Can't read $eicar_file: $!");
  }

  my $test_file = File::Spec->rel2abs("$tmpdir/test.dat");

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 clamav:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    DefaultRoot => '~',

    IfModules => {
      'mod_clamav.c' => {
        ClamAV => 'on',
        ClamServer => '127.0.0.1',
        ClamPort => $clamd_port,
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 1);
      $client->login($user, $passwd);

      my $conn = $client->stor_raw('test.dat');
      unless ($conn) {
        die("Failed to STOR: " . $client->response_code() . " " .
          $client->response_msg());
      }

      my $buf = $eicar_data;
      $conn->write($buf, length($buf), 25);
      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msgs = $client->response_msgs();
      my $resp_nmsgs = scalar(@$resp_msgs);

      my $expected;

      $expected = 550;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = "Virus Detected and Removed: Eicar-Test-Signature";

      my $resp_msg = $resp_msgs->[$resp_nmsgs-1];
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      $client->quit();

      $self->assert(!-f $test_file,
        test_msg("File '$test_file' exists expectedly"));
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    test_append_logfile($log_file, $ex);
    unlink($log_file);

    die($ex);
  }

  unlink($log_file);
}

sub clamav_config_maxsize {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/clamav.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/clamav.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/clamav.scoreboard");

  my $log_file = test_get_logfile();

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/clamav.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/clamav.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  # my $clamd_port = $ENV{CLAMD_PORT};
  my $clamd_port = 3310;

  my $eicar_file = File::Spec->rel2abs('t/etc/modules/mod_clamav/eicar.dat');
  my $eicar_data;
  if (open(my $fh, "< $eicar_file")) {
     local $/;
     $eicar_data = <$fh>;
     close($fh);

  } else {
    die("Can't read $eicar_file: $!");
  }

  my $test_file = File::Spec->rel2abs("$tmpdir/test.dat");

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 clamav:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    IfModules => {
      'mod_clamav.c' => {
        ClamAV => 'on',
        ClamServer => '127.0.0.1',
        ClamPort => $clamd_port,
        ClamMaxSize => '5 Mb',
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 1);
      $client->login($user, $passwd);

      my $conn = $client->stor_raw('test.dat');
      unless ($conn) {
        die("Failed to STOR: " . $client->response_code() . " " .
          $client->response_msg());
      }

      my $buf = $eicar_data;
      $conn->write($buf, length($buf), 25);
      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msgs = $client->response_msgs();
      my $resp_nmsgs = scalar(@$resp_msgs);

      my $expected;

      $expected = 550;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = "Virus Detected and Removed: Eicar-Test-Signature";

      my $resp_msg = $resp_msgs->[$resp_nmsgs-1];
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      $client->quit();

      $self->assert(!-f $test_file,
        test_msg("File '$test_file' exists expectedly"));
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    test_append_logfile($log_file, $ex);
    unlink($log_file);

    die($ex);
  }

  unlink($log_file);
}

sub clamav_vroot {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/clamav.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/clamav.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/clamav.scoreboard");

  my $log_file = test_get_logfile();

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/clamav.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/clamav.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  # my $clamd_port = $ENV{CLAMD_PORT};
  my $clamd_port = 3310;

  my $eicar_file = File::Spec->rel2abs('t/etc/modules/mod_clamav/eicar.dat');
  my $eicar_data;
  if (open(my $fh, "< $eicar_file")) {
     local $/;
     $eicar_data = <$fh>;
     close($fh);

  } else {
    die("Can't read $eicar_file: $!");
  }

  my $test_file = File::Spec->rel2abs("$tmpdir/test.dat");

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 clamav:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    IfModules => {
        'mod_vroot.c' => {
            VRootEngine => 'on',
            VRootLog => $log_file,
            DefaultRoot => '/tmp',
        },

      'mod_clamav.c' => {
        ClamAV => 'on',
        ClamServer => '127.0.0.1',
        ClamPort => $clamd_port,
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 1);
      $client->login($user, $passwd);

      my $conn = $client->stor_raw('test.dat');
      unless ($conn) {
        die("Failed to STOR: " . $client->response_code() . " " .
          $client->response_msg());
      }

      my $buf = $eicar_data;
      $conn->write($buf, length($buf), 25);
      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msgs = $client->response_msgs();
      my $resp_nmsgs = scalar(@$resp_msgs);

      my $expected;

      $expected = 550;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = "Virus Detected and Removed: Eicar-Test-Signature";

      my $resp_msg = $resp_msgs->[$resp_nmsgs-1];
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      $client->quit();

      $self->assert(!-f $test_file,
        test_msg("File '$test_file' exists expectedly"));
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    test_append_logfile($log_file, $ex);
    unlink($log_file);

    die($ex);
  }

  unlink($log_file);
}

sub clamav_vroot_homedir {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/clamav.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/clamav.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/clamav.scoreboard");

  my $log_file = test_get_logfile();

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/clamav.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/clamav.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  # my $clamd_port = $ENV{CLAMD_PORT};
  my $clamd_port = 3310;

  my $eicar_file = File::Spec->rel2abs('t/etc/modules/mod_clamav/eicar.dat');
  my $eicar_data;
  if (open(my $fh, "< $eicar_file")) {
     local $/;
     $eicar_data = <$fh>;
     close($fh);

  } else {
    die("Can't read $eicar_file: $!");
  }

  my $test_file = File::Spec->rel2abs("$tmpdir/test.dat");

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 clamav:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    IfModules => {
        'mod_vroot.c' => {
            VRootEngine => 'on',
            VRootLog => $log_file,
            DefaultRoot => $home_dir,
        },

      'mod_clamav.c' => {
        ClamAV => 'on',
        ClamServer => '127.0.0.1',
        ClamPort => $clamd_port,
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 1);
      $client->login($user, $passwd);

      my $conn = $client->stor_raw('test.dat');
      unless ($conn) {
        die("Failed to STOR: " . $client->response_code() . " " .
          $client->response_msg());
      }

      my $buf = $eicar_data;
      $conn->write($buf, length($buf), 25);
      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msgs = $client->response_msgs();
      my $resp_nmsgs = scalar(@$resp_msgs);

      my $expected;

      $expected = 550;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = "Virus Detected and Removed: Eicar-Test-Signature";

      my $resp_msg = $resp_msgs->[$resp_nmsgs-1];
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      $client->quit();

      $self->assert(!-f $test_file,
        test_msg("File '$test_file' exists expectedly"));
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    test_append_logfile($log_file, $ex);
    unlink($log_file);

    die($ex);
  }

  unlink($log_file);
}

sub clamav_stream {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/clamav.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/clamav.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/clamav.scoreboard");

  my $log_file = test_get_logfile();

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/clamav.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/clamav.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  # my $clamd_port = $ENV{CLAMD_PORT};
  my $clamd_port = 3310;

  my $eicar_file = File::Spec->rel2abs('t/etc/modules/mod_clamav/eicar.dat');
  my $eicar_data;
  if (open(my $fh, "< $eicar_file")) {
     local $/;
     $eicar_data = <$fh>;
     close($fh);

  } else {
    die("Can't read $eicar_file: $!");
  }

  my $test_file = File::Spec->rel2abs("$tmpdir/test.dat");

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 clamav:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    IfModules => {

      'mod_clamav.c' => {
        ClamAV => 'on',
        ClamServer => '127.0.0.1',
        ClamPort => $clamd_port,
        ClamStream => 'on',
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 1);
      $client->login($user, $passwd);

      my $conn = $client->stor_raw('test.dat');
      unless ($conn) {
        die("Failed to STOR: " . $client->response_code() . " " .
          $client->response_msg());
      }

      my $buf = $eicar_data;
      $conn->write($buf, length($buf), 25);
      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msgs = $client->response_msgs();
      my $resp_nmsgs = scalar(@$resp_msgs);

      my $expected;

      $expected = 550;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = "Virus Detected and Removed: Eicar-Test-Signature";

      my $resp_msg = $resp_msgs->[$resp_nmsgs-1];
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      $client->quit();

      $self->assert(!-f $test_file,
        test_msg("File '$test_file' exists expectedly"));
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    test_append_logfile($log_file, $ex);
    unlink($log_file);

    die($ex);
  }

  unlink($log_file);
}

1;
