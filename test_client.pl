#!/usr/bin/perl
use strict;
use warnings;
use Switch;
use IO::Socket;
use IO::Socket::Timeout;
use POSIX;
use String::Random qw(random_regex random_string);
use Errno qw(ETIMEDOUT EWOULDBLOCK);
use Time::HiRes qw(time);
use threads;
use threads::shared;
use String::Diff;
use Expect;
use Config;
use IPC::Open2;
use IO::Handle;

$Config{useithreads} or
    die('Recompile Perl with threads to run this program.');

### Declares used in functions.

my ($rout, $fromClient,$toClient,$line,$errorCount,$errorLogString);
my $rin= '';

#print "arguments $#ARGV.\n";
if ( $#ARGV != 2 ) {
    print "Wrong syntax.\n";
    print "Syntax: \n";
    print "test_client.pl <IP:Port> MainLog ExecutionLog\n";
    print " \n";
    print "IP is the IP of the server.\n";
    print "Port is the port of the server.\n";
    exit(1);
}

##########FUNCTIONS

sub loggerSub {
    my ($socket,$name)= @_;
    my $lsline;
    print FH "I am the LOGGER THREAD, $name.\n";

    my $msgCounter=0;
    my $termCounter=0;
    my $k=0;
    while($termCounter==0){
	while($lsline=<$socket>){
	    chomp($lsline);
	    if ( "$lsline" =~ /DROP/ ){
		$termCounter=1;
	    } else {
		print FH "LOGGER: $lsline\n";
	    }
	}
	print FH "LOGGER, socket timeout.\n";
    }
    print FH "LOGGER LEFT\n";
    return;
}

sub clientSub {
    my ($socket,$name,$id,$words)= @_;
    my $word;
    print EXH "I am a THREAD, $name id=$id, strings=$words\n";
    my @stringStore=split(/ /,$words);
    my $m=$#stringStore;
    my $msgCounter=0;
    my $termCounter=0;
    my $k=0;

    while($termCounter==0){
	
	$word = $stringStore[$k];
	print $socket "MSG $word\n";
	print EXH "TD[$name|$k/$m] ==================> MSG $word \n";
	while($word=<$socket>){
	    chomp($word);
	    if ( "$word" =~ /DROP/ ){
		$termCounter=1;
	    }
	    print EXH "TD[$name|$k/$m] <= $word\n";
	}
	$k++;
	if($k>$#stringStore){
	    $k=0;
	}

    }
    
    
    return;
}
	
    

sub depart() {
    print FH "SUMMARY: Errors: $errorCount.\n";
    print FH "LOG: $errorLogString\n";
    print FH "IN client test, errors and log does not matter, as test is done at CLIENT side.\n";
    close(FH);
    close(EXH);
    exit(1);
}


#################START of MAIN




#my $remote_host='127.0.0.1';
#my $remote_port=6000;

my $remote=shift;

my $remote_host;#=shift;
my $remote_port;#=shift;

($remote_host,$remote_port)=split(':',$remote);

my $fout=shift;
my $fexe=shift;
#my $binary=shift;
my $READTIMEOUT=3.0;
my $WORDCNT=2;




print "Starting client test ($remote_host:$remote_port), storing to $fout and $fexe, sleeping 2s.\n";
print "This connects to the server, and tests how it behaves. To terminate the test, launch a \n";
print "client (nc) register (NICK), and send a message 'MSG DROP'. The clients will pick it\n";
print "up and terminate, that in turn will terminate the application.\n";

    
#my  $text="Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua Ut enim ad minim veniam quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur Excepteur sint occaecat cupidatat non proident sunt in culpa qui officia deserunt mollit anim id est laborum";
my  $text="one two three four five six seven eight nine ten";
my @textArray=split(/ /, $text);


open(FH, '>', "$fout") or die $!;
open(EXH, '>', "$fexe") or die $!;


print FH "Starting client test ($remote_host:$remote_port), storing to $fout and $fexe, sleeping 2s.\n";
#sleep(2);

my ($op,$v1,$v2,$remainder, $socket, $helloMsg,$assignment,$result,$response,$correctCount);

my $tests=2;
my $clientCount=0;
my %clients;

my $testClient="13.53.76.30:4712";

$errorCount=0;
$errorLogString="";

my $msgCount :shared; 
my $sentMsg :shared;

$msgCount=0;
$sentMsg=0;


print EXH "Connecting logger.";

my $logsocket = IO::Socket::INET->new(PeerAddr => $remote_host,
				PeerPort => $remote_port,
				Proto    => "tcp",
				Timeout  => 2,
				   Type     => SOCK_STREAM)
    or die "Couldn't connect to $remote_host:$remote_port : $@\n";

my $nickName="logger".random_regex('[A-Z]{2}[a-z]{2}');
my ($tim1,$tim2,$NICKstatus);
IO::Socket::Timeout->enable_timeouts_on($logsocket);
$logsocket->read_timeout(3);
$logsocket->write_timeout(0.5);
   
$helloMsg = <$logsocket>;
if ( $helloMsg =~ m[Hello 1\n]i ) {
    print EXH ".";
} elsif  ( $helloMsg =~ m[Hello 1.0\n]i ) {
    print EXH ".";
} else {
    print EXH "Server said; |$helloMsg| not as expected.\n";
    $errorLogString="Incorrect connection for $nickName.\n$errorLogString";
    print $socket "ERROR\n";
    close($socket);
    depart();
    exit; 
}
#Send NICK

print $logsocket "NICK $nickName\n";
$tim1=time;
$NICKstatus=<$logsocket>;
$tim2=time;
 
if ( $NICKstatus =~ m[OK\n]i ) {
    my %data=(
	'sock' => $logsocket,
	'nick' => "$nickName",
	'id' => "-1",
	);
    $clients{$nickName} = \%data;
    $clientCount++;
    #	print $socket->sockhost() . ":" . $socket->sockport() ." --> " . $socket->peeraddr() . ":" . $socket->peerport ." ";
    print EXH "Added $nickName with id=-1, took " . ($tim2-$tim1)*1000 ." [ms] \n";
} else {
    print EXH "Server rejected $nickName, took " . ($tim2-$tim1)*1000 . "[ms] \n";
    $errorLogString="Server rejected $nickName.\n$errorLogString";
    $errorCount++;
}


#print FH "Starting chat client, $binary. \n";


print EXH "\nLaunching $tests additional clients.\n";
my $haystackOfNames="";
my %nickWordCombo;

for(my $i=0;$i<$tests;$i++) {
    $socket = IO::Socket::INET->new(PeerAddr => $remote_host,
				    PeerPort => $remote_port,
				    Proto    => "tcp",
				    Timeout  => 2,
				    Type     => SOCK_STREAM)
	or die "Couldn't connect to $remote_host:$remote_port : $@\n";
    
    $nickName="TC".random_regex('[A-Z]{2}[a-z]{2}')."$i";
    $haystackOfNames="$nickName $haystackOfNames";
    IO::Socket::Timeout->enable_timeouts_on($socket);
    $socket->read_timeout(3);
    $socket->write_timeout(0.5);
   
    $helloMsg = <$socket>;
    if ( $helloMsg =~ m[Hello 1\n]i ) {
	print EXH ".";
    } elsif  ( $helloMsg =~ m[Hello 1.0\n]i ) {
	print EXH ".";
    } else {
	print EXH "Server said; |$helloMsg| not as expected.\n";
	$errorLogString="Incorrect connection for $nickName.\n$errorLogString";
	print $socket "ERROR\n";
	close($socket);
	depart();
	exit; 
    }
    #Send NICK
    
    print $socket "NICK $nickName\n";
    $tim1=time;
    $NICKstatus=<$socket>;
    $tim2=time;

    
    my $word = $textArray[ rand @textArray ];
    my $stringStore="";
    my $tmpKey;
    for(my $k=0;$k<$WORDCNT;$k++){
#	$word = $textArray[ rand @textArray ];
	$word = $textArray[ $k ]; 
	$tmpKey="$nickName$word";
	$nickWordCombo{$tmpKey}=1;
	$stringStore="$word $stringStore";
    }

    
    if ( $NICKstatus =~ m[OK\n]i ) {
	my %data=(
	    'sock' => $socket,
	    'nick' => "$nickName",
	    'id' => "$i",
	    'words' => "$stringStore",	    
	    );
	$clients{$nickName} = \%data;
	$clientCount++;
#	print $socket->sockhost() . ":" . $socket->sockport() ." --> " . $socket->peeraddr() . ":" . $socket->peerport ." ";
	print EXH "Added $nickName with id=$i, took " . ($tim2-$tim1)*1000 ." [ms] \n";
    } else {
	print EXH "Server rejected $nickName, took " . ($tim2-$tim1)*1000 . "[ms] \n";
	$errorLogString="Server rejected $nickName.\n$errorLogString";
	$errorCount++;
    }
}

print EXH "\n";

print EXH "\nGot $clientCount accepted clients.\n\n";


my @clist=(keys %clients);
my $cNt=($#clist+1);
print EXH "$cNt clients were successfully connected, including LOGGER..\n\n";


print EXH "client1 \n";
$socket= $clients{$clist[0]}{sock};
print $socket "HELLO from client1\n";
$NICKstatus=<$socket>;
if(!$NICKstatus){
    print EXH "SERVer did not respond.\n";
}



print EXH "client2 \n";
$socket= $clients{$clist[1]}{sock};
print $socket "HELLO from client2\n";
$NICKstatus=<$socket>;
if(!$NICKstatus){
    print EXH "SERVer did not respond.\n";
}


my %thds;
#print FH "*****************\n";
#print FH "Starting threads.\n";
#print FH "*****************\n";

for(my $i=0;$i<($tests+1);$i++){
#    print FH "Threading " .$clients{$clist[$i]}{nick} ."/". $clients{$clist[$i]}{id} . " ";
    if ( $clients{$clist[$i]}{nick} =~ "logger" ) {
	print EXH "Logger is special\n";
	$thds{$clients{$clist[$i]}{nick}}=threads->create(\&loggerSub,
							  $clients{$clist[$i]}{sock},
							  $clients{$clist[$i]}{nick});
    }else{
	print EXH "Regular client.\n";
	$thds{$clients{$clist[$i]}{nick}}=threads->create(\&clientSub,
							  $clients{$clist[$i]}{sock},
							  $clients{$clist[$i]}{nick},
							  $clients{$clist[$i]}{id},
							  $clients{$clist[$i]}{words});
    }
}
print EXH "*****************\n";
print EXH "Threads started.\n";
print EXH "*****************\n\n";


my $myData;

print EXH "Wait for threads to die.\n";
for(my $i=0;$i<($tests+1);$i++){
    $thds{$clients{$clist[$i]}{nick}}->join();
    print EXH "Joining " .$clients{$clist[$i]}{nick} ."/". $clients{$clist[$i]}{id} . "\n";
}
print EXH "After threads have died, we have msgCount=$msgCount.\n\n";


#print FH "$tests $correctCount $errorCount\n";
close($logsocket);

print EXH "Closing server test script.\n";
depart();
exit;


