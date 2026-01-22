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
use String::Dump qw (dump_hex );
use Config;
$Config{useithreads} or
    die('Recompile Perl with threads to run this program.');

#my $remote_host='127.0.0.1';
#my $remote_port=5001;

my $remote_host=shift;
my $remote_port=shift;
my $fout=shift;
my $READTIMEOUT=3.0;
my $WORDCNT=2;


my  $text="Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua Ut enim ad minim veniam quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur Excepteur sint occaecat cupidatat non proident sunt in culpa qui officia deserunt mollit anim id est laborum";
my @textArray=split(/ /, $text);


open(FH, '>', "$fout") or die $!;

print "Starting Server calc test, storing to $fout, sleeping 2s.\n";
#sleep(2);

my ($op,$v1,$v2,$remainder, $socket, $helloMsg,$assignment,$result,$response,$errorCount,$correctCount);

my $tests=5;
my $clientCount=0;
my %clients;

$errorCount=0;
my $errorLogString="";

my $msgCount :shared; 
my $sentMsg :shared;

$msgCount=0;
$sentMsg=0;

sub clientSub {
    my ($socket,$name,$id,$words)= @_;
    my $word;
    print FH "I am a THREAD, $name id=$id, strings=$words\n";
    my @stringStore=split(/ /,$words);
    my $m=$#stringStore;
    for(my $k=0;$k<=$#stringStore;$k++){
	$word = $stringStore[$k];
	print $socket "MSG $word\n";
#	print FH "TD[$name|$k/$m] MSG $word \n";
    }
    $sentMsg+=($#stringStore+1);
    

    my ($line,$t1,$t2);
    my $msgCounter=0;
    my $termCounter=0;
    while( $termCounter==0) {
	$t1=time();
	$line=<$socket>;
	$t2=time();
	if (!$line) {
	    print FH "TD[$name] empty socket after " .($t2-$t1)*1 . "[s], read $msgCounter.\n";
	}else {
	    if ( "$line" =~ /DROP/ ){
#		print "LEAVING $name \n";
		$termCounter=1;
	    }
	    $msgCounter++;
	    if ($msgCounter>100){
		print FH "TD[$name] Passed 100 Msg, leaving.\n";
		$termCounter=1;
	    }
	}

    }
    print FH "TD[$name] LEAVING, I received $msgCounter messages.\n";
    $msgCount+=$msgCounter;
    return($words);
}
	
    

sub depart() {
    print FH "Im the departing subroutine, Errors: $errorCount.\n";
    print FH "$errorLogString\n";
    close(FH);
    exit(1);
}





print FH "First test; reaction to connection.\n";
print FH "Expects '[Hello 1]i\\n', nothing more nothing less.\n";
print "First test; reaction to connection.\n";

my $Bobsocket = IO::Socket::INET->new(PeerAddr => $remote_host,
				   PeerPort => $remote_port,
				   Proto    => "tcp",
				   Timeout  => 2,
				   Type     => SOCK_STREAM)
    or die "Couldn't connect to $remote_host:$remote_port : $@\n";

IO::Socket::Timeout->enable_timeouts_on($Bobsocket);

$Bobsocket->read_timeout($READTIMEOUT);
$Bobsocket->write_timeout(0.5);

#print $Bobsocket->sockhost() . ":" . $Bobsocket->sockport() ." --> " . $Bobsocket->peeraddr() . ":" . $Bobsocket->peerport ."\n";

$helloMsg = <$Bobsocket>;
#       chomp $helloMsg;
if ( !$helloMsg ) {
    print FH "ERROR: Client did not receive a response, \n";
    print FH "       so it timed out after $READTIMEOUT [s].\n";
    $errorCount++;
    $errorLogString="No response on first connection.\n$errorLogString";
    exit(1);
}

my $noLRhello=$helloMsg;
$noLRhello =~ s/\n//g;
print FH "Server said: |$noLRhello| '(-\\n)' =>";

if (  $helloMsg =~ m[Hello 1\n]i ){
    print " OK.\n";
} elsif ( $helloMsg =~ m[Hello 1.0\n]i ) {
    print " OK.\n";
} else {
    print FH "ERROR: Server response was not expected.\n";
    $errorLogString="Incorrect response on connection.\n$errorLogString";
    print $Bobsocket "ERROR\n";
    close($Bobsocket);
    exit; 
    
}

print "\n";
#Send NICK
my ($tim1,$tim2);

my $longNICK="abcefghijklmnopq";
print FH "Testing Nick 1, $longNICK " . length($longNICK) . " chars.\n";
print "Testing Nick 1, $longNICK " . length($longNICK) . " chars.\n";

print $Bobsocket "NICK $longNICK\n";
$tim1=time;
my $NICKstatus=<$Bobsocket>;
$tim2=time;
$noLRhello=$NICKstatus;
$noLRhello =~ s/\n//g;
print FH "=>|" . $noLRhello . "|\n";
if ( $NICKstatus =~ m/ERROR/i ) {
    print FH "$longNICK passed the test, generated an error.\n\n";
} elsif ( $NICKstatus =~ m/OK/i ){
    print FH "ERROR: The proposed NICK is too long, should generate\n";
    print FH "       an ERROR of some kind. We got: $NICKstatus .\n";
    print FH "       Breaking protocol, but continuing tests.\n";
    print "ERROR: The proposed NICK is too long, should generate\n";
    print "       an ERROR of some kind. We got: $NICKstatus .\n";
    print "       Breaking protocol, but continuing tests.\n";
    $errorLogString="Failed Long Nick test.\n$errorLogString";
    $errorCount++;
} else {
    print FH "ERROR: Did not get ERROR or OK back.\n";
    print FH "       Breaking protocol, but continuing tests.\n";
    print FH "       Got |$noLRhello|\n";
    print "ERROR: Did not get ERROR or OK back.\n";
    print "       Got |$noLRhello|\n";
    $errorLogString="Failed Long Nick test1 (junk data).\n$errorLogString";
    $errorCount++;
}
	
#print "Closing this, socket and starting a new.\n";
close($Bobsocket);


$Bobsocket = IO::Socket::INET->new(PeerAddr => $remote_host,
				   PeerPort => $remote_port,
				   Proto    => "tcp",
				   Timeout  => 2,
				   Type     => SOCK_STREAM)
    or die "Couldn't connect to $remote_host:$remote_port : $@\n";

IO::Socket::Timeout->enable_timeouts_on($Bobsocket);

$Bobsocket->read_timeout($READTIMEOUT);
$Bobsocket->write_timeout(0.5);

#print $Bobsocket->sockhost() . ":" . $Bobsocket->sockport() ." --> " . $Bobsocket->peeraddr() . ":" . $Bobsocket->peerport ."\n";

$helloMsg = <$Bobsocket>;
#       chomp $helloMsg;
if ( !$helloMsg ) {
    print "ERROR: Client did not receive a response, \n";
    print "       so it timed out after $READTIMEOUT [s].\n";
    $errorLogString="Failed to respond on second connection.\n$errorLogString";
    $errorCount++;
    exit(1);
}

$noLRhello=$helloMsg;
$noLRhello =~ s/\n//g;
print FH "Server said: |$noLRhello| '(-\\n)' =>";

if (  $helloMsg =~ m[Hello 1\n]i ){
    print FH " OK.\n";
} elsif ( $helloMsg =~ m[Hello 1.0\n]i ) {
    print FH " OK.\n";
} else {
    print FH "ERROR: Server response was not expected.\n";
    $errorLogString="Server response on connection two was bad.\n$errorLogString";
    print $Bobsocket "ERROR\n";
    close($Bobsocket);
    exit; 
    
}

$longNICK="*Jode.Doe";
print FH "Testing Nick2, $longNICK " . length($longNICK) . " chars, with bad chars,\n";
print "Testing Nick2, $longNICK " . length($longNICK) . " chars, with bad chars.\n";

print $Bobsocket "NICK $longNICK\n";
$tim1=time;
$NICKstatus=<$Bobsocket>;
$tim2=time;
$noLRhello=$NICKstatus;
$noLRhello =~ s/\n//g;
#print "=>|" . $noLRhello . "|\n";

if ( $NICKstatus =~ m/ERROR/i ) {
    print FH "$longNICK passed the test, generated an error.\n\n";
} elsif ( $NICKstatus =~ m/OK/i ){
    print FH "ISSUE: The proposed NICK is bad, should generate\n";
    print FH "       an ERROR of some kind. We got:  $NICKstatus \n";
    print FH "       Breaking protocol, but continuing tests.\n";
    $errorLogString="Issue with bad Nick2 test ($longNICK).\n$errorLogString";
} else {
    print FH "ERROR: Did not get ERROR or OK back.\n";
    print FH "       Breaking protocol, but continuing tests.\n";
    print FH "       Got |" . chomp($NICKstatus) . "|\n";
    print "ERROR: Did not get ERROR or OK back.\n";
    print "       Breaking protocol, but continuing tests.\n";
    print "       Got |" . chomp($NICKstatus) . "|\n";   
    $errorLogString="Failed Long Nick test2 (junk data).\n$errorLogString";
    $errorCount++;
}
	
print "Closing this, socket and starting a new.\n";
close($Bobsocket);


$Bobsocket = IO::Socket::INET->new(PeerAddr => $remote_host,
				   PeerPort => $remote_port,
				   Proto    => "tcp",
				   Timeout  => 2,
				   Type     => SOCK_STREAM)
    or die "Couldn't connect to $remote_host:$remote_port : $@\n";

IO::Socket::Timeout->enable_timeouts_on($Bobsocket);

$Bobsocket->read_timeout($READTIMEOUT);
$Bobsocket->write_timeout(0.5);

#print $Bobsocket->sockhost() . ":" . $Bobsocket->sockport() ." --> " . $Bobsocket->peeraddr() . ":" . $Bobsocket->peerport ."\n";

$helloMsg = <$Bobsocket>;
#       chomp $helloMsg;
if ( !$helloMsg ) {
    print FH "ERROR: Client did not receive a response, \n";
    print FH "       so it timed out after $READTIMEOUT [s].\n";
    $errorLogString="Server did not respond to connection three.\n$errorLogString";
    $errorCount++;
    depart();
    exit(1);
}

$noLRhello=$helloMsg;
$noLRhello =~ s/\n//g;
print FH "Server said: |$noLRhello| '(-\\n)' =>";

if (  $helloMsg =~ m[Hello 1\n]i ){
    print FH " OK.\n";
} elsif ( $helloMsg =~ m[Hello 1.0\n]i ) {
    print FH " OK.\n";
} else {
    print FH "ERROR: Server response was not expected.\n";
    $errorLogString="Incorrect response on connection.\n$errorLogString";
    print $Bobsocket "ERROR\n";
    close($Bobsocket);
    depart();
    exit; 
    
}



############### Next set of tests
print "Setting proper name; 'Bob'\n";
print $Bobsocket "NICK Bob\n";
$tim1=time;
$NICKstatus=<$Bobsocket>;
$tim2=time;


#printf "=> |$NICKstatus| " . ($tim2-$tim1) . "(s)\n";

if ( $NICKstatus !~ m[OK\n] || $NICKstatus !~ m[ok \n]) { 
    print "Server accepted 'Bob' \n";
    print FH "Server accepted 'Bob' \n";
} else {
    print "Server rejected 'Bob' \n";
    print FH "Server rejected 'Bob' \n";
    $errorLogString="Server rejected 'Bob'.\n$errorLogString";
    $errorCount++;
    depart();
}
  
my $nickName;
my %nickWordCombo;
my $haystackOfNames="";

print "\nLaunching $tests additional clients.\n";

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
#    chomp $helloMsg;
#    print "Server said: |$helloMsg|\n";
    if ( $helloMsg =~ m[Hello 1\n]i ) {
	print ".";
    } elsif  ( $helloMsg =~ m[Hello 1.0\n]i ) {
	print ".";
    } else {
	print FH "Server said; |$helloMsg| not as expected.\n";
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

    
##    printf "=> |$NICKstatus| " . ($tim2-$tim1) . "(s)\n";
    
    my $word = $textArray[ rand @textArray ];
    my $stringStore="";
    my $tmpKey;
    for(my $k=0;$k<$WORDCNT;$k++){
	$word = $textArray[ rand @textArray ];
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
	print FH "Added $nickName with id=$i, took " . ($tim2-$tim1)*1000 ." [ms] \n";
    } else {
	print FH "Server rejected $nickName, took " . ($tim2-$tim1)*1000 . "[ms] \n";
	print "Server rejected $nickName, took " . ($tim2-$tim1)*1000 . "[ms] \n";
	print "Got|$NICKstatus|\n";
	$errorLogString="Server rejected $nickName.\n$errorLogString";
	$errorCount++;
    }
}

print "\n";

if ($clientCount==0){
    print "No clients with digits were accepted!\n";
    print "Launching NEW clients. \n";
    %clients=();
##################3
    for(my $i=0;$i<$tests;$i++) {
	$socket = IO::Socket::INET->new(PeerAddr => $remote_host,
					PeerPort => $remote_port,
					Proto    => "tcp",
					Timeout  => 2,
					Type     => SOCK_STREAM)
	    or die "Couldn't connect to $remote_host:$remote_port : $@\n";
	
	$nickName="TC".random_regex('[A-Z]{2}[a-z]{2}');
	$haystackOfNames="$nickName $haystackOfNames";
	IO::Socket::Timeout->enable_timeouts_on($socket);
	$socket->read_timeout(3);
	$socket->write_timeout(0.5);
	
	
	$helloMsg = <$socket>;
	#    chomp $helloMsg;
	#    print "Server said: |$helloMsg|\n";
	if ( $helloMsg =~ m[Hello 1\n]i ) {
	    print ".";
	} elsif  ( $helloMsg =~ m[Hello 1.0\n]i ) {
	    print ".";
	} else {
	    print FH "Server said; |$helloMsg| not as expected.\n";
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
	
	
	##    printf "=> |$NICKstatus| " . ($tim2-$tim1) . "(s)\n";
	
	my $word = $textArray[ rand @textArray ];
	my $stringStore="";
	my $tmpKey;
	for(my $k=0;$k<$WORDCNT;$k++){
	    $word = $textArray[ rand @textArray ];
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
	    print FH "Added $nickName with id=$i, took " . ($tim2-$tim1)*1000 ." [ms] \n";
	} else {
	    print FH "Server rejected $nickName, took " . ($tim2-$tim1)*1000 . "[ms] \n";
	    print "Server rejected $nickName, took " . ($tim2-$tim1)*1000 . "[ms] \n";
	    print "Got|$NICKstatus|\n";
	    $errorLogString="Server rejected $nickName.\n$errorLogString";
	    $errorCount++;
	}
    }

    if ($clientCount==0){
	print FH "No clients without were accepted!\n";
	print FH "Giving up!\n";
	exit(1);
    }
    
    
    #################3
}
##print "\nGot $clientCount accepted clients.\n\n";

my @clist=(keys %clients);
my $cNt=($#clist+1);
print "$cNt clients were successfully launched.\n\n";
print $Bobsocket "MSG Helloworld!\n";
my $tmpSocket;
my ($old,$new);
my $string1="MSG Bob Helloworld!";
my $string2="Bob Helloworld!";
my $string3="Helloworld!";


print "Testing/checking that the clients received Bob's 'Helloworld!'\n";

for(my $i=0;$i<$#clist;$i++){
#    print "i=$i >" . $clients{$clist[$i]}{nick} . "--" . $clients{$clist[$i]}{sock} . "--" . $clients{$clist[$i]}{sock} . "\n";
    
    $tmpSocket=$clients{$clist[$i]}{sock};
    $tim1=time;
    $response=<$tmpSocket>;
    $tim2=time;
    if (!$response) {
	## handle timeout
	print FH "[$i](" .$clients{$clist[$i]}{nick} .")=> TIMEDOUT ". ($tim2-$tim1)*1000 . " [ms] \n";
	$errorLogString=$clients{$clist[$i]}{nick} . " timed out waiting for Bob's Hello world!, " . ($tim2-$tim1)*1000 . " [ms].\n$errorLogString";
	
	$errorCount++;
    } else {
	chomp($response);
	print FH "[$i](" .$clients{$clist[$i]}{nick} ."/". $clients{$clist[$i]}{id} . ")=> |$response| ";
	if ( "$string1" eq "$response") {
	    $correctCount++;
	    print FH "[$i](" .$clients{$clist[$i]}{nick} ."/". $clients{$clist[$i]}{id} . ")=> Fine \n";
	} elsif( "$string2" eq "$response" ) {
	    print FH " Missing MSG.\n";
	    print "[$i](" .$clients{$clist[$i]}{nick} ."/". $clients{$clist[$i]}{id} . ")=> Missing MSG.\n";
	    $errorCount++;
	    $errorLogString=$clients{$clist[$i]}{nick}. " missing MSG.\n$errorLogString";
	} elsif( "$string3" eq "$response" ) {
	    print FH " Missing MSG and NICK.\n";
	    print "[$i](" .$clients{$clist[$i]}{nick} ."/". $clients{$clist[$i]}{id} . ")=> Missing MSG and NICK\n";
	    $errorLogString=$clients{$clist[$i]}{nick}. " missing MSG+NICK.\n$errorLogString";
	    $errorCount+=2;
	} else {
	    print "[$i](" .$clients{$clist[$i]}{nick} ."/". $clients{$clist[$i]}{id} . ")=> Missing all parts.\n";
	    print FH "Missing all parts of what I was looking for.\n";
	    print FH "'MSG Bob Helloworld!'\n";
	    print FH "|$response|\n";
	    print FH "HEX: |". dump_hex($response) . "|\n";
	    ($old,$new)=String::Diff::diff('MSG Bob Helloworld!',$response);
	    print "old='$old'\n";
	    print "new='$new'\n";
	    print "HEX: |". dump_hex($response) . "|\n";
	    $errorLogString=$clients{$clist[$i]}{nick}. " missing all relevant parts of 'MSG Bob Hello Word!\\n'.\n$errorLogString";	     
	    $errorCount+=4;
	}
	
    }   
}

my %thds;
#print "*****************\n";
#print "Starting threads.\n";
#print "*****************\n";

for(my $i=0;$i<$tests;$i++){
#    print "Threading " .$clients{$clist[$i]}{nick} ."/". $clients{$clist[$i]}{id} . " ";
    if ( $clients{$clist[$i]}{nick} eq "Bob" ) {

#	print "Not Bob\n";
    }else{
#	print ".\n";
	$thds{$clients{$clist[$i]}{nick}}=threads->create(\&clientSub,
							  $clients{$clist[$i]}{sock},
							  $clients{$clist[$i]}{nick},
							  $clients{$clist[$i]}{id},
							  $clients{$clist[$i]}{words});
    }
}
print "*****************\n";
print "Threads started.\n";
print "*****************\n\n";



print "Giving clients sentMsg=$sentMsg, waiting 5s.\n";
sleep(5);
print "Clients have now sent $sentMsg messages.\n";
print "Telling clients to stop.\n\n";
print $Bobsocket "MSG DROP\n";
print $Bobsocket "MSG DROP\n";
print $Bobsocket "MSG DROP\n";

print "Starting with a msgCount=$msgCount.\n";

my $myData;

print "Wait for threads to die.\n";
for(my $i=0;$i<$tests;$i++){
    $myData=$thds{$clients{$clist[$i]}{nick}}->join();
    $clients{$clist[$i]}{words}=$myData;
    print "Joining " .$clients{$clist[$i]}{nick} ."/". $clients{$clist[$i]}{id} . "|$myData|\n";
}
print "After threads have died, we have msgCount=$msgCount.\n\n";


my $messages=$tests*$WORDCNT;
my @msgArray;
my $nickIndex=1;
my $tmpKey;
print "Bob wants to read $messages messages.\n";
for(my $i=0;$i<$messages;$i++){
    $response=<$Bobsocket>;
    if ($response) {
	chomp($response);
	print FH "BobRead: $response ---";
	@msgArray=split(/ /, $response);
	if ( $msgArray[0] !~ m[MSG] ){
	    $errorLogString="Missing MSG tag.\n$errorLogString";
	    $errorCount++;
	    $nickIndex=0;
	} else {
	    $nickIndex=1;
	}
	if (index($haystackOfNames,$msgArray[$nickIndex]) != -1 ){
	    #found nick
	    $tmpKey=$msgArray[$nickIndex].$msgArray[$nickIndex+1];
	    if ( $nickWordCombo{$tmpKey} ){
		print FH "Msg OK (right nick+word)\n";
		delete($nickWordCombo{$tmpKey});
	    } else {
		print FH "Bad nick+word combo ($tmpKey - " . $msgArray[$nickIndex] . "--" .$msgArray[$nickIndex+1] .".\n";
		$errorLogString="Bad nick+word combo.\n$errorLogString";
		$errorCount++;
	    }

	} else {
	    if ( $msgArray[$nickIndex] eq "Bob" ) {
		print FH "Dont bother, server echoed Bob.\n";
		$i--;
	    } else {
		print FH "Strange NICK name, $msgArray[$nickIndex].\n";
		$errorLogString="Strange NICK name, $msgArray[$nickIndex].\n$errorLogString";
	    }
	}
	
    } else {
	print "BobRead: TIMEOUT\n";
	$errorLogString="BobREad: TIMEOUT\n$errorLogString";
	$errorCount++;
    }
}



print FH "\nWe left the read part, these are left (should be zero.), " . length( keys %nickWordCombo) . "\n";
my $element;
for $element ( keys %nickWordCombo ) {
    print FH "element = $element \n";
}
    
print "\n";

#print "checking clients.\n";
#for(my $i=0;$i<$#clist;$i++){
#    print $clients{$clist[$i]}{nick} ."/". $clients{$clist[$i]}{words} . "\n";
#}





#print FH "$tests $correctCount $errorCount\n";


print "Closing server test script.\n";
depart();
exit;
