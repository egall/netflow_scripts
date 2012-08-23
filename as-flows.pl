#!/usr/local/bin/perl
#use strict;
#use warnings;


my $EXITCODE = 0;
END{ exit $EXITCODE; }
sub note(@) { print STDERR "$0: @_"; };
$SIG{'__WARN__'} = sub { note @_; $EXITCODE = 1; };
$SIG{'__DIE__'} = sub { warn @_; exit; };




(my $USAGE = <<__END_USAGE__) =~ s/^#[ ]?//gm;
#
# NAME
#    $0 SRC_IP [-s START DATE] [-e END DATE] [-b BYTES] [-c COUNT]
#
# SYNOPSIS
#    $0 [-h]               - for help 
#    $0 src                - to run
#    $0 -s  [yyyy/mm/dd]   - for starting date
#    $0 -e  [yyyy/mm/dd]   - for ending date
#    $0 -b  [BYTES]        - for flows over a byte limit
#    $0 -c  [COUNT]        - limit the number of flows viewed
#
# DESCRIPTION
#    Give whois info on destination ips for a flow
#
# OPTIONS
#    -h    print help and exit
#
__END_USAGE__

use Getopt::Long;
my %OPTS;
#getopts ("hs:e:b:", \%OPTS);
print $USAGE and exit if $OPTS{'h'};

my $start_date = '';
my $end_date = '';
my $bytes = 0;
my $count = 0;

GetOptions(
    'start_date=s' => \$start_date,
    'end_date=s'   => \$end_date,
    'bytes=i'      => \$bytes,
    'count=i'      => \$count,
) or die "Incorrect usage!\n";

#print "Start date = $start_date\nEnd date = $end_date\nbytes = $bytes\n";


if (!@ARGV){
   print "$0: Arguement required!\n";
   exit 1;
}

my $src_ip = @ARGV[0];




#print "This is working\n";
# Start second, minute, hour, day, month, year, wday, yday, isdst
my @current_date = my ($ssec, $smin, $shr, $smday, $smon, $syear, $swday, $syday, $sisdst) = localtime(time);
$syear += 1900;
$smon += 1;
#print @current_date;
#print "\nThat was the date\n";
#print "day = $smday\nmonth = $smon\nyear = $syear";
$smon = sprintf("%2d", $smon);
$smon =~ tr/ /0/;
$smday = sprintf("%2d", $smday);
$smday =~ tr/ /0/;

#print "day = $smday\nmonth = $smon\nyear = $syear";

#$start_date = join('/', $syear, $smon, $smday);


# $count, $bytes, $start_date and $end_date can be defined as options. If they aren't, populate with defaults.
if (!$bytes){ $bytes = 10;}
my $emday = $smday + 1;
if (!$start_date){ $start_date = "$syear/$smon/$smday";}
if (!$end_date){ $end_date = "$syear/$smon/$emday";}
print "Start date = $start_date\n";
print "End date = $end_date\n";
print "Bytes = $bytes\n";

# Get netflow data
my @dump_out = `/usr/local/bin/nfdump -R /data/nfsen/profiles-data/live/comm-d123-g -a -L +$bytes\M -c 5 -t $start_date-$end_date ' src ip $src_ip' `;

#print "Dump out = @dump_out";


# Open file for destination ip addresses
open FILE, ">dst_ips.txt" or die $!;

#Add "begin" to the file 
print FILE "begin\n";

#print "this should be the dst ip's\n";

my @bytes_per_flow;
my $dstip_cnt = 0;

foreach $flow (@dump_out){
    
#    print $flow;
    #split line by "->" to get dstip: second argument of flow_line should now be the dst ip addr
    my @flow_line = split(/->/, $flow);
#    print @flow_line[1];
    #cut off dstip by splitting it at the port.
    my @flow_dstip = split(/:/, @flow_line[1]);
    my $dstip = @flow_dstip[0];
#    my $dst_bytes = (@flow_dstip[0] =~ /[0-9]+(\.[0-9][0-9]?)?/ );
    my @tokens = split(/ /, $flow_dstip[1]);
    my $tok_count = 0;
    foreach my $tok (@tokens){
        if ($tok ne ''){
            $tok_count++;
            if ($tok_count == 3){
                if ($tok =~ m/^[0-9]+\.[0-9]+/){
                    @bytes_per_flow[$dstip_cnt] = $tok;
#                print "Tok stored = $tok\n";
                }else{
                  print "Not a valid byte count\n";
                }
            }
        }
    }
    
#    if (@flow_dstip[1] =~ /^.+\.[0-9]\s.+$/ ){
#        print "@flow_dstip\n";
#        my $dst_bytes = $1 if @flow_dstip[1] =~ s/.+[0-9]+\.[0-9].+//g ;
#        print "these bytes = $dst_bytes\n";
       
#    }
    $dstip =~ s/^\s*(.*)\s*$/$1/;
#    print $dstip;
    # TODO: Write a better check than this
    if ($dstip =~ m/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/){
#        print "dstip = $dstip\n";
#        print "ips counted = $dstip_cnt\n";
        $dstip_cnt++;
    }else{
        next;
    }
    if ($dstip) { print FILE "$dstip\n"; }
    
#    print "\n$dstip\n";
}

print "Bytes per flow:\n@bytes_per_flow\n";



#print "Hopefully there was something in between here\n";

print FILE "end\n";


close FILE;

print "#cli:             $src_ip\n";
print "#Source IP        $ARGV[0]\n";
print "#Target time      $start_date - $end_date\n";
print "#threshold        $bytes bytes per host during sample interval\n";
print "#run              @current_date\n";

@whois_out = `nc whois.cymru.com 43 < dst_ips.txt`;

print @whois_out;
