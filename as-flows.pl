#!/usr/local/bin/perl
#use strict;
#use warnings;
use Net::IP;



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
#    $0 [-h]                        - for help 
#    $0 src                         - to run
#    $0 -s  [yyyy/mm/dd.hh:mm:ss]   - for starting date
#    $0 -e  [yyyy/mm/dd.hh:mm:ss]   - for ending date
#    $0 -b  [BYTES]                 - for flows over a byte limit
#    $0 -c  [COUNT]                 - limit the number of flows viewed
#
# DESCRIPTION
#    Give whois info on destination ips for a flow
#
# OPTIONS
#    -h    print help and exit
# 
# NOTE: Make sure the port number is not still attached to the end of the ip address you're running
#
__END_USAGE__

use Getopt::Long;
my %OPTS;
#getopts ("hs:e:b:", \%OPTS);
print $USAGE and exit if $OPTS{'h'};

#initialize the option variables 
my $start_date = '';
my $end_date = '';
my $bytes = 0;
my $count = 0;

# If an option is given, set the corrosponding variable
GetOptions(
    'start_date=s' => \$start_date,
    'end_date=s'   => \$end_date,
    'bytes=i'      => \$bytes,
    'count=i'      => \$count,
) or die "Incorrect usage!\n";

#print "Start date = $start_date\nEnd date = $end_date\nbytes = $bytes\n";


# if no arguements are given pring help message and exit
if (!@ARGV){
   print $USAGE;
   exit 1;
}

# Set the source ip to be the first arguement
my $src_ip = @ARGV[0];




# Init second, minute, hour, day, month, year, wday, yday, isdst to be the current time. 
my @current_date = my ($ssec, $smin, $shr, $smday, $smon, $syear, $swday, $syday, $sisdst) = localtime(time);
$syear += 1900;
$smon += 1;
$smon = sprintf("%2d", $smon);
$smon =~ tr/ /0/;
$smday = sprintf("%2d", $smday);
$smday =~ tr/ /0/;

# $count, $bytes, $start_date and $end_date can be defined as options. If they aren't, populate with defaults.
if (!$bytes){ $bytes = 10;}
my $emday = $smday + 1;
if (!$start_date){ $start_date = "$syear/$smon/$smday";}
if (!$end_date){ $end_date = "$syear/$smon/$emday";}
print "Start date = $start_date\n";
print "End date = $end_date\n";
print "Bytes = $bytes\n";

# Count '.'s, if it's an ipv4 address there should be 3
my $ipv4_count = $src_ip =~ tr/.//;
# Count ':'s, if it's an ipv6 address there should be at least two
my $ipv6_count = $src_ip =~ tr/://;
# (0 for v4, 1 for v6)
my $ip_version = 0;

if ($ipv4_count >= 3 && $ipv6_count <= 1){
    print "IPv4\n";
    $ip_version = 0;
}elsif ($ipv6_count >= 2 && $ipv4_count <= 1){
    print "IPv6\n";
    $ip_version = 1;
}else{
    print "Are you sure that's a valid IP address?\n";
    exit(1);
}


# Translate the ip address from input to a more standard format
my $ip = new Net::IP($src_ip) or die (Net::IP::Error());
#my $ip = ipv6_expand_2($src_ip);

# Grab the actual ip address from the structure
my $ip_addr = $ip->ip();

# Get netflow data
my @dump_out;
#my @dump_out = `/usr/local/bin/nfdump -R /data/nfsen/profiles-data/live/comm-d123-g/2012/09/12 -6 -a -L +$bytes\M -c 5 -t $start_date-$end_date -o line6 'inet6 and src ip $ip_addr' `;
if ($ip_version & 1){
    @dump_out = `/usr/local/bin/nfdump -R /data/nfsen/profiles-data/live/comm-d123-g/ -a -L +$bytes -c 5 -t $start_date-$end_date -o line6 'inet6 and src ip $ip_addr'`;
}else{
    @dump_out = `/usr/local/bin/nfdump -R /data/nfsen/profiles-data/live/comm-d123-g/ -a -L +$bytes -c 5 -t $start_date-$end_date -o line6 'src ip $ip_addr'`;
}

#print "Dump out = @dump_out";


# Open file for destination ip addresses
open FILE, ">dst_ips.txt" or die $!;

#Add "begin" to the file 
print FILE "begin\n";

#print "this should be the dst ip's\n";

# bytes per flow tracks the bytes for each flow given
my @bytes_per_flow;
my $dstip_cnt = 0;
my @flow_dstip;

# This loop runs through the nfdump output and stores the bytes per flow,
# as well as the destination ip addresses. If the destination ip address
# is present it'll write it to a file, which can then be processed by whois
foreach $flow (@dump_out){
    # split line by "->" to get dstip: second argument of flow_line should now be the dst ip addr
    my @flow_line = split(/->/, $flow);
    if ($ip_version & 1){
        # cut off dstip by splitting it at the port, which is deliminated by the '.'.
        @flow_dstip = split('\\.', @flow_line[1]);
    }else{
        # cut off dstip by splitting it at the port, which is deliminated by the '.'.
        @flow_dstip = split('\\:', @flow_line[1]);
    }
    # Get the first element of the new list, which will be the destination ip address if the format is the same
    my $dstip = @flow_dstip[0];
#    my $dst_bytes = (@flow_dstip[0] =~ /[0-9]+(\.[0-9][0-9]?)?/ );

    my @tokens = split(/ /, $flow_dstip[1]);
    my $tok_count = 0;
    # This loop finds the bytes associated with each line of the nfdump output. It get the third element of the list
    # which, with the current nfdump format, is the bytes. It verifies that it has gotten a number, and stores the 
    # bytes in an array.
    foreach my $tok (@tokens){
        if ($tok ne ''){
            $tok_count++;
            if ($tok_count == 3){
                # This regex is for a a decimal number, which is what the bytes will show up as
                if ($tok =~ m/^[0-9]+(\.[0-9]+)?/){
                    @bytes_per_flow[$dstip_cnt] = $tok;
                }else{
                  print "Not a valid byte count\n";
                }
            }
        }
    }
    
    $dstip =~ s/^\s*(.*)\s*$/$1/;
#    print "dst ip = $dstip\n";
    if ($ip_version & 1){
        # Regex to match ipv6 address
        if ($dstip =~ m/^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$/ ){
            $dstip_cnt++;
        }else{
            next;
        }
    }else{
        # Regex to match ipv4 address 
        if ($dstip =~ m/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/){
            $dstip_cnt++;
        }else{
            next;
        }
    }
    if ($dstip) { print FILE "$dstip\n"; }
}        



print FILE "end\n";


close FILE;

print "\n";
print "#cli:             $src_ip\n";
print "#Source IP        $ARGV[0]\n";
print "#Target time      $start_date - $end_date\n";
print "#threshold        $bytes bytes per host during sample interval\n";
print "#run              @current_date\n";
print "\n";

@whois_out = `nc whois.cymru.com 43 < dst_ips.txt`;
my $output_line;
my $itor = 0;
foreach $line (@whois_out){
    chomp($line);
    if($itor > 0){ 
        $output_line = $line . "  " . $bytes_per_flow[$itor-1];
    }else{
        $output_line = "AS      |     IP address                           |              Location                      | Bytes";
    }
    $itor++;
    print "$output_line\n";
}
    

#print @whois_out;


#print "Bytes per flow:\n@bytes_per_flow\n";

# This function takes a compressed ipv6 address and expands it
#Got this code from http://www.monkey-mind.net/code/perl/ipv6_expand.html

sub ipv6_expand_2 {
    local($_) = shift;
    s/^:/0:/;
    s/:$/:0/;
    s/(^|:)([^:]{1,3})(?=:|$)/$1.substr("0000$2", -4)/ge;
    my $c = tr/:/:/;
    s/::/":".("0000:" x (8-$c))/e;
    return $_;
}
