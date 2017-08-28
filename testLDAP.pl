#!/usr/local/perl-5.10.0/bin/perl
###############################################
# BiffSocko
# testLDAP.pl
#
# query by username
###############################################
use Net::LDAP;

my $ldap   = undef;
my $result = undef;
my $msg    = undef;
my $entry  = undef;

if(@ARGV != 1){
        print "usage: $0 [username]\n";
        exit(1);
}
#######################################
# connect & bind to LDAP server       #
#######################################
if(!($ldap = Net::LDAP->new('addc003.ad.mlp.com'))){
        print "Error connecting to LDAP\n";
        exit(1);
}

$result = $ldap->bind('CN=ServiceLDAP,OU=Directory,OU=Service_Accounts,OU=IT,OU=AD_Users,DC=AD,DC=FOO,DC=com',
                       password => 'YourPasswordHere');

if ($result->code) {
        print "$result->code\n";
        print "An error occurred binding to the LDAP server\n" ;
        exit(1);
}

$msg = $ldap->search( # perform a search
                        base   => "dc=AD,dc=FOO,dc=com",
                        #filter => "(sn=murphy)"
                        #filter => "(uid=tmurphy)"
                        filter => "(uid=$ARGV[0])"
                      );

foreach $entry ($msg->all_entries) {
        $entry->dump;
}
$ldap->unbind;

