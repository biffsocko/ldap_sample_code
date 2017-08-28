#!/ms/dist/perl5/bin/perl
############################################################
# BiffSocko
# ldap_biff.pl
#
# 
##!/ms/dist/perl5/bin/perl5.8
# causes problems with conf modules (<DB name.pm> vs. MSDW::Version...)
# TODO fix at some point to swith to perl5.8

################################################################################
use Mozilla::LDAP::Conn;	# LDAP Connection management
use Mozilla::LDAP::Entry;       # LDAP Entry handling
use Mozilla::LDAP::Utils;
use Mozilla::LDAP::API qw(:api :constant);
use File::Copy;

################################################################################
# BEGIN
################################################################################
BEGIN
{
    if ( scalar(@ARGV) != 1 )   # 1 argument, UID
    {
        print "usage: meta_extract.pl USERID\n";
        die "Invalid argument list.\n";
    }
    else
    {
        $UID = $ARGV[0];
    }
}                               # end BEGIN

################################################################################
# LDAP STUFF
################################################################################
@attr = qw(employeenumber uid manager);

#
# firmwide directory access criteria.
#
$ld{host}="fwldap-prod.corpms.com";
$ld{port}="389";
$ld{bind}="cn=aribasystem,ou=ldapids,o=morgan stanley";
$ld{pswd}=`/u/ariba/util/Decrypt_File.pl /u/ariba/.Key/Key.PROD /u/ariba/v8/DEV_MSDW_Common_Interface/Configure/.Password/Ariba_LDAP.TEST`;
chomp $ld{pswd};
$ld{base}="ou=people,o=morgan stanley";

$conn = new Mozilla::LDAP::Conn(\%ld);
	die "Could not connect to firmwide LDAP server $ld{host}" unless $conn;

####################
# Search for uid
####################
#print STDERR "********************\nStart Search Time: ", `date`;
$entry = $conn->search($ld{base},"","(uid=$UID)",0,@attr);
#$entry = $conn->search($ld{base},"","(msfwid=$UID)",0,@attr);
#print STDERR "End Search Time: ", `date`;


while ( $entry )
{
    $enum = $entry->{employeenumber}[0];
    $enum =~ s/^\s+//;          # strip off leading whitespace
    $enum =~ s/\s+$//;          # strip off trailing whitespace

    $uid = $entry->{uid}[0];
    $uid =~ s/^\s+//;           # strip off leading whitespace
       $uid =~ s/\s+$//;           # strip off trailing whitespace

    $manager = $entry->{manager}[0];
       $manager  =~ s/^\s+//;         # strip off leading whitespace
       $manager  =~ s/msfwid=//;         # strip off leading whitespace
       $manager  =~ s/,(.*)$//;         # strip off leading whitespace
    $manager  =~ s/\s+$//;         # strip off trailing whitespace


    #print "UID = $uid||Manager = $manager\n";
    $entry = $conn->nextEntry();
}

@attr = qw(uid);
$entry = $conn->search($ld{base},"","(msfwid=$manager)",0,@attr);
while ( $entry )
{
   $managerid=$entry->{uid}[0];
   $managerid =~ s/^\s+//;      # strip off leading whitespace
   $managerid =~ s/\s+$//;      # strip off trailing whitespace
    $entry = $conn->nextEntry();
}

    print "UID = $uid||Manager msfwid = $manager || manager userid = $managerid\n";

