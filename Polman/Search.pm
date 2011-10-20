# ----------------------------------------------------------------------
# The Advanced Policy-Manager for IPS/IDS Sensors
# Copyright (C) 2010-2011, Edward Fjellskål <edwardfjellskaal@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
# ----------------------------------------------------------------------

use strict;
package Polman::Search;
use Polman::Common qw/sensor_enable_sid sensor_disable_sid get_rule check_for_new_ruledb_sids/;
use Exporter;
use vars qw (@ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);

@ISA = qw (Exporter);

@EXPORT = qw (search_rules search_rules_cat search_rules_enabled
              proccess_list_of_rules search_rules_maindb print_rule
              search_rules_flowbits_isset_isnotset search_rules_flowbits_set
              search_rules_flow search_new_rules);

@EXPORT_OK = qw (search_rules search_rules_cat search_rules_enabled
                proccess_list_of_rules search_rules_maindb print_rule
                search_rules_flowbits_isset_isnotset search_rules_flowbits_set
                search_rules_flow search_new_rules);

%EXPORT_TAGS = (all => [@EXPORT_OK]); # Import :all to get everything.

=head1 NAME 

 Polman::Search - Subs for searching in Polmans RuleDBs and applying to Sensors

=head1 VERSION

 0.1

=head1 DESCRIPTION

 Modules for searching in RuleDBs and applying to Sensors

=cut

=head1 FUNCTIONS

=head2 search_rules

 Searches through rules in specified fields

=cut

# Redo this to include _ALL_ searches one day in a more elegant fasion!
sub search_rules {
    my ($SENSOR,$SENSH,$RULEDB,$RDBH,$SEARCH_C,$SEARCH_M,$SEARCH_P,$VERBOSE,$DEBUG) = @_;
    # Searchs can be complex:
    # * can consist of searches in fileds: msg, metadata and classtype
    # So defining priority on search fields:
    # 1. Classtype, 2. Metadata, 3, MSG
    my $STYPE = 0;
    my $SRDB_C = {};
    my $SRDB_P = {};
    my $SRDB_M = {};
    my $SRDB   = {};

    # Populate search results
    # We should extend this to include to search for "enabled" and "catagory" as well!
    if (defined $SEARCH_C && $SEARCH_C ne "" ) {
        $STYPE += 1;
        # $RDBH,$RULEDB,$search,$field,$VERBOSE,$DEBUG
        $SRDB_C = search_rules_maindb($RDBH,$RULEDB,$SEARCH_C,"classtype",$VERBOSE,$DEBUG);
    }
    if (defined $SEARCH_P && $SEARCH_P ne "" ) {
        $STYPE += 2;
        $SRDB_P = search_rules_maindb($RDBH,$RULEDB,$SEARCH_P,"metadata",$VERBOSE,$DEBUG);
    }
    if (defined $SEARCH_M && $SEARCH_M ne "" ) {
        $STYPE += 4;
        $SRDB_M = search_rules_maindb($RDBH,$RULEDB,$SEARCH_M,"msg",$VERBOSE,$DEBUG);
    }

    # Easy searches
    if ( $STYPE == 1) {
        foreach my $sid (keys %$SRDB_C) {
            $SRDB->{$sid} = $SRDB_C->{$sid};
        }
    }
    elsif ( $STYPE == 2) {
        foreach my $sid (keys %$SRDB_P) {
            $SRDB->{$sid} = $SRDB_C->{$sid};
        }
    }
    elsif ( $STYPE == 4) {
        foreach my $sid (keys %$SRDB_M) {
            $SRDB->{$sid} = $SRDB_C->{$sid};
        }
    }

    # Complex searches
    elsif ( $STYPE == 3 ) {
        # C+P
        foreach my $sid (keys %$SRDB_C) {
            if (defined $SRDB_P->{$sid}) {
                $SRDB->{$sid} = $SRDB_C->{$sid};
            }
        }
    }
    elsif ( $STYPE == 5 ) {
        # C+M
        foreach my $sid (keys %$SRDB_C) {
            if (defined $SRDB_M->{$sid}) {
                $SRDB->{$sid} = $SRDB_C->{$sid};
            }
        }
    }
    elsif ( $STYPE == 6 ) {
        # P+M
        foreach my $sid (keys %$SRDB_P) {
            if (defined $SRDB_M->{$sid}) {
                $SRDB->{$sid} = $SRDB_P->{$sid};
            }
        }
    }
    elsif ( $STYPE == 7 ) {
        # C+P+M
        foreach my $sid (keys %$SRDB_C) {
            if (defined $SRDB_P->{$sid} && defined $SRDB_M->{$sid}) {
                $SRDB->{$sid} = $SRDB_C->{$sid};
            }
        }
    }

    $SENSH = proccess_list_of_rules($SENSOR,$SENSH,$RULEDB,$RDBH,$SRDB,$VERBOSE,$DEBUG);
    return $SENSH;
}

=head2 search_new_rules

 Searches for rules in ruledb which are not in the sensor rules

=cut

sub search_new_rules {
    my ($SENSOR,$SENSH,$RULEDB,$RDBH,$AUTO,$VERBOSE,$DEBUG) = @_;

    my $SRDB = {};
    my $rules = $RDBH->{$RULEDB}->{1};

    if ($AUTO == 1) {
        # autoenable in default state
        $SENSH = check_for_new_ruledb_sids ($SENSOR,$SENSH,$RULEDB,$RDBH,"default",$VERBOSE,$DEBUG);
    } else {
        foreach my $sid (keys %$rules) {
            if ( not defined $SENSH->{$SENSOR}->{1}->{'RULES'}->{$sid} ) {
                $SRDB->{$sid} = $RDBH->{$RULEDB}->{1}->{$sid};
            } # Skip old rules
        }  
        $SENSH = proccess_list_of_rules($SENSOR,$SENSH,$RULEDB,$RDBH,$SRDB,$VERBOSE,$DEBUG);
    }
    return $SENSH;
}

=head2 search_rules_cat

 Searches for rules in specific catagorty

=cut

sub search_rules_cat {
    my ($SENSOR,$SENSH,$RULEDB,$RDBH,$SEARCH_CAT,$VERBOSE,$DEBUG) = @_;
    my $SRDB = {};

    # Populate search results
    if (defined $SEARCH_CAT) {
        $SRDB = search_rules_maindb($RDBH,$RULEDB,$SEARCH_CAT,"catagory",$VERBOSE,$DEBUG);
        $SENSH = proccess_list_of_rules($SENSOR,$SENSH,$RULEDB,$RDBH,$SRDB,$VERBOSE,$DEBUG);
    }
    return $SENSH;
}

=head2 search_rules_flow

 Searches for rules that has a specific flowbits option

=cut

sub search_rules_flow {
    my ($SENSOR,$SENSH,$RULEDB,$RDBH,$SEARCH_F,$VERBOSE,$DEBUG) = @_;
    my $SRDB = {};

    # Populate search results
    if (defined $SEARCH_F) {
        $SRDB = search_rules_maindb($RDBH,$RULEDB,$SEARCH_F,"flowbits",$VERBOSE,$DEBUG);
        $SENSH = proccess_list_of_rules($SENSOR,$SENSH,$RULEDB,$RDBH,$SRDB,$VERBOSE,$DEBUG);
    }
    return $SENSH;
}

=head2 search_rules_enabled

 Searches for rules that are default enabled by provider

=cut

sub search_rules_enabled {
    my ($SENSOR,$SENSH,$RULEDB,$RDBH,$SEARCH_E,$VERBOSE,$DEBUG) = @_;
    my $SRDB = {};

    # Populate search results
    if (defined $SEARCH_E) {
        $SRDB = search_rules_maindb($RDBH,$RULEDB,$SEARCH_E,"enabled",$VERBOSE,$DEBUG);
        $SENSH = proccess_list_of_rules($SENSOR,$SENSH,$RULEDB,$RDBH,$SRDB,$VERBOSE,$DEBUG);
    }
    return $SENSH;
}

=head2 search_rules_flowbits_isset_isnotset

 Searches for rules that is depended on a flowbit is set.

=cut

sub search_rules_flowbits_isset_isnotset {
    my ($SENSOR,$SENSH,$RULEDB,$RDBH,$VERBOSE,$DEBUG) = @_;
    my $FLOWBITS = [];
    my $FLOWBITS_UNIQ = [];
    my $SENSORRULES = $SENSH->{$SENSOR}->{1}->{'RULES'};
    my $count = 0;

    foreach my $sid (keys %$SENSORRULES) {
        $count ++;
        if ( $count == 5000 ) {
            print "." if not defined ($DEBUG||$VERBOSE) ;
            $count = 0;
        }
        if ( defined $RDBH->{$RULEDB}->{1}->{$sid}->{'options'} ) {
            #next if not defined $SENSH->{$SENSOR}->{1}->{'RULES'}->{$sid}->{'enabled'};
            next if not defined $SENSORRULES->{$sid}{'enabled'};
            #next if $SENSH->{$SENSOR}->{1}->{'RULES'}->{$sid}->{'enabled'} == 0;
            next if $SENSORRULES->{$sid}{'enabled'} == 0;
            while ( $RDBH->{$RULEDB}->{1}->{$sid}->{'options'} =~ /flowbits:\s?(is(not)?|un)set,\s?([\w.]*)\s?;/g ) {
            #if ( $RDBH->{$RULEDB}->{1}->{$sid}->{'options'} =~ /flowbits:\s?(is(not)?|un)set,\s?([\w.]*)\s?;/ ) {
                my $fb = $3;
                print "[D] Got flowbit $1set: $fb\n" if ($VERBOSE||$DEBUG);
                push (@$FLOWBITS, $fb);
            }
        }
    }
    my %seen = ();
    @$FLOWBITS_UNIQ = grep { ! $seen{ $_ }++ } @$FLOWBITS;
    print "[D] Found " if ($VERBOSE||$DEBUG);
    print scalar(@$FLOWBITS_UNIQ) if ($VERBOSE||$DEBUG);
    print " unique flowbits...\n" if ($VERBOSE||$DEBUG);
    return $FLOWBITS_UNIQ;
}

=head2 search_rules_flowbits_set

 Searches for rules that sets flowbits

=cut

sub search_rules_flowbits_set {
    my ($SENSOR,$SENSH,$RULEDB,$RDBH,$FLOWBITS,$VERBOSE,$DEBUG) = @_;
    my $retrules = {};
    my $count = 0;
    return $retrules if (!@$FLOWBITS);

    my $rules = $RDBH->{$RULEDB}->{1};
    foreach my $sid (keys %$rules ) {
        next if (not defined $sid || $sid eq '');
        $count ++;
        if ( $count == 3737 ) {
            print "." if not defined ($DEBUG||$VERBOSE) ;
            $count = 0;
        }
        foreach my $flowbit (@$FLOWBITS) {
            next if (not defined $flowbit);
            #if ( $RDBH->{$RULEDB}->{1}->{$sid}->{'options'} =~ /flowbits:\s?set,\s?$flowbit\s?;/ ) {
            if ( $rules->{$sid}{'options'} =~ /flowbits:\s?set,\s?$flowbit\s?;/ ) {
                $retrules->{$sid} = 1;
                #print "[*] Sid $sid sets flowbit $flowbit: " . $RDBH->{$RULEDB}->{1}->{$sid}->{'name'} . "\n" if ($VERBOSE||$DEBUG);
                print "[*] Sid $sid sets flowbit $flowbit: " . $rules->{$sid}{'name'} . "\n" if ($VERBOSE||$DEBUG);
            }
        }
    }
    return $retrules;
}

=head2 proccess_list_of_rules

 Takes a hash of rules and prints/enables/disables them.

=cut

sub proccess_list_of_rules {
    my ($SENSOR,$SENSH,$RULEDB,$RDBH,$rules,$VERBOSE,$DEBUG) = @_;
    #my ($rules,$RULEDB,$SENSOR) = @_;
    my $count = 0;
    my $ACTION = qq(current);
    my $RESP = qq();

    if ( not defined $rules ) {
        print "[*] Empty search result... \n";
        return $SENSH;
    }
    foreach (keys %$rules) {
        $count ++;
    }

    if ( $count > 0) {
        print "[*] Found $count rule(s) matching search criterias...\n";
        foreach my $sid (sort keys %$rules) {
            my $enabled;
            my $action;
            if (defined $SENSH->{$SENSOR}->{1}->{'RULES'}->{$sid}->{'enabled'} &&
                $SENSH->{$SENSOR}->{1}->{'RULES'}->{$sid}->{'enabled'} == 1) {
                $action = $SENSH->{$SENSOR}->{1}->{'RULES'}->{$sid}->{'action'};
                $enabled = "E";
            } else {
                $action = $RDBH->{$RULEDB}->{1}->{$sid}->{'action'};
                $enabled = "D";
            }
            print "[**] [$enabled] sid:$sid [$action] (" . $RDBH->{$RULEDB}->{1}->{$sid}->{'name'} . ")\n";
        }
        if ( $count > 35) {
            print "[*] Displayed $count rules...\n";
        }
        # Disable rules
        print "[i] Do you want to Disable all rules for sensor $SENSOR? (y/N)?: ";
        my $DRESP = <STDIN> ;
        chomp $DRESP;
        if ( $DRESP eq "y" || $DRESP eq "yes" || $DRESP eq "Y" || $DRESP eq "YES") {
            foreach my $DSID (keys %$rules) {
                $SENSH = sensor_disable_sid($DSID,$SENSOR,$SENSH,$RDBH,$RULEDB,$VERBOSE,$DEBUG);
            }
            return $SENSH;
        }
        # Enable rules
        print "[i] Do you want to Enable all rules for sensor $SENSOR? (y/N)?: ";
        my $ERESP = <STDIN> ;
        chomp $ERESP;
        if ( $ERESP eq "y" || $ERESP eq "yes" || $ERESP eq "Y" || $ERESP eq "YES") {

            # SET RULE ACTION
            print "[*] Do you want to change rule action for this search (y/N)?: ";
            $RESP = <STDIN>;
            chomp $RESP;
            if ( $RESP eq "y" || $RESP eq "yes" || $RESP eq "Y" || $RESP eq "YES") {
                print "[*] *default* will reset rule action to original source state.\n";
                print "[*] *current* will keep current state or use *default* if it is the first time the rule is enabled.\n";
                print "[*] Choose one of alert,log,pass,drop,reject,sdrop,default or current (default: current): ";
                $RESP = <STDIN>;
                chomp $RESP;
                if    ( $RESP eq "alert" )  {$ACTION = "alert"}
                elsif ( $RESP eq "log" )    {$ACTION = "log"}
                elsif ( $RESP eq "pass" )   {$ACTION = "pass"}
                elsif ( $RESP eq "drop" )   {$ACTION = "drop"}
                elsif ( $RESP eq "reject" ) {$ACTION = "reject"}
                elsif ( $RESP eq "sdrop" )  {$ACTION = "sdrop"}
                elsif ( $RESP eq "default" ){$ACTION = "default"}
                else { $ACTION = "current" }
                print "[*] Rule action for search is: $ACTION\n";
            }

            foreach my $ESID (keys %$rules) {
                $SENSH = sensor_enable_sid($ESID,$SENSOR,$SENSH,$RDBH,$RULEDB,$ACTION,$VERBOSE,$DEBUG);
            }
            return $SENSH;
        }
        print "[i] Do you want to Enable/Disable rule by rule (y/N)?: ";
        my $RBRRESP = <STDIN>;
        chomp $RBRRESP;
        if ( $RBRRESP eq "y" || $RBRRESP eq "yes" || $RBRRESP eq "Y" || $RBRRESP eq "YES") {
            foreach my $sid (keys %$rules) {
                print_rule($sid,$SENSOR,$SENSH,$RULEDB,$RDBH,$VERBOSE,$DEBUG);
                print "[i] Do you want to Enable/Disable or Skip processing of this rule (e/d/S)?: ";
                my $RBRRESP = <STDIN>;
                chomp $RBRRESP;
                if ( $RBRRESP eq "e" || $RBRRESP eq "E") {
                    # SET RULE ACTION
                    print "[*] Do you want to change rule action for this rule (y/N)?: ";
                    $RESP = <STDIN>;
                    chomp $RESP;
                    if ( $RESP eq "y" || $RESP eq "yes" || $RESP eq "Y" || $RESP eq "YES") {
                        print "[*] *default* will reset rule action to original source state.\n";
                        print "[*] *current* will keep current state or use *default* if it is the first time the rule is enabled.\n";
                        print "[*] Choose one of alert,log,pass,drop,reject,sdrop,default or current (default: current): ";
                        $RESP = <STDIN>;
                        chomp $RESP;
                        if    ( $RESP eq "alert" )  {$ACTION = "alert"}
                        elsif ( $RESP eq "log" )    {$ACTION = "log"}
                        elsif ( $RESP eq "pass" )   {$ACTION = "pass"}
                        elsif ( $RESP eq "drop" )   {$ACTION = "drop"}
                        elsif ( $RESP eq "reject" ) {$ACTION = "reject"}
                        elsif ( $RESP eq "sdrop" )  {$ACTION = "sdrop"}
                        elsif ( $RESP eq "default" ){$ACTION = "default"}
                        else { $ACTION = "current" }
                    }
                    print "[*] Rule action for sid $sid is set to: $ACTION\n";
                    $SENSH = sensor_enable_sid($sid,$SENSOR,$SENSH,$RDBH,$RULEDB,$ACTION,$VERBOSE,$DEBUG);
                } elsif ( $RBRRESP eq "d" || $RBRRESP eq "D") {
                    $SENSH = sensor_disable_sid($sid,$SENSOR,$SENSH,$RDBH,$RULEDB,$VERBOSE,$DEBUG);
                } else {
                    print "[*] Skipping processing of rule...\n";
                }
            }
            return $SENSH;
        }

    } else {
        print "[*] Empty search result... \n";
        return $SENSH;
    }

}

=head2 search_rules_maindb

 searches through main rules db

=cut

sub search_rules_maindb {
    my ($RDBH,$RULEDB,$search,$field,$VERBOSE,$DEBUG) = @_;
    my $retrules = {};
    return $retrules if not defined $RULEDB;
    return $retrules if not defined $RDBH->{$RULEDB};
    my $rules = $RDBH->{$RULEDB}->{1};
    my ($msg, $class, $meta, $cata, $flowbit) = qq();

    print "[*] Search term: $search\n" if ($VERBOSE||$DEBUG);
    print "[*] Search field: $field\n" if ($VERBOSE||$DEBUG);

    foreach my $sid (keys %$rules ) {
        next if (not defined $sid);
        if ( defined $RDBH->{$RULEDB}->{1}->{$sid}->{'options'} ) {
            if ( $field eq "msg" && $RDBH->{$RULEDB}->{1}->{$sid}->{'options'}  =~ /msg:\s*\"(.*?)\"\s*;/ ) {
                $msg = $1;
                if ($msg =~ /$search/i) {
                    $retrules->{$sid} = $RDBH->{$RULEDB}->{1}->{$sid};
                    print "[*] Sid $sid matches: " . $RDBH->{$RULEDB}->{1}->{$sid}->{'name'} . "\n" if $DEBUG;
                }
            }
            elsif ( $field eq "classtype" && $RDBH->{$RULEDB}->{1}->{$sid}->{'options'}  =~ /classtype:\s*(.*?)\s*;/ ) {
                $class = $1;
                if ($class =~ /$search/) {
                    $retrules->{$sid} = $RDBH->{$RULEDB}->{1}->{$sid};
                    print "[*] Sid $sid matches: " . $RDBH->{$RULEDB}->{1}->{$sid}->{'name'} . "\n" if $DEBUG;
                }
            }
            elsif ( $field eq "metadata" && $RDBH->{$RULEDB}->{1}->{$sid}->{'options'}  =~ /metadata:\s*(.*?)\s*;/ ) {
                $meta = $1;
                if ($meta =~ /$search/i) {
                    $retrules->{$sid} = $RDBH->{$RULEDB}->{1}->{$sid};
                    print "[*] Sid $sid matches: " . $RDBH->{$RULEDB}->{1}->{$sid}->{'name'} . "\n" if $DEBUG;
                }
            }
            elsif ( $field eq "catagory" && defined $RDBH->{$RULEDB}->{1}->{$sid}->{'rulegroup'} ) {
                $cata = $RDBH->{$RULEDB}->{1}->{$sid}->{'rulegroup'};
                if ($cata =~ /$search/i) {
                    $retrules->{$sid} = $RDBH->{$RULEDB}->{1}->{$sid};
                    print "[*] Sid $sid matches: " . $RDBH->{$RULEDB}->{1}->{$sid}->{'name'} . "\n" if $DEBUG;
                }
            }
            #elsif ( $field eq "flowbits" && $RDBH->{$RULEDB}->{1}->{$sid}->{'options'}  =~ /flowbits:\s*(.*?)\s*;/ ) {
            elsif ( $field eq "flowbits" && $RDBH->{$RULEDB}->{1}->{$sid}->{'options'} ) {
                while ( $RDBH->{$RULEDB}->{1}->{$sid}->{'options'} =~ /flowbits:\s?(is(not)?|un)?set\s?,\s?([\w.]*)\s?;/g ) {
                    $flowbit = $3;
                    if ($flowbit =~ /$search/i) {
                        $retrules->{$sid} = $RDBH->{$RULEDB}->{1}->{$sid};
                        print "[*] Sid $sid matches: " . $RDBH->{$RULEDB}->{1}->{$sid}->{'name'} . "\n" if $DEBUG;
                    }
                }
            }
            elsif ( $field eq "enabled" && defined $RDBH->{$RULEDB}->{1}->{$sid}->{'enabled'} ) {
                if ( $RDBH->{$RULEDB}->{1}->{$sid}->{'enabled'} == $search ) {
                    $retrules->{$sid} = $RDBH->{$RULEDB}->{1}->{$sid};
                    print "[*] Sid $sid matches: " . $RDBH->{$RULEDB}->{1}->{$sid}->{'name'} . "\n" if $DEBUG;
                }
            }
        }
    }
    return $retrules;
}

=head2 print_rule

 Prints out the rule corrosponding to the sid:gid

=cut

sub print_rule {
    my ($sid,$SENSOR,$SENSH,$RULEDB,$RDBH,$VERBOSE,$DEBUG) = @_;
    my $enabled = qq();

    if ( defined $SENSH->{$SENSOR}->{1}->{'RULES'}->{$sid} && 
         defined $SENSH->{$SENSOR}->{1}->{'RULES'}->{$sid}->{'enabled'} &&
         defined $SENSH->{$SENSOR}->{1}->{'RULES'}->{$sid}->{'enabled'} == 1) {
        $enabled = "enabled";
    } else {
        $enabled = "disabled";
    }

    if (defined $RDBH->{$RULEDB}->{1}->{$sid}) {
        print "[*] Displaying $enabled sid $sid:\n";
        my $rule = get_rule($SENSOR,$SENSH,$RULEDB,$RDBH,$sid,$VERBOSE,$DEBUG);
        print "$rule\n";
    } else {
        print "[W] Sid $sid is not found in main rule DB, skipping!\n"; # could add, as it does not matter...
    }
}

1;
