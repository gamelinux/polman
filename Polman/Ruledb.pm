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
package Polman::Ruledb;
use Polman::Common qw/:all/;
use Polman::Parser qw/:all/;
use Exporter;
use vars qw (@ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);

@ISA = qw (Exporter);

@EXPORT = qw (is_defined_ruledb show_menu_ruledb add_ruledb choose_ruledb 
              show_ruledb_status edit_ruledb set_ruledb_rules_dir 
              set_ruledb_comment set_ruledb_name set_ruledb_engine_type
              load_rulefiles_into_db);

@EXPORT_OK = qw (is_defined_ruledb show_menu_ruledb add_ruledb choose_ruledb    
              show_ruledb_status edit_ruledb set_ruledb_rules_dir 
              set_ruledb_comment set_ruledb_name set_ruledb_engine_type
              load_rulefiles_into_db);

%EXPORT_TAGS = (all => [@EXPORT_OK]); # Import :all to get everything.

=head1 NAME 

 Polman::Ruledb - Subs for manipulating Polmans RuleDBs

=head1 VERSION

 0.1

=head1 DESCRIPTION

 Modules for manipulating Polman RuleDBs.

=cut

=head1 FUNCTIONS

=head2 is_defined_ruledb

 Checks if a $RULEDB exists in $RDB, if not - choose one.
 Return param : 1 if defined / 0 if not

=cut

sub is_defined_ruledb {
   my ($RULEDB,$RDBH,$VERBOSE,$DEBUG) = @_;
   if (not defined $RDBH) {
       print "[E] You need to add a RuleDB first!\n";
       return 0;
   } elsif (not defined $RDBH->{$RULEDB}) {
       print "[E] RuleDB $RULEDB does not exist!\n";
       return 0;
   } elsif (not defined $RDBH->{$RULEDB}->{'RULESDIRS'}) {
       print "[E] RuleDB is missing RULESDIRS entry!\n";
       return 0;
   } elsif (not defined $RDBH->{$RULEDB}->{'REVISION'}) {
       print "[E] RuleDB is missing REVISION entry!\n";
       return 0;
   } elsif (not defined $RDBH->{$RULEDB}->{'ENGINE'}) {
       print "[E] RuleDB is missing ENGINE entry!\n";
       return 0;
   } elsif (not defined $RDBH->{$RULEDB}->{'COMMENT'}) {
       print "[E] RuleDB is missing COMMENT entry!\n";
       return 0;
   } elsif (not defined $RDBH->{$RULEDB}->{'CREATED'}) {
       print "[E] RuleDB is missing CREATED entry!\n";
       return 0;
   } elsif (not defined $RDBH->{$RULEDB}->{'MODIFIED'}) {
       print "[E] RuleDB is missing MODIFIED entry!\n";
       return 0;
   } elsif (not defined $RDBH->{$RULEDB}->{'UPDATED'}) {
       print "[E] RuleDB is missing UPDATED entry!\n";
       return 0;
   } else {
       return 1;
   }
}

=head2 show_menu_ruledb

 Prints out the ruledb edit menu to stdout

=cut

sub show_menu_ruledb {
    my ($RULEDB,$VERBOSE,$DEBUG) = @_;
    print "\n";
    print " Current RuleDB: $RULEDB\n";
    print " *************** Edit RuleDBs ***************\n";
    print "  Item |  Description                        \n";
    print "    1  |  Choose RuleDB to edit              \n";
    print "    2  |  Add Rule DB (You need at least one)\n";
    print "    3  |  Change RuleDB Name                 \n";
    print "    4  |  Change RuleDB Engine Type          \n";
    print "    5  |  Change RuleDB Comment              \n";
    print "    6  |  Change RuleDB Rules Dir            \n";
    print "    7  |  Show RuleDB Status                 \n";
    print "    8  |  Load/Update Rules into RuleDB      \n";
#    print "    9  |  RuleDBs Summary                    \n";
    print "   99  |  Back To Main Menu                  \n";
    print "Enter Item: ";
}

=head2 add_ruledb

 Adds a ruledb ($RULEDB) to $RDB
 A ruledb holds all rules for a engine type.

 Return param : 1 OK, 0 FAIL

=cut

sub add_ruledb {
    my ($RDBH,$VERBOSE,$DEBUG) = @_;
    my $RULEDB = qq();;
    while ($RULEDB eq "") {
        $RULEDB = set_ruledb_name($RDBH,$VERBOSE,$DEBUG);
    }
    if ( not defined $RDBH->{$RULEDB} ) {
        print "[*] Creating RuleDB $RULEDB\n";
        $RDBH->{$RULEDB}->{'CREATED'} = time();
        $RDBH->{$RULEDB}->{'MODIFIED'} = time();
        $RDBH->{$RULEDB}->{'UPDATED'} = time();
        $RDBH->{$RULEDB}->{'REVISION'} = 0;
        set_ruledb_comment($RULEDB,$RDBH,$VERBOSE,$DEBUG);
        set_ruledb_engine_type($RULEDB,$RDBH,$VERBOSE,$DEBUG);
        set_ruledb_rules_dir($RULEDB,$RDBH,$VERBOSE,$DEBUG);
        print "[*] You can now load rules into ruledb $RULEDB\n";
        return ($RULEDB,$RDBH);
    } else {
        print "[W] RuleDB $RULEDB exists! Nothing to do here!...\n";
        return ($RULEDB,$RDBH);
    }
}

=head2 choose_ruledb

 Choose $RULEDB to work on.

 Return param : $RULEDB / undef

=cut

sub choose_ruledb {
    my ($RDBH,$VERBOSE,$DEBUG) = @_;
    my $count = 0;
    my $RULEDB = qq();

    print "\n";
    print " ************* Choose RuleDB ************\n";
    print "  item |  RuleDB                   \n";
    foreach my $RDBN ( keys %$RDBH ) {
        next if $RDBN eq "";
        $count ++;
        $RULEDB = $RDBN;
        print "    $count  |  $RDBN                   \n";
    }
    if ( $count == 0) {
        print "[E] No RuleDBs are defined!\n";
        return undef;
    }
    my $RESP = qq();
    while ($RULEDB ne "" ) {
        print "Enter item: ";
        $RESP = <STDIN>;
        chomp $RESP;
        $count = 0;
        if ( $RESP =~ /\d+/ ) {
            foreach my $RDBN ( keys %$RDBH ) {
                next if $RDBN eq "";
                $count ++;
                if ( $RESP == $count ) {
                    $RULEDB = $RDBN;
                    return $RULEDB;
                }
            }
        }
        print "[E] Not a valid item!\n";
    }
    exit;
}

=head2 show_ruledb_status

 Displays status for $RULEDB

 Return param : none

=cut

sub show_ruledb_status {
    my ($RULEDB,$RDBH,$VERBOSE,$DEBUG) = @_;
    my $count = 0;

    print "*------------------------------------------*\n";
    print "[i] RuleDB       : $RULEDB\n";
    my $ENGINE = $RDBH->{$RULEDB}->{'ENGINE'};
    print "[i] Engine Type  : $ENGINE\n";

    my $RDIRS = $RDBH->{$RULEDB}->{'RULESDIRS'};
    foreach my $RDIRN ( %$RDIRS ) {
        next if not $RDIRN =~ /\d+/;
        my $RDIR = $RDIRS->{$RDIRN};
        print "[i] Rules Dir    : $RDIR\n";
    }
    my $CT=localtime($RDBH->{$RULEDB}->{'CREATED'});
    my $MT=localtime($RDBH->{$RULEDB}->{'MODIFIED'});
    print "[i] Created      : $CT\n";
    print "[i] Last Modified: $MT\n";
    my $rules = $RDBH->{$RULEDB}->{1};
    foreach (keys %$rules) {
        $count ++;
    }
    print "[i] Rules loaded : $count\n";
    my $COMMENT = $RDBH->{$RULEDB}->{'COMMENT'};
    print "[i] Comment      : $COMMENT\n";
}

=head2 edit_ruledb

 Edits $RULEDB

 Return param : none

=cut

sub edit_ruledb {
    my ($RDBH,$VERBOSE,$DEBUG) = @_;
    my $run = 0;
    my $RULEDB = qq();
    my $RESP = qq();

    if (not defined $RDBH) {
        print "[*] No RuleDBs are defined, we need at least one! Adding...\n";
        ($RULEDB,$RDBH) = add_ruledb($RDBH,$VERBOSE,$DEBUG);
    } else {
        $RULEDB = choose_ruledb($RDBH,$VERBOSE,$DEBUG);
    }

    while ($run == 0) {
        show_menu_ruledb($RULEDB,$VERBOSE,$DEBUG);
        $RESP = <STDIN>;
        chomp $RESP;
        if ( $RESP eq "" or not $RESP =~ /^\d+$/ ) {
            print "[*] Not a valid entery!\n";
        }
        elsif ( $RESP == 1 ) {
            $RULEDB = choose_ruledb($RDBH,$VERBOSE,$DEBUG);
        }
        elsif ( $RESP == 2 ) {
            ($RULEDB,$RDBH) = add_ruledb($RDBH,$VERBOSE,$DEBUG);
        }
        elsif ( $RESP == 3 ) {
            $RULEDB = change_ruledb_name($RULEDB,$RDBH,$VERBOSE,$DEBUG);
        }
        elsif ( $RESP == 4 ) {
            set_ruledb_engine_type($RULEDB,$RDBH,$VERBOSE,$DEBUG);
        }
        elsif ( $RESP == 5 ) {
            set_ruledb_comment($RULEDB,$RDBH,$VERBOSE,$DEBUG);
        }
        elsif ( $RESP == 6 ) {
            set_ruledb_rules_dir($RULEDB,$RDBH,$VERBOSE,$DEBUG);
        }
        elsif ( $RESP == 7 ) {
            show_ruledb_status($RULEDB,$RDBH,$VERBOSE,$DEBUG);
        }
        elsif ( $RESP == 8 ) {
            $RDBH = load_rulefiles_into_db($RULEDB,$RDBH,$VERBOSE,$DEBUG);
        }
        elsif ( $RESP == 9 ) {
            #show_ruledb_summary();
        }
        elsif ( $RESP == 99 ) {
            $run = 1;
            return $RDBH;
        } else {
            print "[*] $RESP is not a valid entery!\n";
        }
    }
}

=head2 set_ruledb_rules_dir

 Sets the dir to load rules from

 Return param : none

=cut

sub set_ruledb_rules_dir {
    my ($RULEDB,$RDBH,$VERBOSE,$DEBUG) = @_;
show_ruledb_rules_dirs($RULEDB,$RDBH,$VERBOSE,$DEBUG);
#    my $RESP = qq();
#
#    print "[*] Please specify the path to load rules from: ";
#    $RESP = <STDIN>;
#    chomp $RESP;
#    #$RESP = qq(/tmp/rules/) if ($RESP eq "");
#    $RDBH->{$RULEDB}->{'RULESDIR'} = $RESP;
#    $RDBH->{$RULEDB}->{'MODIFIED'} = time();
}

# specify dirs to load rules from
# could then have a module for downloading rules and
# extracting them into a dir...

sub show_ruledb_rules_dirs {
    my ($RULEDB,$RDBH,$VERBOSE,$DEBUG) = @_;
    my $count = 0;

    print "\n";
    print " ********* Listing Rule Dirs **********\n";
    print "  item |  RuleDB Dir                     \n";
    my $RDBRDS = $RDBH->{$RULEDB}->{'RULESDIRS'};
    foreach my $RDBRD ( keys %$RDBRDS ) {
        next if $RDBRD eq "";
        $count ++;
        my $RULEDIR = $RDBRDS->{$RDBRD};
        print "    $RDBRD  |  $RULEDIR                 \n";
    }
    print "\n";
    if ( $count == 0) {
        print "[*] No Rule Directories are defined!\n\n";
    }
    print "[*] Enter an item Nr# if you want to edit it.\n" if $count != 0;
    print "[*] Enter \'a\' if you want to add a directory.\n";
    print "[*] Enter \'d <item>\' if you want to delete an item.\n" if $count != 0;
    my $RESP = qq();
    print "Enter item/command: ";
    $RESP = <STDIN>;
    chomp $RESP;
    if ( $RESP =~ /^\d+$/ ) {
        if ( not defined $RDBRDS->{$RESP} ) {
            print "[*] Invalid item nr#, not defined in rulesdirs...\n";
        } else {
            print "[*] Please specify a path to load rules from: ";
            my $PATH = <STDIN>;
            chomp $PATH;
            $RDBH->{$RULEDB}->{'RULESDIRS'}->{$RESP} = $PATH;
            $RDBH->{$RULEDB}->{'MODIFIED'} = time();
        }
    } elsif ( $RESP =~ /^[aA]$/) {
        $count ++;
        while ( defined $RDBRDS->{$count} ) {
            $count ++;
        }
        print "[*] Please specify a path to load rules from: ";
        my $PATH = <STDIN>;
        chomp $PATH;
        $RDBH->{$RULEDB}->{'RULESDIRS'}->{$count} = $PATH;
        $RDBH->{$RULEDB}->{'MODIFIED'} = time();
    } elsif ( $RESP =~ /^[dD] (\d+)$/) {
        my $item = $1;
        if (defined $RDBRDS->{$item}) {
            delete $RDBRDS->{$item};
            $RDBH->{$RULEDB}->{'MODIFIED'} = time();
        } else {
            print "[*] Item $item not found!\n";
        }
    }
}

=head2 set_ruledb_comment

 Adds a comment to the ruledb

 Return param : none

=cut

sub set_ruledb_comment {
    my ($RULEDB,$RDBH,$VERBOSE,$DEBUG) = @_;
    my $RESP = qq();

    print "[*] Please add comment: ";
    $RESP = <STDIN>;
    chomp $RESP;
    $RESP = "No comment added"  if ($RESP eq "");
    $RDBH->{$RULEDB}->{'COMMENT'} = $RESP;
    $RDBH->{$RULEDB}->{'MODIFIED'} = time();
}

=head2 set_ruledb_name

 Changes the name for a ruledb

 Return param : 1 OK / 0 FAIL

=cut

sub set_ruledb_name {
    my ($RDBH,$VERBOSE,$DEBUG) = @_;
    my $RESP = qq();

    while ( $RESP eq "" ) {
        print "[*] Enter RuleDB name: ";
        $RESP = <STDIN>;
        chomp $RESP;
        #$RESP =~ s/ /_/g;
        if ( $RESP eq "" ) {
            print "[E] No name specified! Try again...\n";
        } elsif (defined $RDBH->{$RESP}) {
            print "[E] RuleDB $RESP exists! Try again...\n";
            $RESP = qq();
        }
    }
    if ( not defined $RDBH->{$RESP}) {
        return $RESP;
    }
    print "[E] Should not be here.... exit!\n";
    exit;
}

=head2 change_ruledb_name

 Changes the name of a RuleDB

=cut

sub change_ruledb_name {
    my ($RULEDB,$RDBH,$VERBOSE,$DEBUG) = @_;
    my $RESP = qq();

    while ( $RESP eq "" ) {
        print "[*] Enter RuleDB name: ";
        $RESP = <STDIN>;
        chomp $RESP;
        $RESP =~ s/ /_/g;
        if ( $RESP eq "" ) {
            print "[E] No name specified! Try again...\n";
        }
    }

    if ( $RESP ne $RULEDB && not defined $RDBH->{$RESP} ) {
        $RDBH->{$RESP} = $RDBH->{$RULEDB};
        delete($RDBH->{$RULEDB});
        print "[*] RuleDB name changed from $RULEDB to $RESP\n";
        return $RESP;
    } else {
        print "[*] RuleDB name not changed!\n";
        return $RULEDB;
    }
}

=head2 set_ruledb_engine_type

 Choose engine type for ruledb

 Return param : none

=cut

sub set_ruledb_engine_type {
    my ($RULEDB,$RDBH,$VERBOSE,$DEBUG) = @_;
    my $RESP = qq();

    print "[*] What engine type is it (snort/suricata/other)?: ";
    $RESP = <STDIN>;
    chomp $RESP;
    if ( $RESP =~ /snort/i ) {
        $RDBH->{$RULEDB}->{'ENGINE'} = "snort";
    } elsif ( $RESP =~ /suricata/i ) {
        $RDBH->{$RULEDB}->{'ENGINE'} = "suricata";
    } else {
        $RDBH->{$RULEDB}->{'ENGINE'} = "other";
    }
    $RDBH->{$RULEDB}->{'MODIFIED'} = time();
}

=head2 load_rulefiles_into_db

 Loads all rulefiles from a dir, and updates a RuleDB

=cut

sub load_rulefiles_into_db {
    my ($RULEDB,$RDBH,$VERBOSE,$DEBUG) = @_;
    print "[*] Updating ruledb: $RULEDB\n";

    my $RULESDIRS = $RDBH->{$RULEDB}->{'RULESDIRS'};
    my $NRULEDB = {};
    foreach my $RDBS ( %$RULESDIRS ) {
        next if not $RDBS =~ /\d+/;
        next if not defined $RULESDIRS->{$RDBS};
        my $RULESDIR = $RULESDIRS->{$RDBS};
        $NRULEDB = parse_all_rule_files($RULESDIR,$NRULEDB,$VERBOSE,$DEBUG);
    }
    if (defined $NRULEDB->{1}->{0}) {
        print "[*] Total rules loaded: " . $NRULEDB->{1}->{0}->{'COUNT'} . "\n";
    } else {
        print "[E] Could not load any rules, and thats a no go!\n";
        print "[E] Check your rules path(s)!\n";
        return $RDBH;
    }

    my $CURTIME = time();
    my $UPDATED = 0;
    my $NRDB = $NRULEDB->{1};
    foreach my $rule (sort (keys ( %$NRDB ))) {
        next if not defined $rule;
        next if $rule eq '';
        next if ($rule == 0);
        if ( not defined $RDBH->{$RULEDB}->{1}->{$rule}->{'rev'} ) {
           # New rule
           $UPDATED = 1;
           $RDBH->{$RULEDB}->{1}->{$rule} = $NRULEDB->{1}->{$rule};
           $RDBH->{$RULEDB}->{1}->{$rule}->{'CREATED'}  = $CURTIME;
           $RDBH->{$RULEDB}->{1}->{$rule}->{'MODIFIED'} = $CURTIME;
           print "[*] New sid: " . $NRULEDB->{1}->{$rule}->{'sid'} . "\n"; #if $VERBOSE;
        } elsif ( $RDBH->{$RULEDB}->{1}->{$rule}->{'rev'} < $NRULEDB->{1}->{$rule}->{'rev'} ) {
           # New revision of rule
           $UPDATED = 1;
           $NRULEDB->{1}->{$rule}->{'CREATED'} = $RDBH->{$RULEDB}->{1}->{$rule}->{'CREATED'};
           $RDBH->{$RULEDB}->{1}->{$rule} = $NRULEDB->{1}->{$rule};
           $RDBH->{$RULEDB}->{1}->{$rule}->{'MODIFIED'} = $CURTIME;
           print "[*] Updating sid: " . $NRULEDB->{1}->{$rule}->{'sid'} . "\n"; #if $VERBOSE;
        } elsif ( $RDBH->{$RULEDB}->{1}->{$rule}->{'rev'} == $NRULEDB->{1}->{$rule}->{'rev'} ) {
           # Same rule
           print "[*] Existing sid (same rev): " . $NRULEDB->{1}->{$rule}->{'sid'} . "\n" if ($VERBOSE||$DEBUG);
        } elsif ( $RDBH->{$RULEDB}->{1}->{$rule}->{'rev'} > $NRULEDB->{1}->{$rule}->{'rev'} ) {
           # Old rule
           print "[*] Existing sid (old rev): " . $NRULEDB->{1}->{$rule}->{'sid'} . "\n" if ($VERBOSE||$DEBUG);
        } else {
           print "[E] Error: Should not be here! (Sid:$rule) \n" if ($VERBOSE||$DEBUG);
        }
    }
    if ( $UPDATED == 1 ) {
        $RDBH->{$RULEDB}->{'UPDATED'} = $CURTIME;
        if ( defined $RDBH->{$RULEDB}->{'REVISION'} ) {
            $RDBH->{$RULEDB}->{'REVISION'} ++;
        } else {
            $RDBH->{$RULEDB}->{'REVISION'} = 1;
        }
    }
    return $RDBH;
}

1;
