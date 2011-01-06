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
package Polman::Sensor;
use Exporter;
use Polman::Ruledb qw/choose_ruledb/;
use Polman::Common qw/:all/;
use Polman::Search qw/search_rules_flowbits_isset_isnotset search_rules_flowbits_set/;
use Polman::Parser qw/delete_all_rulefiles/;
use vars qw (@ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);

@ISA = qw (Exporter);

@EXPORT = qw ( is_defined_sensor show_menu_sensor add_sensor
               show_sensor_status edit_sensor choose_sensor
               set_sensor_comment set_sensor_ruledb set_sensor_name
               set_sensor_engine_type 
               update_sensor_rules);

@EXPORT_OK = qw (is_defined_sensor show_menu_sensor add_sensor
               show_sensor_status edit_sensor choose_sensor
               set_sensor_comment set_sensor_ruledb set_sensor_name
               set_sensor_engine_type 
               update_sensor_rules);

%EXPORT_TAGS = (all => [@EXPORT_OK]); # Import :all to get everything.

#my $RULEDB;
#my $SENSOR;
my $COMMENT;
#my $WFILE;
#my $VERBOSE;

=head1 NAME 

 Polman::Sensor - Subs for manipulating Polmans Sensors

=head1 VERSION

 0.1

=head1 DESCRIPTION

 Modules for manipulating Polman Sensors.

=cut

=head1 FUNCTIONS

=head2 is_defined_sensor

 Checks if the sensor exists, and has sain values

=cut
# $SENSH->{$SENSOR}->{'CREATED'} $SENSH->{$SENSOR}->{'MODIFIED'} $SENSH->{$SENSOR}->{'WRITTEN'} $SENSH->{$SENSOR}->{'RULEDB'} $SENSH->{$SENSOR}->{'COMMENT'} $SENSH->{$SENSOR}->{'ENGINE'} $SENSH->{$SENSOR}->{'RULESPATH'} $SENSH->{$SENSOR}->{'REVISION'}
sub is_defined_sensor {
   my ($SENSOR,$SENSH,$RDBH,$VERBOSE,$DEBUG) = @_;
   if (not defined $SENSH ) {
       print "[E] You need to add a sensor first!\n";
       return 0;
   }
   if (not defined $SENSH->{$SENSOR}) {
       print "[E] Sensor $SENSOR does not exist!\n";
       return 0;
   }
   if (not defined $SENSH->{$SENSOR}->{'RULEDB'} ) {
       print "[E] The sensor $SENSOR has a undefined RuleDB\n";
       return 0;
   }
   my $RDBN = $SENSH->{$SENSOR}->{'RULEDB'};
   if (not defined $RDBH->{$RDBN}) {
       print "[E] The sensor $SENSOR has a nonexistant RuleDB: $RDBN\n";
       exit;
   }
   if (not defined $SENSH->{$SENSOR}->{'ENGINE'} ) {
       print "[E] The sensor $SENSOR has a undefined Engine\n";
       return 0;
   }
   if (not defined $SENSH->{$SENSOR}->{'RULESPATH'} ) {
       print "[E] The sensor $SENSOR has a undefined Rulespath\n";
       return 0;
   }
   if (not defined $SENSH->{$SENSOR}->{'CREATED'}) {
       print "[E] The sensor $SENSOR has a undefined creation time\n";
       return 0;
   }
   return 1;
}

=head2 show_menu_sensor

 prints out the sensor edit menu

=cut

sub show_menu_sensor {
    my ($SENSOR,$VERBOSE,$DEBUG)= @_;
    print "\n";
    print " Current Sensor: $SENSOR\n";
    print " ***************  Edit Sensors **************\n";
    print "  Item |  Description                        \n";
    print "    1  |  Choose Sensor to edit              \n";
    print "    2  |  Add Sensor                         \n";
    print "    3  |  Change Sensor Name                 \n";
    print "    4  |  Change Sensor Engine Type          \n";
    print "    5  |  Change Sensor RuleDB               \n";
    print "    6  |  Change Sensor Comment              \n";
    print "    7  |  Show Sensor Status                 \n";
    print "    8  |  Change Sensor rulepath             \n";
    print "    9  |  Write rules to rulepath            \n";
    print "   99  |  Back To Main Menu                  \n";
    print "Enter Item: ";
}

=head2 add_sensor

 Adds a sensor to manage

=cut

sub add_sensor {
    my ($SENSH,$RDBH,$VERBOSE,$DEBUG) =@_;
    my $SENSOR = qq();
    while ($SENSOR eq "") {
        $SENSOR = set_sensor_name($SENSH,$VERBOSE,$DEBUG);
    }
    if ( not defined $SENSH->{$SENSOR} ) {
        print "[*] Creating sensor $SENSOR\n";
        $SENSH->{$SENSOR}->{'CREATED'} = time();
        $SENSH->{$SENSOR}->{'MODIFIED'} = time();
        $SENSH->{$SENSOR}->{'WRITTEN'} = 0;
        $SENSH = set_sensor_comment($SENSOR,$SENSH,$VERBOSE,$DEBUG);
        $SENSH = set_sensor_engine_type($SENSOR,$SENSH,$VERBOSE,$DEBUG);
        $SENSH = set_sensor_ruledb($SENSOR,$SENSH,$RDBH,$VERBOSE,$DEBUG);
        $SENSH = set_sensor_write($SENSOR,$SENSH,$VERBOSE,$DEBUG);
        print "[*] You can now add rules to sensor $SENSOR\n";
        return ($SENSOR,$SENSH);
    } else {
        print "[W] Sensor $SENSOR exists! Switching...\n";
        return ($SENSOR,$SENSH);
    }
}

=head2 show_sensor_status

 Displays status for a sensor

=cut

sub show_sensor_status {
     my ($SENSOR,$SENSH,$RDBH,$VERBOSE,$DEBUG) = @_;

     my $ER = count_enabled_rules($SENSOR,$SENSH,$VERBOSE,$DEBUG);

     print "*------------------------------------------*\n";
     print "[i] Sensor       : $SENSOR\n";
     my $ENGINE = $SENSH->{$SENSOR}->{'ENGINE'};
     print "[i] Engine Type  : $ENGINE\n";
     my $RULEDB = $SENSH->{$SENSOR}->{'RULEDB'};
     print "[i] RuleDB       : $RULEDB\n";
     my $RPATH = $SENSH->{$SENSOR}->{'RULESPATH'};
     # my $DEST = is_dir_or_file($RFILE); # $DEST is "dir " or "file"
     print "[i] Write to path: $RPATH\n";
     my $CT=localtime($SENSH->{$SENSOR}->{'CREATED'});
     my $MT=localtime($SENSH->{$SENSOR}->{'MODIFIED'});
     my $WT=localtime($SENSH->{$SENSOR}->{'WRITTEN'});
     print "[i] Created      : $CT\n";
     print "[i] Last Modified: $MT\n";
     print "[i] Last Written : $WT\n";
     print "[i] Enabled rules: $ER\n";
     my $RDBT = $SENSH->{$SENSOR}->{'RULEDB'};
     if ( $SENSH->{$SENSOR}->{'WRITTEN'} < $RDBH->{$RDBT}->{'UPDATED'} ) {
         print "[i] Needs Update : Yes\n";
     } else {
         print "[i] Needs Update : No\n";
     }
     my $COMMENT = $SENSH->{$SENSOR}->{'COMMENT'};
     print "[i] Comment      : $COMMENT\n";
}

=head2 edit_sensor

 Edit a sensor

=cut

sub edit_sensor {
    my ($SENSH,$RDBH,$VERBOSE,$DEBUG) = @_;
    my $run = 0;
    my $SENSOR = qq();
    my $RESP = qq();

    if (not defined $RDBH) {
        print "[*] No RuleDBs are defined, we need at least one!\n";
        return;
    }

    if (not defined $SENSH) {
        print "[*] No Sensors are defined, we need at least one! Adding...\n";
        ($SENSOR,$SENSH) = add_sensor($SENSH,$RDBH,$VERBOSE,$DEBUG);
    } else {
        $SENSOR = choose_sensor($SENSH,$VERBOSE,$DEBUG);
    }

    while ($run == 0) {
        show_menu_sensor($SENSOR,$VERBOSE,$DEBUG);
        my $RESP = <STDIN>;
        chomp $RESP;
        if ( $RESP eq "") {
            print "[*] Not a valid entery!\n";
        }
        elsif ( $RESP == 1 ) {
            $SENSOR = choose_sensor($SENSH,$VERBOSE,$DEBUG);
        }
        elsif ( $RESP == 2 ) {
            ($SENSOR,$SENSH) = add_sensor($SENSH,$RDBH,$VERBOSE,$DEBUG);
        }
        elsif ( $RESP == 3 ) {
            $SENSOR = change_sensor_name($SENSOR,$SENSH,$VERBOSE,$DEBUG);
        }
        elsif ( $RESP == 4 ) {
            $SENSH = set_sensor_engine_type($SENSOR,$SENSH,$VERBOSE,$DEBUG);
        }
        elsif ( $RESP == 5 ) {
            $SENSH = set_sensor_ruledb($SENSOR,$SENSH,$RDBH,$VERBOSE,$DEBUG);
        }
        elsif ( $RESP == 6 ) {
            $SENSH = set_sensor_comment($SENSOR,$SENSH,$VERBOSE,$DEBUG);
        }
        elsif ( $RESP == 7 ) {
            show_sensor_status($SENSOR,$SENSH,$RDBH,$VERBOSE,$DEBUG);
        }
        elsif ( $RESP == 8 ) {
             $SENSH = set_sensor_write($SENSOR,$SENSH,$VERBOSE,$DEBUG);
        }
        elsif ( $RESP == 9 ) {
             $SENSH = update_sensor_rules($SENSOR,$SENSH,$RDBH,$VERBOSE,$DEBUG);
        }
        elsif ( $RESP == 99 ) {
            $run = 1;
            return $SENSH;
        } else {
            print "[*] $RESP is not a valid entery!\n";
        }
    }
}

=head2 choose_sensor

 Choose sensor to work on

=cut

sub choose_sensor {
    my ($SENSH,$VERBOSE,$DEBUG) = @_;
    my $count = 1;
    my $SENSOR = qq();

    print "\n";
    print " ************* Choose Sensor ************\n";
    print "  item |  Sensor                   \n";
    foreach my $SENS ( keys %$SENSH ) {
        print "    $count  |  $SENS                   \n";
        $count ++;
    }
    my $RESP = qq();
    while ($SENSOR eq "") {
        print "Enter item: ";
        $RESP = <STDIN>;
        chomp $RESP;
        $count = 1;
        if ( $RESP =~ /\d+/ ) {
            foreach my $SENS ( keys %$SENSH ) {
                if ( $RESP == $count ) {
                    $SENSOR = $SENS;
                    return $SENS;
                }
                $count ++;
            }
        }
    }
}

=head2 set_sensor_comment

 Adds a comment to the sensor

=cut

sub set_sensor_comment {
    my ($SENSOR,$SENSH,$VERBOSE,$DEBUG) = @_;
    print "[*] Please add comment: ";
    my $RESP = <STDIN>;
    chomp $RESP;
    $RESP = $COMMENT if ($RESP eq "");
    $SENSH->{$SENSOR}->{'COMMENT'} = $RESP;
    $SENSH->{$SENSOR}->{'MODIFIED'} = time();
    return $SENSH;
}

=head2 set_sensor_ruledb

 Choose which ruledb to associate with the sensor
 This will be the ruledb that all rule are fetched from
 when working on the sensor.

=cut

sub set_sensor_ruledb {
    my ($SENSOR,$SENSH,$RDBH,$VERBOSE,$DEBUG) = @_;

    print "[*] Which Rule DB should this Sensor use: ";
    my $RULEDB = qq();
    while ( $RULEDB eq "" || not defined $RULEDB ) {
        $RULEDB = choose_ruledb($RDBH,$VERBOSE,$DEBUG);
    }
    $SENSH->{$SENSOR}->{'RULEDB'} = $RULEDB;
    $SENSH->{$SENSOR}->{'MODIFIED'} = time();
    return $SENSH;
}

=head2 set_sensor_name

 Set name for sensor

=cut

sub set_sensor_name {
    my ($SENSH,$VERBOSE,$DEBUG) =@_;
    my $SENS = qq();
    while ($SENS eq "") {
        print "[*] Enter Sensor name: ";
        $SENS = <STDIN>;
        chomp $SENS;
        $SENS =~ s/ /_/g;
        if ( not defined $SENSH->{$SENS}) {
            return $SENS;
        } else {
            print "[E] Sensor $SENS exists!\n";
            $SENS = qq();
        }
    }
}

=head2 change_sensor_name

 Changes name for a $SENSOR

=cut

sub change_sensor_name {
    my ($SENSOR,$SENSH,$VERBOSE,$DEBUG) = @_;
    my $RESP = qq();

    while ( $RESP eq "" ) {
        print "[*] Enter sensor name: ";
        $RESP = <STDIN>;
        chomp $RESP;
        $RESP =~ s/ /_/g;
        if ( $RESP eq "" ) {
            print "[E] No name specified! Try again...\n";
        }
    }

    if ( $RESP ne $SENSOR && not defined $SENSH->{$RESP} ) {
        $SENSH->{$RESP} = $SENSH->{$SENSOR};
        delete($SENSH->{$SENSOR});
        print "[*] Sensor name changed from $SENSOR to $RESP\n";
        return $RESP;
    } else {
        print "[*] Sensor name not changed!\n";
        return $SENSOR;
    }
}

=head2 set_sensor_engine_type

 Choose engine type for sensor

=cut

sub set_sensor_engine_type {
    my ($SENSOR,$SENSH,$VERBOSE,$DEBUG) = @_;

    print "[*] What engine type is it (snort/suricata/other)?: ";
    my $RESP = <STDIN>;
    chomp $RESP;
    if ( $RESP =~ /snort/i ) {
        $SENSH->{$SENSOR}->{'ENGINE'} = "snort";
    } elsif ( $RESP =~ /suricata/i ) {
        $SENSH->{$SENSOR}->{'ENGINE'} = "suricata";
    } else {
        $SENSH->{$SENSOR}->{'ENGINE'} = "other";
    }
    $SENSH->{$SENSOR}->{'MODIFIED'} = time();
    return $SENSH;
}

=head2 set_sensor_write

 Sets dir or file to write rule too...

=cut

sub set_sensor_write {
    my ($SENSOR,$SENSH,$VERBOSE,$DEBUG) = @_;

    print "[*] If a dir is specified, rules will be written to multiple files.\n";
    print "[*] Enter file or dir to write rule to: ";
    my $PATH = <STDIN>;
    chomp $PATH;
    #$PATH =~ s/ /_/g;
    $SENSH->{$SENSOR}->{'RULESPATH'} = $PATH;
    $SENSH->{$SENSOR}->{'MODIFIED'} = time();
    return $SENSH;
}

=head2 update_sensor_rules

 Makes a new rulefile(s) for $sensor with enabled/disabled rules.

=cut

sub update_sensor_rules {
    my ($SENSOR,$SENSH,$RDBH,$VERBOSE,$DEBUG) = @_;

    if ( not defined $SENSH->{$SENSOR}) {
        print "[E] Sensor $SENSOR does not exist!!!\n";
        return $SENSH;
    }

    my $RULEDB = $SENSH->{$SENSOR}->{'RULEDB'};
    if (defined $SENSH->{$SENSOR}) {
        # Sensor exists
        print "[*] Sensor                    : $SENSOR\n";
        print "[*] Sensor created            : " . localtime($SENSH->{$SENSOR}->{'CREATED'})  . "\n";
        print "[*] Sensor last modified      : " . localtime($SENSH->{$SENSOR}->{'MODIFIED'}) . "\n";
        if (not defined $SENSH->{$SENSOR}->{'WRITTEN'}) {
            $SENSH->{$SENSOR}->{'WRITTEN'} = 0;
        }
        print "[*] Rules last written        : " . localtime($SENSH->{$SENSOR}->{'WRITTEN'}) . "\n";
        print "[*] RuleDB revision nr.       : " . $RDBH->{$RULEDB}->{'REVISION'} . "\n";
        print "[*] Writing rules to path     : " . $SENSH->{$SENSOR}->{'RULESPATH'} . "\n";
    } else {
        print "[E] Could read sensor rc\n";
        return $SENSH;
    }

    my $totrules = $RDBH->{$RULEDB}->{1};
    my $count = count_hash($totrules);
    if ($count <= 0) {
        print "[W] No rules loaded in RuleDB: $RULEDB\n";
        return $SENSH;
    }
   
    # if ruledb has been updated, add new sigs to sensor in its default state.
    print "[*] Checking for new rules in ruledb...\n";
    $SENSH = check_for_new_ruledb_sids($SENSOR,$SENSH,$RDBH,$RULEDB,"current",$VERBOSE,$DEBUG);

    if (defined $SENSH->{$SENSOR}->{1}->{'RULES'}) {
        print "[*] Processing gid 1 rules...\n";
    } else {
        print "[W] No gid 1 rules defined for sensor $SENSOR\n";
        return $SENSH;
    }

    # Check flowbits
    print "[*] Searching for flowbit dependencies...\n";
    my $flowsids = {};
    # I see a potential problem here:
    # Example, sid 2002924 sets a flowbit, but it also depends on flowbits
    # so we might be in a situation that we search_rules_flowbits_isset_isnotset
    # finds a flowbit dependencies, enables 2002924, but do not enable the
    # rules that 2002924 depends on etc. Next time you run update, they will
    # be enabled, but thats not good enough... This could be recursive also...
    # A while loop might do the trick, but leaving it for now as it is...
    my $FLOWBITS = search_rules_flowbits_isset_isnotset($SENSOR,$SENSH,$RULEDB,$RDBH,$VERBOSE,$DEBUG);
    print "[*] Searching for needed flowbit rules...\n";
    $flowsids = search_rules_flowbits_set($SENSOR,$SENSH,$RULEDB,$RDBH,$FLOWBITS,$VERBOSE,$DEBUG);
    print "[*] Enabling dependent flowbit rules...\n";
    foreach my $fsid (keys %$flowsids) {
        next if not defined $fsid;
        # Could also pass $fsids as a string "1234,4567,7890"
        $SENSH = sensor_enable_sid($fsid,$SENSOR,$SENSH,$RDBH,$RULEDB,"current",$VERBOSE,$DEBUG);
    }
    # A hack would be to run it twice! Uncomment the next lines if you want to :)
    #$FLOWBITS = search_rules_flowbits_isset_isnotset($SENSOR,$SENSH,$RULEDB,$RDBH,$DEBUG,$DEBUG);
    #$flowsids = search_rules_flowbits_set($SENSOR,$SENSH,$RULEDB,$RDBH,$FLOWBITS,$DEBUG,$DEBUG);
    #foreach my $fsid (keys %$flowsids) {
    #    next if not defined $fsid;
    #    $SENSH = sensor_enable_sid($fsid,$SENSOR,$SENSH,$RDBH,$RULEDB,"current",$DEBUG,$DEBUG);
    #}
    my $SENSORRULES = $SENSH->{$SENSOR}->{1}->{'RULES'};
   
    exit if not defined $SENSH->{$SENSOR}->{'RULEDB'}; 
    my $WFILE = $SENSH->{$SENSOR}->{'RULESPATH'};
    if ( -d $WFILE ) {
        # We have a directory
        # Move old files too "trash"
        delete_all_rulefiles($WFILE);
        # split up rules into different files.
        # split rules into $hash->$catagory->$sid
        print "[*] Writing rulefiles too directory: $WFILE\n";
        my $CAT = {};
        foreach my $sid (keys %$SENSORRULES) {
           if ( defined $RDBH->{$RULEDB}->{1}->{$sid} ) {
                next if not defined $SENSH->{$SENSOR}->{1}->{'RULES'}->{$sid}->{'enabled'};
                next if $SENSH->{$SENSOR}->{1}->{'RULES'}->{$sid}->{'enabled'} == 0;
                my $catagory = $RDBH->{$RULEDB}->{1}->{$sid}->{'rulegroup'};
                $CAT->{$catagory}->{$sid} = 1;
           } else {
                print "[E] Sensor has sid $sid, but its lacking from main rule DB :(\n" if ($VERBOSE||$DEBUG);
           }
        }
        # write out foreach $sid in $catagory to $WFILE/$catagory
        foreach my $rg (keys %$CAT) {
            my $sids = $CAT->{$rg};
            print "[*] Writing gid 1 rules to $WFILE/$rg.rules file.\n";
            open (RULEFILE, ">$WFILE/$rg.rules");
            foreach my $sid (keys %$sids) {
                my $rule = get_rule($SENSOR,$SENSH,$RULEDB,$RDBH,$sid,$VERBOSE,$DEBUG);
                print RULEFILE "$rule\n";
            }
            close (RULEFILE);
        }
    } else {
        # Must be a file then :)
        print "[*] Writing to rulefile: $WFILE\n";
        open (RULEFILE, ">$WFILE");
        foreach my $sid (keys %$SENSORRULES) {
            if ( defined $RDBH->{$RULEDB}->{1}->{$sid} ) {
                next if not defined $SENSH->{$SENSOR}->{1}->{'RULES'}->{$sid};
                next if not defined $SENSH->{$SENSOR}->{1}->{'RULES'}->{$sid}->{'enabled'};
                next if $SENSH->{$SENSOR}->{1}->{'RULES'}->{$sid}->{'enabled'} == 0;
                print "[*] Writing sid:$sid with gid 1 to rules file.\n" if ($VERBOSE||$DEBUG);
                my $rule = get_rule($SENSOR,$SENSH,$RULEDB,$RDBH,$sid,$VERBOSE,$DEBUG);
                print RULEFILE "$rule\n";
            } else {
                print "[E] Sensors has sid $sid, but its lacking from main rule DB :(\n" if ($VERBOSE||$DEBUG);
            }
        }
        close (RULEFILE);
    }
    # Update time and revision
    $SENSH->{$SENSOR}->{'WRITTEN'} = time();
    $SENSH->{$SENSOR}->{'REVISION'} = $RDBH->{$RULEDB}->{'REVISION'};
    print "[*] Done updating rules for sensor $SENSOR\n";
    return $SENSH;
}

1;
