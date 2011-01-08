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
package Polman::Common;
use Exporter;
use vars qw (@ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);

@ISA = qw (Exporter);

@EXPORT = qw (check_for_new_ruledb_sids sensor_enable_sid sensor_disable_sid 
              count_enabled_rules get_rule get_sid_msg_map count_hash);

@EXPORT_OK = qw (check_for_new_ruledb_sids sensor_enable_sid sensor_disable_sid 
                 count_enabled_rules get_rule get_sid_msg_map count_hash);

%EXPORT_TAGS = (all => [@EXPORT_OK]); # Import :all to get everything.

=head1 NAME 

 Polman::Common - Common subs for Polman

=head1 VERSION

 0.1

=head1 DESCRIPTION

 Common generic modules for Polman

=cut

=head1 FUNCTIONS

=head2 check_for_new_ruledb_sids

 Compares rules in ruledb to rules in sensor, and enabled
 new rules in its default state, defined by vendor.

=cut

sub check_for_new_ruledb_sids {
    my ($SENSOR,$SENSH,$RDBH,$RULEDB,$ACTION,$VERBOSE,$DEBUG) = @_;
    my $rules = $RDBH->{$RULEDB}->{1};
    my $COMMENT = "Rule auto enabled";

    foreach my $sid (keys %$rules) {
        if ( not defined $SENSH->{$SENSOR}->{1}->{'RULES'}->{$sid} ) {
            my $action = $RDBH->{$RULEDB}->{1}->{$sid}->{'action'};
            if ( $RDBH->{$RULEDB}->{1}->{$sid}->{'enabled'} == 1) {
                print "[*] Auto enabling new sid $sid [$action] (" . $RDBH->{$RULEDB}->{1}->{$sid}->{'name'} . ")\n" if ($VERBOSE||$DEBUG);
                $SENSH->{$SENSOR}->{1}->{'RULES'}->{$sid}->{'enabled'} = 1;
            } else {
                print "[*] Auto disabling new sid $sid [$action] (" . $RDBH->{$RULEDB}->{1}->{$sid}->{'name'} . ")\n" if ($VERBOSE||$DEBUG);
                $SENSH->{$SENSOR}->{1}->{'RULES'}->{$sid}->{'enabled'} = 0;
            }
            $SENSH->{$SENSOR}->{1}->{'RULES'}->{$sid}->{'ADDED'} = time();
            $SENSH->{$SENSOR}->{1}->{'RULES'}->{$sid}->{'MODIFIED'} = time();
            $SENSH->{$SENSOR}->{1}->{'RULES'}->{$sid}->{'COMMENT'} = $COMMENT;
            $SENSH->{$SENSOR}->{1}->{'RULES'}->{$sid}->{'action'} = $action;
        } # else is a "old" rule
    }
    return $SENSH;
}

=head2 sensor_enable_sid

 Enables a $sid for $sensor

=cut

sub sensor_enable_sid {
    my ($SID,$SENSOR,$SENSH,$RDBH,$RULEDB,$ACTION,$VERBOSE,$DEBUG) = @_;

    $ACTION = "current" if not defined $ACTION;
    my $COMMENT = "Rule enabled: $ACTION";
    my $SIDS = [];

    # Handles multiple sids: -e 1234,5678,9012,...
    if ($SID =~ /,/) {
        @$SIDS = split(/,/, $SID);
    } else {
        push (@$SIDS, $SID);
    }

    foreach my $sid (@$SIDS) {
        next if not defined $sid;
        next if not ($sid =~ /^\d+$/);
    
        if (defined $RDBH->{$RULEDB}->{1}->{$sid}) {
            if (not defined $SENSH->{$SENSOR}->{1}->{'RULES'}->{$sid}->{'ADDED'}) {
                $SENSH->{$SENSOR}->{1}->{'RULES'}->{$sid}->{'ADDED'} = time();
            }
            if (not defined $SENSH->{$SENSOR}->{1}->{'RULES'}->{$sid}->{'action'}) {
                # Adding it for the first time, so there is no "current" and it should be the same as "default"
                if ( $ACTION eq "default" || $ACTION eq "current") {
                    $SENSH->{$SENSOR}->{1}->{'RULES'}->{$sid}->{'action'} = $RDBH->{$RULEDB}->{1}->{$sid}->{'action'};
                } else {
                    $SENSH->{$SENSOR}->{1}->{'RULES'}->{$sid}->{'action'} = $ACTION;
                }
            } else {
                # The rule exists
                if ( $ACTION eq "default" ) {
                    # Revert to default value from RULEDB
                    $SENSH->{$SENSOR}->{1}->{'RULES'}->{$sid}->{'action'} = $RDBH->{$RULEDB}->{1}->{$sid}->{'action'};
                } elsif ( $ACTION eq "current" ) {
                    # Keep current state (do nothing)
                } else {
                    $SENSH->{$SENSOR}->{1}->{'RULES'}->{$sid}->{'action'} = $ACTION;
                }
            }
    
            my $action = $SENSH->{$SENSOR}->{1}->{'RULES'}->{$sid}->{'action'};
            if (defined $SENSH->{$SENSOR}->{1}->{'RULES'}->{$sid}->{'enabled'} &&
                      $SENSH->{$SENSOR}->{1}->{'RULES'}->{$sid}->{'enabled'} == 1) {
                # Allready enabled
                print "[*] Already enabled sid $sid [$action] (" . $RDBH->{$RULEDB}->{1}->{$sid}->{'name'} . ")\n" if ($VERBOSE||$DEBUG);
            } else {
                $SENSH->{$SENSOR}->{1}->{'RULES'}->{$sid}->{'enabled'} = 1;
                $SENSH->{$SENSOR}->{1}->{'RULES'}->{$sid}->{'MODIFIED'} = time();
                $SENSH->{$SENSOR}->{1}->{'RULES'}->{$sid}->{'COMMENT'} = $COMMENT;
                $SENSH->{$SENSOR}->{'MODIFIED'} = time();
                print "[*] Enabling sid $sid [$action] (" . $RDBH->{$RULEDB}->{1}->{$sid}->{'name'} . ")\n" if ($VERBOSE||$DEBUG);
            }
        } else {
            print "[W] Sid $sid is not found in main rule DB, skipping!\n" if $DEBUG; # could add, as it does not matter...
        }
    }
    return $SENSH;
}

=head2 sensor_disable_sid

 Disables a $sid for $sensor

=cut

sub sensor_disable_sid {
    my ($SID,$SENSOR,$SENSH,$RDBH,$RULEDB,$VERBOSE,$DEBUG) = @_;
    my $COMMENT = "Rule disabled";
    my $SIDS = [];
 
    if (not defined $RDBH ||
        not defined $RDBH->{$RULEDB} ) {
        print "[E] RuleDB problems...\n" if $DEBUG;
        return $SENSH;
    }

    # Handles multiple sids: -d 1234,5678,9012,...
    if ($SID =~ /,/) {
        @$SIDS = split(/,/, $SID);
    } else {
        push (@$SIDS, $SID);
    }

    foreach my $sid (@$SIDS) {
        next if not defined $sid;
        next if not ($sid =~ /^\d+$/);
        next if not defined not defined $RDBH->{$RULEDB}->{1}->{$sid};
        # need to go over this with a clear head.....
        if (defined $SENSH->{$SENSOR}->{1}->{'RULES'}->{$sid}) {
            my $action = $SENSH->{$SENSOR}->{1}->{'RULES'}->{$sid}->{'action'};
            if (not defined $SENSH->{$SENSOR}->{1}->{'RULES'}->{$sid}->{'enabled'}) {
                $SENSH->{$SENSOR}->{1}->{'RULES'}->{$sid}->{'enabled'} = 0;
                $action = $RDBH->{$RULEDB}->{1}->{$sid}->{'action'};
                print "[*] Already disabled sid $sid [$action] (" . $RDBH->{$RULEDB}->{1}->{$sid}->{'name'} . ")\n" if ($VERBOSE||$DEBUG);
            } elsif ($SENSH->{$SENSOR}->{1}->{'RULES'}->{$sid}->{'enabled'} == 1) {
                $SENSH->{$SENSOR}->{1}->{'RULES'}->{$sid}->{'enabled'} = 0;
                $SENSH->{$SENSOR}->{'MODIFIED'} = time();
                $SENSH->{$SENSOR}->{1}->{'RULES'}->{$sid}->{'COMMENT'} = $COMMENT;
                print "[*] Disabling sid $sid [$action] (" . $RDBH->{$RULEDB}->{1}->{$sid}->{'name'} . ")\n" if ($VERBOSE||$DEBUG);
            } elsif ($SENSH->{$SENSOR}->{1}->{'RULES'}->{$sid}->{'enabled'} == 0) {
                # Allready disabled
                print "[*] Already disabled sid $sid [$action] (" . $RDBH->{$RULEDB}->{1}->{$sid}->{'name'} . ")\n" if ($VERBOSE||$DEBUG);
            } else {
                $SENSH->{$SENSOR}->{1}->{'RULES'}->{$sid}->{'enabled'} = 0;
                $action = $RDBH->{$RULEDB}->{1}->{$sid}->{'action'};
                print "[*] Already disabled sid $sid [$action] (" . $RDBH->{$RULEDB}->{1}->{$sid}->{'name'} . ")\n" if ($VERBOSE||$DEBUG);
            }
        } else {
            $SENSH->{$SENSOR}->{1}->{'RULES'}->{$sid}->{'ADDED'} = time();
            $SENSH->{$SENSOR}->{1}->{'RULES'}->{$sid}->{'MODIFIED'} = time();
            $SENSH->{$SENSOR}->{1}->{'RULES'}->{$sid}->{'enabled'} = 0;
            $SENSH->{$SENSOR}->{1}->{'RULES'}->{$sid}->{'COMMENT'} = $COMMENT;
            $SENSH->{$SENSOR}->{1}->{'RULES'}->{$sid}->{'action'} = $RDBH->{$RULEDB}->{1}->{$sid}->{'action'};
            my $action = $SENSH->{$SENSOR}->{1}->{'RULES'}->{$sid}->{'action'};
            print "[*] Already disabled sid $sid [$action] (" . $RDBH->{$RULEDB}->{1}->{$sid}->{'name'} . ")\n" if ($VERBOSE||$DEBUG);
        }
    }
    return $SENSH;
}

=head2 get_rule

 Give it a $sid, $SENSOR and a $RULEDB,
 and it will return you your rule in its current state
 defined for the $SENSOR.

=cut

sub get_rule {
    my ($SENSOR,$SENSH,$RULEDB,$RDBH,$sid,$VERBOSE,$DEBUG) = @_;
    #my ($sid,$RULEDB,$SENSOR) = @_;
    my $rule = qq(ERROR);

    if (not defined $RULEDB) {
        $RULEDB = $SENSH->{$SENSOR}->{'RULEDB'};
    }
    return $rule if not defined $RDBH->{$RULEDB};
    return $rule if not defined $RDBH->{$RULEDB}->{1}->{$sid};

    if ( defined $SENSH->{$SENSOR}->{1}->{'RULES'}->{$sid}->{'action'} ) {
        if ( $SENSH->{$SENSOR}->{1}->{'RULES'}->{$sid}->{'action'} eq "" ) {
            # If not specified, use default (hardcoded to alert for now)
            $SENSH->{$SENSOR}->{1}->{'RULES'}->{$sid}->{'action'} = "alert";
        }
        $rule = "$SENSH->{$SENSOR}->{1}->{'RULES'}->{$sid}->{'action'}";
    } else {
        $rule = "$RDBH->{$RULEDB}->{1}->{$sid}->{'action'}";
    }

    $rule = "$rule $RDBH->{$RULEDB}->{1}->{$sid}->{'protocol'} "
          . "$RDBH->{$RULEDB}->{1}->{$sid}->{'src_ip'} $RDBH->{$RULEDB}->{1}->{$sid}->{'src_port'} "
          . "$RDBH->{$RULEDB}->{1}->{$sid}->{'direction'} "
          . "$RDBH->{$RULEDB}->{1}->{$sid}->{'dst_ip'} $RDBH->{$RULEDB}->{1}->{$sid}->{'dst_port'} "
          . "($RDBH->{$RULEDB}->{1}->{$sid}->{'options'})";

    print "RAW RULE:\n$rule\n" if $DEBUG;
    return $rule;
}

=head2 get_sid_msg_map

 Give it a $sid, $SENSOR and a $RULEDB,
 and it will return you the sid-gen.map entery for 

=cut

sub get_sid_msg_map {
    my ($RULEDB,$RDBH,$sid,$VERBOSE,$DEBUG) = @_;
    my $smm = qq(ERROR);

    return $smm if not defined $RDBH->{$RULEDB};
    return $smm if not defined $RDBH->{$RULEDB}->{1}->{$sid};

    if ( defined $RDBH->{$RULEDB}->{1}->{$sid}->{'name'} ) {
        my $msg = $RDBH->{$RULEDB}->{1}->{$sid}->{'name'};
        $smm = "$sid || $msg"
    } else {
        return $smm;
    }

    my $opt = $RDBH->{$RULEDB}->{1}->{$sid}->{'options'};
    my @OPTS = split( /;(\t|\s)?/, $opt ) if $opt;
    foreach my $OPT ( reverse (@OPTS) ) {
         my ( $key, $arg ) = split( /:/, $OPT ) if $OPT;
         if ( defined $key && defined $arg ) {
             if ( $key =~ /reference/ ) {
                 $smm = "$smm || $arg";
             }
         }
    }
    #while ( $SENSH->{$SENSOR}->{1}->{'RULES'}->{$sid}->{'options'} =~ /reference:\s?([\S.]*)\s?;/g ) {
    #    $smm = "$smm || $1"
    #}
    print "$smm\n" if ($DEBUG && $VERBOSE); # Yes both...
    return $smm
}

=head2 count_enabled_rules

 Counts rules that are enabled on a sensor

=cut

sub count_enabled_rules {
    my ($SENSOR,$SENSH,$VERBOSE,$DEBUG) = @_;
    my $rules = $SENSH->{$SENSOR}->{1}->{'RULES'};
    my $count = 0;
    foreach (keys %$rules) {
        $count ++;
    }
    return $count;
}

=head2 count_hash

 Counts elements in a hash

=cut

sub count_hash {
    my $hash  = shift;
    return 0 if not defined $hash;
    my $count = 0;
    foreach (keys %$hash) {
        $count ++;
    }
    return $count;
}

1;
