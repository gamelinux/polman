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
package Polman::Parser;
use Exporter;
use File::Path;
use vars qw (@ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);

@ISA = qw (Exporter);

@EXPORT = qw ( parse_all_rule_files delete_all_rulefiles );

@EXPORT_OK = qw ( parse_all_rule_files delete_all_rulefiles );

%EXPORT_TAGS = (all => [@EXPORT_OK]); # Import :all to get everything.

my $RULEDB;
my $SENSOR;
my $RULESDIR;
my $NRULEDB;
my $DEBUG;

=head1 NAME 

 Polman::Parser - Subs for manipulating rule files

=head1 VERSION

 0.1

=head1 DESCRIPTION

 Modules for manipulating rule files.

=cut

=head1 FUNCTIONS

=head2 parse_all_rule_files

 Opens all the rule files, parses them, and stors rules in a hash

=cut

sub parse_all_rule_files {
    my ($RULESDIR,$VERBOSE) = @_;
    my @FILES;
    my $NRULEDB = {};

    #if (not defined $RULESDIR) {
    #   $SENS::SENSORS->{$SENSOR}
    #}

    # Open the directory
    print "[*] Looking for rulefiles in $RULESDIR\n";
    if( opendir( DIR, "$RULESDIR/" ) ) {
       # Find rule files in dir (*.rules)
       while( my $FILE = readdir( DIR ) ) {
          next if( ( "." eq $FILE ) || ( ".." eq $FILE ) );
          next unless ($FILE =~ /.*\.rules$/);
          push( @FILES, $FILE ) if( -f "$RULESDIR$FILE" );
       }
       closedir( DIR );
    } else {
        warn "[!] Error opening dir: $RULESDIR";
        return;
        #exit 1;
    }
    foreach my $FILE ( @FILES ) {
       $NRULEDB = get_rules ("$RULESDIR/$FILE",$NRULEDB,$VERBOSE);
       if ( $NRULEDB->{1}->{0}->{'OK'} == 0 ) {
          warn "[*] Couldn't parse $RULESDIR$FILE: $!\n";
       }
    }
    return $NRULEDB;
}

=head2 delete_all_rulefiles

 Moves all rulesfiles from a dir into dir/old/

=cut

sub delete_all_rulefiles {
    my ($RULESDIR,$VERBOSE) = @_;
    my @FILES;
    # Open the directory
    if( opendir( DIR, "$RULESDIR/" ) ) {
       # Find rule files in dir (*.rules)
       while( my $FILE = readdir( DIR ) ) {
          next if( ( "." eq $FILE ) || ( ".." eq $FILE ) );
          next unless ($FILE =~ /.*\.rules$/);
          push( @FILES, $FILE ) if( -f "$RULESDIR$FILE" );
       }
       closedir( DIR );
    } else {
        warn "[E] Error opening dir: $RULESDIR";
        #return;
        exit;
    }
    my $timenow = time;
    my $trashdir = "$RULESDIR/old/$timenow/";
    mkpath( $trashdir );
    print "[*] Moving old rulefiles in $RULESDIR too $trashdir\n";
    foreach my $FILE ( @FILES ) {
       print "Moving $RULESDIR/$FILE too $trashdir\n" if $DEBUG;
       my $RET = rename ("$RULESDIR/$FILE","$trashdir/$FILE");
       if ($RET != 1) {
           print "[E] Could not move $RULESDIR/$FILE too $trashdir\n";
       }
    }
}

=head2 get_rules

 This sub extracts the rules from a rules file.
 Takes $file as input parameter.

=cut

sub get_rules {
    my ($RFILE,$NRULEDB,$VERBOSE) = @_;
    $NRULEDB->{1}->{0}->{'OK'} = 0;

    if (open (FILE, $RFILE)) {
        my ($rulegroup) = ($RFILE =~ /\/([-\w]+)\.rules$/);
        print "Found rules file: ".$RFILE."\n" if ($DEBUG || $VERBOSE);
        # Verify the data in the session files
        LINE:
        while (my $rule = readline FILE) {
            chomp $rule;
            #$rule =~ s/\#.*//;
            next LINE unless($rule); # empty line
            next LINE if ($rule =~ /^\#$/);
            next LINE if not ( $rule =~ /^\#? ?(drop|alert|log|pass|activate|dynamic)\s+(\S+?)\s+(\S+?)\s+(\S+?)\s+(\S+?)\s+(\S+?)\s+(\S+?)\s+\((.*)\)$/);
            my ($action, $proto, $sip, $sport, $dir, $dip, $dport, $options) = ($1, $2, $3, $4, $5, $6, $7, $8);

            #$rule =~ /^\#? ?(drop|alert|log|pass|activate|dynamic)\s+(\S+?)\s+(\S+?)\s+(\S+?)\s+(\S+?)\s+(\S+?)\s+(\S+?)\s+\((.*)\)$/;
            #my ($action, $proto, $sip, $sport, $dir, $dip, $dport, $options) = ($1, $2, $3, $4, $5, $6, $7, $8);

            unless($rule) {
                warn "[*] Error: Not a valid rule in: '$RFILE'" if $DEBUG;
                warn "[*] RULE: $rule" if $DEBUG;
                next LINE;
            }

            if (not defined $options) {
                warn "[*] Error: Options missing in rule: '$RFILE'" if $DEBUG;
                warn "[*] RULE: $rule" if $DEBUG;
                next LINE;
            }

            # ET rules has: "sid: 2003451;"
            unless( $options =~ /sid:\s*([0-9]+)\s*;/ ) {
                warn "[*] Error: No sid found in rule options: '$RFILE'" if $DEBUG;
                warn "[*] RULE: $options" if $DEBUG;
                next LINE;
            }
            my $sid = $1;

            $options =~ /msg:\s*\"(.*?)\"\s*;/;
            my $msg = $1;

            $options =~ /rev:\s*(\d+?)\s*;/;
            my $rev = $1;

            my $enabled = 0;
            # This also removes comments in rules (making them active)
            if ( $rule =~ s/^# ?//g ) {
               $enabled = 0;
            } else {
                $enabled = 1;
            }
            # Things should be "OK" now to send to the hash-DB
            #push (@{$RULEDB{$sid}}, [ $rule ]);
            $NRULEDB->{1}->{$sid}->{'sid'}       = $sid;
            #$NRULEDB->{1}->{$sid}->{'rule'}      = $rule;
            $NRULEDB->{1}->{$sid}->{'rulegroup'} = $rulegroup;
            $NRULEDB->{1}->{$sid}->{'enabled'}   = $enabled;
            $NRULEDB->{1}->{$sid}->{'action'}    = $action;
            $NRULEDB->{1}->{$sid}->{'protocol'}  = $proto;
            $NRULEDB->{1}->{$sid}->{'src_ip'}    = $sip;
            $NRULEDB->{1}->{$sid}->{'src_port'}  = $sport;
            $NRULEDB->{1}->{$sid}->{'direction'} = $dir;
            $NRULEDB->{1}->{$sid}->{'dst_ip'}    = $dip;
            $NRULEDB->{1}->{$sid}->{'dst_port'}  = $dport;
            $NRULEDB->{1}->{$sid}->{'name'}      = $msg;
            $NRULEDB->{1}->{$sid}->{'options'}   = $options;
            $NRULEDB->{1}->{$sid}->{'rev'}       = $rev;
#            warn "parsed sid:$sid - $options";
            # Update the OK mark:
            $NRULEDB->{1}->{0}->{'OK'} = 1;
            $NRULEDB->{1}->{0}->{'COUNT'} ++;

        }
      close FILE;
    }
    return $NRULEDB;
}

1;
