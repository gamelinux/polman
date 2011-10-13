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
package Polman::FetchRules;
use Exporter;
use File::Path;
use vars qw (@ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);

@ISA = qw (Exporter);

@EXPORT = qw ( );

@EXPORT_OK = qw ( );

%EXPORT_TAGS = (all => [@EXPORT_OK]); # Import :all to get everything.

=head1 NAME 

 Polman::FetchRules - Subs for fetching rule files from the intertubes...

=head1 VERSION

 0.1

=head1 DESCRIPTION

 Modules for fetching rule files with http/https.

=cut

=head1 FUNCTIONS

=head2 show_menu_sourcedb

 Prints out the sourcedb edit menu to stdout

=cut

sub show_menu_sourcedb {
    my ($RS,$VERBOSE,$DEBUG) = @_;
    print "\n";
    print " Rules Source: $RS\n" if defined $RS;
    print " ************* Edit Rule Sources ************\n";
    print "  Item |  Description                        \n";
    print "    1  |  Choose Rule Source to edit         \n";
    print "    2  |  Add Rule Source                    \n";
    print "    3  |  Change Rule Source Name            \n";
    print "    4  |  Change Rule Source Engine Type     \n";
    print "    5  |  Change Rule Source Comment         \n";
    print "    6  |  Change Rule Source Output Dir      \n";
    print "    7  |  Show Rule Source Status            \n";
    print "    8  |  Fetch Rule Source                  \n";
    print "   99  |  Back To Main Menu                  \n";
    print "Enter Item: ";
}


=head2 somehting

=cut

sub edit_rulesource {
    my ($SH,$VERBOSE,$DEBUG) = @_;

}

# VRT
# https://www.snort.org/reg-rules/$rule_file.md5/$oinkcode
# http://www.snort.org/reg-rules/snortrules-snapshot-2900.tar.gz/b8166168ebc47ae0d73a46dd24f5bb28557462e0
# http://www.snort.org/downloads/595/show_md5

# ET
# http://rules.emergingthreats.net/open/snort-2.9.0/emerging.rules.tar.gz
# http://rules.emergingthreats.net/open/snort-2.9.0/emerging.rules.tar.gz.md5

# ET-PRO
# ?

sub fetch_rules_if_new {
    my ($RULEDB,$RHDB,$VERBOSE,$DEBUG) = @_;
    my $URL = $RDBH->{$RULEDB}->{'URL'};
    my $URL5L = $RDBH->{$RULEDB}->{'URLMD5LAST'};
    my $URL5C = qq();



}

sub getstore {
    my ( $url, $file ) = @_;
    my $request = HTTP::Request->new( GET => $url );
    my $response = $ua->request( $request, $file );
    $response->code;
}

sub md5sum {
    my ( $rule_file, $temp_path ) = @_;
    open( MD5FILE, "$temp_path$rule_file" )
      or croak $!;
    binmode(MD5FILE);
    $rule_digest = Digest::MD5->new->addfile(*MD5FILE)->hexdigest;
    close(MD5FILE);
    if ($@) {
        print $@;
        return "";
    }
    if ($Verbose && !$Quiet) {
        print "\tcurrent local rules file  digest: $rule_digest\n";
    }
    return $rule_digest;
}

sub rule_extract {
    my ( $rule_file, $temp_path, $Distro, $arch, $Snort, $Sorules, $ignore, $docs ) =
      @_;
    print "Prepping rules from $rule_file for work....\n" if !$Quiet;
    print "\textracting contents of $temp_path$rule_file...\n" if ($Verbose && !$Quiet);
    mkpath( $temp_path . "tha_rules" );
    mkpath( $temp_path . "tha_rules/so_rules" );
    my $tar = Archive::Tar->new();
    $tar->read( $temp_path . $rule_file );
    my @ignores = split( /,/, $ignore );

    foreach (@ignores) {
        print "\tIgnoring: $_.rules from the tarball\n" if ($Verbose && !$Quiet);
        $tar->remove("rules/$_.rules");
        $tar->remove("preproc_rules/$_.rules");
    }
    my @files = $tar->get_files();
    foreach (@files) {
        my $filename   = $_->name;
        my $singlefile = $filename;
        if ( $filename =~ /^rules\/.*\.rules$/ ) {
            $singlefile =~ s/^rules\///;
            $tar->extract_file( $filename,
                $temp_path . "/tha_rules/" . $singlefile );
            print "\tExtracted: /tha_rules/$singlefile\n" if ($Verbose && !$Quiet);
        }
        elsif ( $filename =~ /^preproc_rules\/.*\.rules$/ ) {
            $singlefile =~ s/^preproc_rules\///;
            $tar->extract_file( $filename,
                $temp_path . "/tha_rules/" . $singlefile );
            print "\tExtracted: /tha_rules/$singlefile\n" if ($Verbose && !$Quiet);
        }
        elsif ($Sorules
            && $filename =~
            /^so_rules\/precompiled\/($Distro)\/($arch)\/($Snort)\/.*\.so/
            && -d $Sorules )
        {
            $singlefile =~
              s/^so_rules\/precompiled\/($Distro)\/($arch)\/($Snort)\///;
            $tar->extract_file( $filename, $Sorules . $singlefile );
            print "\tExtracted: $Sorules$singlefile\n" if ($Verbose && !$ Quiet);
        }
        elsif ($docs
            && $filename =~ /^doc\/signatures\/.*\.txt/ && -d $docs )
        {
            $singlefile =~
              s/^doc\/signatures\///;
            $tar->extract_file( $filename, $docs . $singlefile );
            print "\tExtracted: $docs$singlefile\n" if ($Verbose == 2 && !$Quiet);
        }
    }
    print "\tDone!\n" if (!$Verbose && !$Quiet);
}
1;
