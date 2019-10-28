#!/usr/bin/env perl

use Modern::Perl;

use AnyEvent;
use AnyEvent::Socket;
use AnyEvent::Handle;

use Digest::SHA qw(sha256);
use Crypt::CTR;
use Crypt::OpenSSL::AES;

my $cv = AE::cv;

my $host = '127.0.0.1';
my $port = 1443;
my %connections;

my $secret_hex = $ARGV[0];

my $secret = pack("H*", $secret_hex);
die "Bad secret" unless length($secret) == 16;

say "tg://proxy?server=$host&port=$port&secret=$secret_hex";

say "secret ", unpack("H*", $secret);

tcp_server( $host, $port, sub {
        my ($fh, $host, $port) = @_;

        print "Connected...\n";

        my $handle;
        $handle = AnyEvent::Handle->new(
            fh => $fh,
            on_read => sub {
                my $h = shift;
                AE::log debug => "Received: " . length($h->rbuf) . "\n";
                unless (defined $connections{$handle}{cipher}) {

                    ## initialization packet
                    ## ???(8) | enc_key(32) | enc_iv(16) | ???(8)
                    ## or
                    ## ???(8) | dec_iv_rev(16) | dec_key(32) | ???(8)
                    $h->unshift_read( chunk => 64, sub {
                            my $initpak = $_[1];
                            my $initrev = reverse $initpak;

                            AE::log debug => unpack("H*", $initpak);

                            my $enc_k = substr($initpak, 8, 32);
                            my $enc_iv = substr($initpak, 40, 16);
                            
                            my $dec_k = substr($initrev, 8, 32);
                            my $dec_iv = substr($initrev, 40, 16);

                            $enc_k = sha256($enc_k . $secret);
                            $dec_k = sha256($dec_k . $secret);

                            $connections{$_[0]}{cipher}{enc} = Crypt::CTR->new(
                                -key => $enc_k,
                                -iv => $enc_iv,
                                -cipher => 'Crypt::OpenSSL::AES'
                            );
                            
                            $connections{$_[0]}{cipher}{dec} = Crypt::CTR->new(
                                -key => $dec_k,
                                -iv => $dec_iv,
                                -cipher => 'Crypt::OpenSSL::AES'
                            );

                            my $dec_init = $connections{$_[0]}{cipher}{enc}->decrypt($initpak);

                            unless (unpack("L", substr($dec_init, 56, 4)) == 0xefefefef) {
                                AE::log warn => "bad key block";
                                $_[0]->destroy;
                                delete $connections{$_[0]};
                            }

                            my $dc = unpack("s<", substr($dec_init, 60, 2));
                            AE::log info => "request for #$dc";
                        } 
                    );
                }
            },
            on_eof => sub {
                my $h = shift;
                AE::log info => "EOF on " . $connections{$h}{host};
                $h->destroy;
            },
            on_error => sub {
                my $h = shift;
                AE::log info => "Error on " . $connections{$h}{host};
                $h->destroy;
            }
        );
        $connections{$handle} = { 
            client => $handle,
            host => $host,
            port => $port
        };
        
        return;
    }
);

print "Listening on $host:$port\n";

$cv->recv;

