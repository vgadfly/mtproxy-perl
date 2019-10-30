#!/usr/bin/env perl

use Modern::Perl;

use AnyEvent;
use AnyEvent::Socket;
use AnyEvent::Handle;

use Digest::SHA qw(sha256);
use Crypt::CTR;
use Crypt::OpenSSL::AES;
use Crypt::OpenSSL::Random;

my $cv = AE::cv;

my $host = '0.0.0.0';
my $port = 2443;

my %clients;
my %servers;

my @telegram_servers = qw( 149.154.175.50 149.154.167.51 149.154.175.100 149.154.167.91 149.154.171.5 );

my $secret_hex = $ARGV[0];
my $secret = pack("H*", $secret_hex);
die "Bad secret" unless length($secret) == 16;

say "tg://proxy?server=$host&port=$port&secret=$secret_hex";

sub ciphers_from_packet
{
    my ($initpak, $secret) = @_;
    my $initrev = reverse $initpak;

    #AE::log debug => unpack("H*", $initpak);

    my $dec_k = substr($initpak, 8, 32);
    my $dec_iv = substr($initpak, 40, 16);
    
    my $enc_k = substr($initrev, 8, 32);
    my $enc_iv = substr($initrev, 40, 16);

    if (defined $secret) {
        $enc_k = sha256($enc_k . $secret);
        $dec_k = sha256($dec_k . $secret);
    }
    my $enc = Crypt::CTR->new(
        -key => $enc_k,
        -iv => $enc_iv,
        -cipher => 'Crypt::OpenSSL::AES'
    );
    
    my $dec = Crypt::CTR->new(
        -key => $dec_k,
        -iv => $dec_iv,
        -cipher => 'Crypt::OpenSSL::AES'
    );

    return ($enc, $dec);
}

sub from_server
{
    my $handle = shift;

    my $data = $handle->{rbuf};
    $handle->{rbuf} = '';
    
    my $client = $servers{$handle}->{client};
    AE::log debug => "server -> client %d", length($data);
    AE::log debug => unpack("H*", $data);
    
    my $enc_data = $client->{cipher}{enc}->encrypt( $data );
    $client->{handle}->push_write( $enc_data );
    AE::log debug => "%d bytes sent", length($enc_data);
}

sub spawn_server
{
    my ($host, $port, $client) = @_;
    tcp_connect( $host, $port, sub {
            my $fh = shift;
            return unless $fh;

            AE::log info => "connected to %s", $host;

            my $handle = AnyEvent::Handle->new( 
                fh => $fh,
                on_read => \&from_server,
                on_error => sub { 
                    AE::log warn => "socket error"
                },
                on_eof => sub {
                    AE::log warn => "socket closed"
                }
            );

            # XXX: forcing abriged, use transport id from client instead
            $handle->push_write( "\xef" );
            $servers{$handle} = {
                handle => $handle,
                client => $client
            };
            $client->{server} = $handle;
            
            # XXX: force on_read on client handle
            $client->{handle}->unshift_read( sub {
                    AE::log debug => "some data left: %d", length($_[0]->{rbuf});
                    my $client = $clients{$_[0]};
                    if ( length( $_[0]->{rbuf}) > 16) {
                        my $data = $client->{cipher}{dec}->decrypt( $_[0]->{rbuf} );
                        $_[0]->{rbuf} = '';
                        AE::log debug => unpack("H*", $data);
                        $client->{server}->push_write( $data );
                        return 1;
                    } 
                    return 0;
                }
            );
        } 
    );
    return;
}

sub from_client
{
    my $handle = shift;
    my $client = $clients{$handle};
    AE::log debug => "Received: " . length($handle->{rbuf}) . "\n";

    unless (defined $clients{$handle}{cipher}) {

## initialization packet
## ???(8) | enc_key(32) | enc_iv(16) | ???(8)
## or
## ???(8) | dec_iv_rev(16) | dec_key_rev(32) | ???(8)
        $handle->unshift_read( chunk => 64, sub {
                my $client = $clients{$_[0]};
                my ($enc, $dec) = ciphers_from_packet( $_[1], $secret );
                $client->{cipher}{enc} = $enc;
                $client->{cipher}{dec} = $dec;

                my $dec_init = $dec->decrypt($_[1]);

                unless (unpack("L", substr($dec_init, 56, 4)) == 0xefefefef) {
                    AE::log warn => "bad key block";
                    $_[0]->destroy;
                    delete $clients{$_[0]};
                }

                my $dc = unpack("s<", substr($dec_init, 60, 2));
                AE::log info => "request for #$dc";
                $dc = abs( $dc );
                if ( $dc < 1 or $dc > 5 ) {
                    AE::log warn => "bad DC id";
                    $_[0]->destroy;
                    delete $clients{$_[0]};
                }

                spawn_server( $telegram_servers[$dc-1], 443, $client );
            } 
        );
    }
    elsif ( defined $client->{server} ) {
        $handle->unshift_read( sub {
                my $client = $clients{$_[0]};
                my $data = $_[0]->{rbuf};
                $_[0]->{rbuf} = '';
                AE::log debug => "more data recvd: %d", length($data);
                $data = $client->{cipher}{dec}->decrypt( $data );
                AE::log debug => unpack("H*", $data);
                $client->{server}->push_write( $data );
                return 1;
            } 
        );
    }
}

tcp_server( $host, $port, sub {
        my ($fh, $host, $port) = @_;

        AE::log info => "$host connected...";

        my $handle;
        $handle = AnyEvent::Handle->new(
            fh => $fh,
            on_read => \&from_client,
            on_eof => sub {
                my $h = shift;
                my $client = $clients{$h};
                AE::log info => "EOF on " . $client->{host};
                $h->destroy;
                if (exists $client->{server}) {
                    $client->{server}->destroy;
                    delete $servers{$client->{server}};
                }
                delete $clients{$fh};
            },
            on_error => sub {
                my $h = shift;
                my $client = $clients{$h};
                AE::log info => "Error on " . $client->{host};
                $h->destroy;
                if (exists $client->{server}) {
                    $client->{server}->destroy;
                    delete $servers{$client->{server}};
                }
                delete $clients{$h};
            }
        );
        $clients{$handle} = { 
            handle => $handle,
            host => $host,
            port => $port
        };
        return;
    }
);

$cv->recv;

