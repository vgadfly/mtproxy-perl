package Crypt::CTR;

use Modern::Perl;
use Carp;

use Crypt::OpenSSL::Random;
use Crypt::OpenSSL::Bignum;

# bignum to BE bin
sub bn2bin
{
    my ($bn, $len) = @_;
    my $blen = $bn->num_bytes;
    my $bin = $bn->to_bin;
    $bin = "\x0"x($len-$blen) . $bin if $blen < $len;
    return $bin;
}

sub new
{
    my ($class, %options) = @_;

    Carp::croak "key, cipher, iv required" 
        unless defined $options{'-key'} and defined $options{'-iv'} and defined $options{'-cipher'};

    my $self = { 
        key => $options{'-key'},
        iv => $options{'-iv'},
        cipher => $options{'-cipher'}
    };

    unless (ref $self->{cipher}) {
        $self->{cipher} = $self->{cipher}->new($self->{key})
    }

    bless( $self, $class );
}

sub encrypt
{
    my ($self, $data) = @_;
    my $block_size = $self->{cipher}->blocksize; 
    my $bn_ctx = Crypt::OpenSSL::Bignum::CTX->new;
    my $ct = Crypt::OpenSSL::Bignum->zero;

    my $pad = Crypt::OpenSSL::Random::random_pseudo_bytes( 
        -(length($data)) % $block_size);

    $data .= $pad;

    my $block_count = length($data) / $block_size;

    my $enc_data;
    for( my $b=0; $b < $block_count; $b++ ) 
    {
        my $iv = $self->{iv};
        my $gamma = $self->{cipher}->encrypt( $iv );
        
        $ct = Crypt::OpenSSL::Bignum->new_from_bin( $iv );
        $ct = $ct->add(Crypt::OpenSSL::Bignum->one);
        $self->{iv} = bn2bin($ct, 16);

        $enc_data .= substr($data, $block_size * $b, $block_size) ^ $gamma;
    }
    return $enc_data;
}

sub decrypt
{
    goto &encrypt;
}

1;

