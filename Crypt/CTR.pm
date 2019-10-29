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
    $bin = substr($bin, 0, $len) if $blen > $len;
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

    my $enc_data;

    if ( defined $self->{_stash} ) {
        my $slen = length( $self->{_stash} );

        if ( $slen < length($data) ) {
            my $slice = substr( $data, 0, $slen );
            $data = substr( $data, $slen );
            $enc_data .= $slice ^ $self->{_stash};
            $self->{_stash} = undef;
        }
        else {
            my $slice = substr( $self->{_stash}, 0, length($data) );
            $enc_data .= $data ^ $slice;
            $self->{_stash} = substr( $self->{_stash}, length($data) );
            $data = '';
        }
    }

    my $block_count = int( length($data) / $block_size );
    for( my $b=0; $b < $block_count; $b++ ) 
    {
        my $iv = $self->{iv};
        my $gamma = $self->{cipher}->encrypt( $iv );
        
        $ct = Crypt::OpenSSL::Bignum->new_from_bin( $iv );
        $ct = $ct->add(Crypt::OpenSSL::Bignum->one);
        $self->{iv} = bn2bin($ct, 16);

        $enc_data .= substr($data, $block_size * $b, $block_size) ^ $gamma;
    }

    if ( $block_count * $block_size < length($data) ) {
        $data = substr( $data, $block_count * $block_size );
        
        my $iv = $self->{iv};
        my $gamma = $self->{cipher}->encrypt( $iv );
        my $slice = substr( $gamma, 0, length($data) );
        $self->{_stash} = substr( $gamma, length($data) );
        
        $ct = Crypt::OpenSSL::Bignum->new_from_bin( $iv );
        $ct = $ct->add(Crypt::OpenSSL::Bignum->one);
        $self->{iv} = bn2bin($ct, 16);
        
        $enc_data .= $data ^ $slice;
    }

    return $enc_data;
}

sub decrypt
{
    goto &encrypt;
}

1;

