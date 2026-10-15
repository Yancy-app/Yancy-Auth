package Yancy::Auth::I18N::en;
our $VERSION = '2.000';
# ABSTRACT: English lexicon for Yancy::Auth

=head1 DESCRIPTION

This is the (default) English lexicon for Yancy::Auth. Since English is the
default, this is largely intended to be a starting point for your own
translation, listing all the necessary lexicon entries and describing them.

=head1 SEE ALSO

L<Yancy::Auth::I18N>, L<Yancy::I18N>, L<Mojolicious::Plugin::I18N>, L<Locale::Maketext>

=cut

use Mojo::Base '-strict';
use base 'Yancy::Auth::I18N';
our %Lexicon = (
    _AUTO => 1,

    'Login' => 'Login',

    'E-mail Address' => 'E-mail Address',

    'Password' => 'Password',

    'Log In' => 'Log In',

    'Registration is disabled.' => 'Registration is disabled.',
);

1;
