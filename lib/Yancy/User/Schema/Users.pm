package Yancy::User::Schema::Users;
use Mojo::Base 'Yancy::Model::Schema', -signatures;
use Data::GUID qw( guid );

sub create($self, $user) {
  # Auto-generate a UUID for the user
  if (!$user->{user_uuid}) {
    $user->{user_uuid} = guid->as_base64;
  }
  return $self->SUPER::create($user);
}

1;
