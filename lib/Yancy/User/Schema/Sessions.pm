package Yancy::User::Schema::Sessions;
use Mojo::Base 'Yancy::Model::Schema', -signatures;
use Data::GUID qw( guid );

sub create($self, $data) {
  if (!$data->{session_uuid}) {
    $data->{session_uuid} = guid->as_base64;
  }
  return $self->SUPER::create($data);
}

1;
