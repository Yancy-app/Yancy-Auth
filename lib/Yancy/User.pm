package Yancy::User;
use Mojo::Base 'Yancy::Model', -signatures;
use Scalar::Util qw( blessed );
use Mojo::JSON qw( true false );
use Data::GUID qw( guid );
use Time::Piece ();

=head1 DESCRIPTION

This is the user _model_: It provides user accounts, sessions, and groups.
Authentication is handled by a L<Yancy::Auth> plugin, which then use this
model to find users and set up sessions.

=cut

has _auths => sub { [] };

sub new($class, @args) {
  my $self = $class->SUPER::new(@args);
  unshift @{$self->namespaces}, 'Yancy::User';
  $self->migrate(__PACKAGE__);
  return $self;
}

sub current_session( $self, $c ) {
  my $now = Time::Piece->new->datetime;
  my $schema = $self->schema('sessions');
  my $session_uuid = $c->session->{session_uuid};
  if ($session_uuid) {
    my $session_list = $schema->list({session_uuid => $session_uuid});
    my $session = $session_list->{items}[0];
    if ($session) {
      $schema->set($session_uuid => {last_activity_datetime => $now});
      return $session;
    }
  }

  my $session_uuid = $c->session->{session_uuid} = guid()->as_base64;
  my $new_session_id = $self->schema('sessions')->create({
    session_uuid => $session_uuid,
    created_datetime => $now,
    last_activity_datetime => $now,
  });
  return $self->schema('sessions')->get($new_session_id);
}

sub current_user( $self, $c ) {
  my $session = $self->current_session($c);
  my $user_id = $session->{user_id};
  return $self->schema('users')->get($user_id);
}

sub add_auth( $self, $auth ) {
  # XXX: Make sure auth provider_name is unique!

}

sub require_permission($self, $permission) {
  return sub($c) {
    my $user = $self->current_user($c);
    if (!$user) {
      $c->render('unauthorized', status => 401);
      return 0;
    }
    my $perm = $self->schema('user_permissions')->get([$user->{user_id},$permission]);
    if (!$perm) {
      $c->log->warn(sprintf 'user "%s" lacks permission "%s"', $user->{login}, $permission);
      return 0;
    }
    return 1;
  };
}

1;
__DATA__

@@ migrations.sqlite
-- 1 up
CREATE TABLE users (
  user_id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  user_uuid STRING NOT NULL,
  login STRING NOT NULL,
  display_name STRING,
  UNIQUE (user_uuid),
  UNIQUE (login)
);

CREATE TABLE user_permissions (
  user_id INTEGER NOT NULL REFERENCES users (user_id),
  permission STRING,
  PRIMARY KEY (user_id, permission)
);

CREATE TABLE sessions (
  session_id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  session_uuid STRING NOT NULL,
  user_id STRING REFERENCES users (user_id),
  created_datetime STRING,
  last_activity_datetime STRING,
  UNIQUE (session_uuid)
);

-- 1 down
DROP TABLE sessions;
DROP TABLE user_permissions;
DROP TABLE users;

@@ unauthorized.html.ep
Unauthorized
