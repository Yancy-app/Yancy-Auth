package Yancy::Auth::Email;

use Mojo::Base 'Yancy::Auth', -signatures;
use Email::Stuffer;
use Crypt::Passphrase;
use Crypt::SysRandom qw( random_bytes );
use MIME::Base64;
use Authen::SASL;
use Time::Piece;
use Time::Seconds;

has provider_name => 'email';
has from =>;
has transport =>;
has password => sub { 
  Crypt::Passphrase->new(
    encoder => {
      module  => 'Argon2',
      profile => 'interactive',
    },
  );
};

sub new( $class, $app, @args ) {
  my $self = $class->SUPER::new($app, @args);
  if (!$self->model->isa('Yancy::User')) {
    die 'model must be a Yancy::User';
  }
  $self->model->migrate( __PACKAGE__ );

  $app->routes->get('/auth/email')->to(cb => sub($c) { $self->show_form($c) });
  $app->routes->post('/auth/email')->to(cb => sub($c) { $self->send_code($c) });
}

sub send_code($self, $c) {
  my $session = $self->model->current_session($c);
  my $login = $c->param('login');

  # TODO: Limit attempts
  # TODO: Limit sends to a given e-mail (timeout between expirations)
  # TODO: Set expiration time

  # If "code", verify code and start session
  if (my $code = $c->param('code')) {
    # Remove spaces and dashes, just to be sure
    $code =~ s/[\ \-]+//g;

    my $password_res = $self->model->schema('email_passwords')->list({session_id => $session->{session_id}, consumed => 0});
    my $password = $password_res->{items}[0];
    if (!$password) {
      $c->log->warn('Could not find email password for session');
      return $c->render(
        status => 400,
        json => { ok => JSON::PP::false, },
      );
    }

    if ($password->{attempts} > 5) {
      $c->log->warn('Too many attempts');
      return $c->render(
        status => 400,
        json => { ok => JSON::PP::false, },
      );
    }

    $self->model->schema('email_passwords')->set($password->{email_password_id}, {attempts => $password->{attempts} + 1});
    if ($password->{login} ne $login) {
      $c->log->warn(sprintf 'Login mismatch (expect: %s; got: %s)', $password->{login}, $login);
      return $c->render(
        status => 400,
        json => { ok => JSON::PP::false, },
      );
    }

    if ($password->{expires_at} le Time::Piece->new->datetime) {
      $c->log->warn('Email password expired');
      return $c->render(
        status => 400,
        json => { ok => JSON::PP::false, },
      );
    }

    my $hashed_code = $password->{password};
    if (!$self->password->verify_password($code, $hashed_code)) {
      $c->log->warn('Code incorrect');
      return $c->render(
        status => 400,
        json => { ok => JSON::PP::false, },
      );
    }

    # If success, return to '/auth/passkey'
    # We are now authenticated!
    $self->model->schema('email_passwords')->set($password->{email_password_id}, {consumed => 1});

    # Does the user exist yet?
    my $user_lookup = $self->model->schema('users')->list({login => $login});
    my $user = $user_lookup->{items}[0];
    if (!$user) {
      # Create a new user
      $c->log->debug('User registered', $user);
      my $user_id = $self->model->schema('users')->create({
        login => $login,
      });
      $user = $self->model->schema('users')->get($user_id);
    }
    else {
      $c->log->debug('User logged-in', $user);
    }
    $session->set({user_id => $user->{user_id}});

    return $c->render(
      json => {
        ok => JSON::PP::true,
      },
    );
  }

  my @code_parts = map { unpack 'h*', random_bytes(2) } 0..1;
  # TODO: Insert hashed passcode into database
  $self->model->schema('email_passwords')->create({
    session_id => $session->{session_id},
    login => $login,
    password => $self->password->hash_password(join "", @code_parts),
    created_at => Time::Piece->new->datetime(),
    expires_at => Time::Piece->new(time + ONE_MINUTE * 5)->datetime(),
  });

  my $passcode = join '-', @code_parts;
  $c->log->debug('Code sent to', $login);
  my $mail = Email::Stuffer->new({ transport => $self->transport });
  $mail->from($self->from);
  $mail->to($login);
  $mail->subject('Passcode for Yancy.app');
  $mail->text_body("Your passcode is $passcode");
  $mail->send;

  return $c->render(
    json => {
      login => $login,
      ok => JSON::PP::true,
    },
  );
}

1;
__DATA__

@@ migrations.sqlite
-- 1 up
CREATE TABLE email_passwords (
  email_password_id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  session_id INTEGER NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
  login STRING NOT NULL,
  password STRING NOT NULL,
  created_at STRING NOT NULL,
  expires_at STRING NOT NULL,
  consumed INTEGER DEFAULT 0,
  attempts INTEGER DEFAULT 0
);

-- 1 down
DROP TABLE email_passwords;
