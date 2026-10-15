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
has from => sub { die 'from is required' };
has app_name => sub { die 'app_name is required' };
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

  push $app->renderer->classes->@*, 'Yancy::Auth::Email';
  $app->routes->get('/auth/email')->to(cb => sub($c) { $self->show_form($c) }, hidden => 1);
  $app->routes->post('/auth/email')->to(cb => sub($c) { $self->send_code($c) }, hidden => 1);
  return $self;
}

sub send_code($self, $c) {
  my $session = $self->model->current_session($c);
  my $login = $c->param('login');

  if (!$self->allow_register) {
    if (!$self->get_user($login)) {
      $c->log->warn(sprintf 'user "%s": registration is disabled', $login);
      return $c->respond_to(
        status => 400,
        json => {
          json => {
            ok => JSON::PP::false,
            error => 'registration_disabled',
            error_description => $c->l('Registration is disabled.'),
          },
        },
        html => {
          template => 'auth/email/login',
          error_description => $c->l('Registration is disabled.'),
        },
      );
    }
  }

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
      return $c->respond_to(
        status => 400,
        json => {
          json => {
            ok => JSON::PP::false,
            error => 'code_expired',
            error_description => $c->l('Code is expired.')
          },
        },
        html => {
          template => 'auth/email/login',
          error => 'code_expired',
          error_description => $c->l('Code is expired.')
        },
      );
    }

    if ($password->{attempts} > 5) {
      $c->log->warn('Too many attempts');
      return $c->render(
        status => 400,
        json => {
          json => {
            ok => JSON::PP::false,
            error => 'code_expired',
            error_description => $c->l('Code is expired.')
          },
        },
        html => {
          template => 'auth/email/login',
          error => 'code_expired',
          error_description => $c->l('Code is expired.')
        },
      );
    }

    $self->model->schema('email_passwords')->set($password->{email_password_id}, {attempts => $password->{attempts} + 1});
    if ($password->{login} ne $login) {
      $c->log->warn(sprintf 'Login mismatch (expect: %s; got: %s)', $password->{login}, $login);
      return $c->render(
        status => 400,
        json => {
          json => {
            ok => JSON::PP::false,
            error => 'code_expired',
            error_description => $c->l('Code is expired.')
          },
        },
        html => {
          template => 'auth/email/login',
          error => 'code_expired',
          error_description => $c->l('Code is expired.')
        },
      );
    }

    if ($password->{expires_at} le Time::Piece->new->datetime) {
      $c->log->warn('Email password expired');
      return $c->render(
        status => 400,
        json => {
          json => {
            ok => JSON::PP::false,
            error => 'code_expired',
            error_description => $c->l('Code is expired.')
          },
        },
        html => {
          template => 'auth/email/login',
          error => 'code_expired',
          error_description => $c->l('Code is expired.')
        },
      );
    }

    my $hashed_code = $password->{password};
    if (!$self->password->verify_password($code, $hashed_code)) {
      $c->log->warn('Code incorrect');
      return $c->render(
        status => 400,
        json => {
          json => {
            ok => JSON::PP::false,
            error => 'code_incorrect',
            error_description => $c->l('Code is incorrect.')
          },
        },
        html => {
          template => 'auth/email/login',
          error => 'code_incorrect',
          error_description => $c->l('Code is incorrect.')
        },
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
        # user => {}
      },
      # XXX: use return_to
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
  my $mail = Email::Stuffer->new({ transport => $self->transport });
  $mail->from($self->from);
  $mail->to($login);
  $mail->subject($c->l('Passcode for [_1]', $self->app_name));
  # TODO: html template for email
  # TODO: text template for email
  $mail->text_body($c->l('Your passcode is [_1]', $passcode));
  $mail->send;
  $c->log->debug('Code sent to', $login);

  return $c->respond_to(
    json => {
      json => {
        login => $login,
        ok => JSON::PP::true,
      },
    },
    html => {
      template => 'auth/email/login',
      login => $login,
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

@@ auth/email/login.html.ep

<form {onsubmit}>
  <label for="one-time-code">
    Enter code sent to {login}
  </label>
  <input
    type="text"
    id="one-time-code"
    bind:value={passcode}
    autocomplete="one-time-code webauthn"
    maxlength="9"
    pattern={"[a-fA-F0-9]{4}-?[a-fA-F0-9]{4}"}
    required
    class="font-mono input field-3xl tracking-wide"
  />

  <label class="label label-text" for="login-login">E-mail</label>
  <input
    class="input"
    id="login-login"
    autocomplete="username webauthn"
    bind:value={login}
  />

  <button class="btn preset-tonal">Next</button>
</form>
