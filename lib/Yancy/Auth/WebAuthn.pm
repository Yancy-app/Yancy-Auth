package Yancy::Auth::WebAuthn;

use Mojo::Base 'Yancy::Auth', -signatures;
use Web::Authn;

has provider_name => 'webauthn';

has rp_id => sub { die 'rp_id is required' };
has rp_name => sub { die 'rp_name is required' };
has expected_origin => sub { die 'expected_origin is required' };
has webauthn => sub($self) {
  return Web::Authn->new(
      rp_id           => $self->rp_id,
      rp_name         => $self->rp_name,
      expected_origin => $self->expected_origin,
  );
};

sub new( $class, $app, @args ) {
  my $self = $class->SUPER::new($app, @args);
  if (!$self->model->isa('Yancy::User')) {
    die 'model must be a Yancy::User';
  }
  $self->model->migrate( __PACKAGE__ );

  $app->routes->get('/auth/passkey')->to(cb => \&entrypoint);
  $app->routes->get('/auth/passkey/register')->to(cb => sub ($c) {
      $self->register_begin($c);
    });
  $app->routes->post('/auth/passkey/register')->to(cb => sub ($c) {
      $self->register_complete($c);
    });
  $app->routes->get('/auth/passkey/login')->to(cb => sub ($c) {
      $self->login_begin($c);
    });
  $app->routes->post('/auth/passkey/login')->to(cb => sub ($c) {
      $self->login_complete($c);
    });
  $app->routes->get('/auth/passkey/logout')->to(cb => sub ($c) {
      if (my $user = $self->model->current_user($c)) {
        my $session = $self->model->current_session($c);
        $c->log->info('Logged out', $user->{user_id});
        $session->set({user_id => undef});
      }
      return $c->render(
        json => { ok => JSON::PP::true },
      );
    });
}

sub entrypoint( $c ) {
  # Check if user in session and has passkey.
  #   If no passkey, ask for passkey
  # If no user, try auto-Passkey
  #   If failure, redirect (fallback) to `/auth/email`
}

sub register_begin ($self, $c) {
  my $authn = $self->webauthn;
  my $session = $self->model->current_session($c);
  my $user = $self->model->current_user($c);
  if (!$user) {
    $c->log->warn('No current user');
    return $c->render(
      status => 401,
      json => { error => 'Unauthorized' },
    );
  }

  my $creds = $self->model->schema('webauthn_credentials')->list({user_id => $user->{user_id}});
  my @exclude = map
  {
      {
          type       => 'public-key',
          id         => $_->{credential_id},
          transports => $_->{transports},
      }
  } @{$creds->{items}};
  my $opts = $authn->generate_registration_options(
      user_name               => $user->{login},
      user_id                 => $user->{user_uuid},
      user_display_name       => $user->{display_name},
      exclude_credentials     => \@exclude,
      authenticator_selection => {
          resident_key      => 'preferred',
          user_verification => 'preferred',
      },
      attestation => 'none',
      timeout     => 60_000,
  );
  if (!$opts) {
    return $c->reply->exception( $authn->error->message );
  }

  $self->create_challenge($session, $user, $opts);
  return $c->render(
    data => $authn->options_to_json( $opts ),
    format => 'json',
  );
}

sub create_challenge( $self, $session, $user, $opts ) {
  if (!$opts->{challenge}) {
    die "No challenge!";
  }

  # Expire any current challenges.
  my $schema = $self->model->schema('webauthn_challenges');
  if (my $res = $schema->list({session_id => $session->{session_id}})) {
    $schema->delete($_->{webauthn_challenge_id}) for @{ $res->{items} };
  }

  $schema->create({
    session_id => $session->{session_id},
    user_id => $user ? $user->{user_id} : undef,
    challenge => $opts->{challenge},
    purpose => 'register',
    expires_at_datetime => Time::Piece->new(time() + 60)->datetime,
  });
}

sub redeem_challenge( $self, $session ) {
  my $res = $self->model->schema('webauthn_challenges')->list({
    session_id => $session->{session_id},
  });
  my $challenge = $res->{items}[0];
  if (!$challenge) {
    return;
  }
  $self->model->schema('webauthn_challenges')->delete($challenge->{webauthn_challenge_id});
  return $challenge;
}

sub register_complete( $self, $c ) {
  my $authn = $self->webauthn;
  my $session = $self->model->current_session($c);
  my $user = $self->model->current_user($c);
  if (!$user) {
    $c->log->warn('User not logged in');
    return $c->render(
      status => 401,
      json => { error => 'Unauthorized' },
    );
  }

  my $challenge = $self->redeem_challenge($session);
  if (!$challenge) {
    $c->log->warn('Challenge not found');
    return $c->render(
      status => 400,
      json => { error => 'BadRequest' },
    );
  }

  my $reg = $authn->verify_registration_response(
      credential                => $c->req->json,
      expected_challenge        => $challenge->{challenge},
      require_user_presence     => 1,
      require_user_verification => 0,
  );
  if (!$reg) {
    $c->log->warn('Challenge not verified', $authn->error->message);
    return $c->render(
      status => 400,
      json => { error => 'BadRequest' },
    );
  }

  $c->log->info('Creating credential', $reg->{credential_id});
  $self->model->schema('webauthn_credentials')->create({
    user_id       => $user->{user_id},
    credential_id => $reg->{credential_id},
    public_key    => $reg->{credential_public_key},
    sign_count    => $reg->{sign_count},
    aaguid        => $reg->{aaguid},
    fmt           => $reg->{fmt},
    device_type   => $reg->{credential_device_type},
    backed_up     => $reg->{credential_backed_up} ? 1 : 0,
    created_at    => Time::Piece->new->datetime,
  });

  return $c->render(
    json => {
      ok => JSON::PP::true,
    },
  );
}

sub login_begin( $self, $c ) {
  my $authn = $self->webauthn;
  my $session = $self->model->current_session($c);
  my $user;
  my @allowed_credentials;
  my $body = $c->req->json;
  if ($body and my $login = $body->{login}) {
    my $user_res = $self->model->schema('users')->list({login => $login});
    $user = $user_res->{items}[0];
    if (!$user) {
      $c->log->warn('Unknown user', $login);
      return $c->render(
        status => 400,
        json => { error => 'RegistrationRequired' },
      );
    }
    @allowed_credentials = map {
        { type => 'public-key', id => $_->{credential_id} }
    } $self->model->schema('webauthn_credentials')->find({user_id => $user->{user_id}})->{items}->@*;
    if (!@allowed_credentials) {
      $c->log->warn('No credentials for user', $login);
      return $c->render(
        status => 400,
        json => { error => 'RegistrationRequired' },
      );
    }
  }

  my $opts = $authn->generate_authentication_options(
      allow_credentials => \@allowed_credentials,
      user_verification => 'preferred',
  ) || return( $c->reply->exception( $authn->error->message ) );
  $self->create_challenge($session, $user, $opts);
  return $c->render(
    format => 'json',
    data => $authn->options_to_json( $opts ),
  );
}

sub login_complete( $self, $c ) {
  my $authn = $self->webauthn;
  my $session = $self->model->current_session($c);
  my $body = $c->req->json;
  my $challenge = $self->redeem_challenge($session);
  if (!$challenge) {
    $c->log->warn('Challenge failed', $authn->error->message);
    return $c->render(
      status => 400,
      json => { error => 'BadRequest' },
    );
  }

  my $credential_id = $authn->base64url_to_bytes( $body->{id} );
  if (!$credential_id) {
    $c->log->warn('Credential not in body');
    return $c->render(
      status => 400,
      json => { error => 'BadRequest' },
    );
  }

  my $res = $self->model->schema('webauthn_credentials')->list({
      credential_id => $credential_id,
    });
  my $credential = $res->{items}[0];
  if (!$credential) {
    $c->log->warn('Credential not found', $credential_id);
    return $c->render(
      status => 400,
      json => { error => 'BadRequest' },
    );
  }

  my $ok = $authn->verify_authentication_response(
    credential                    => $body,
    expected_challenge            => $challenge->{challenge},
    credential_public_key         => $credential->{public_key},
    credential_current_sign_count => $credential->{sign_count},
    require_user_verification     => 0,
  );
  if (!$ok) {
    $c->log->warn('Credential not verified', $authn->error->message);
    return $c->render(
      status => 401,
      json => { error => 'Unauthorized' },
    );
  }
  $self->model->schema('webauthn_credentials')->set($credential->{webauthn_credential_id}, {
    sign_count => $ok->{new_sign_count},
  });

  $c->log->info('Logged in', $credential->{user_id});
  $session->set({user_id => $credential->{user_id}});

  return $c->render(json => { ok => JSON::PP::true });
}

1;
__DATA__
@@ migrations.sqlite
-- 1 up
CREATE TABLE webauthn_credentials (
  webauthn_credential_id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  credential_id BLOB NOT NULL UNIQUE,
  public_key BLOB NOT NULL,
  sign_count INTEGER NOT NULL DEFAULT 0,
  aaguid TEXT,
  fmt TEXT,
  transports TEXT,
  device_type TEXT,
  backed_up INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);

CREATE TABLE webauthn_challenges (
  webauthn_challenge_id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  session_id INTEGER NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
  purpose TEXT NOT NULL,
  challenge BLOB NOT NULL,
  user_id INTEGER REFERENCES users(user_id) ON DELETE CASCADE,
  expires_at_datetime STRING NOT NULL
);

-- 1 down

DROP TABLE webauthn_challenges;
DROP TABLE webauthn_credentials;
