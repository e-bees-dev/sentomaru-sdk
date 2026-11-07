# C-09 (#142): read-only AppRole; renders sentomaru.env (0600) for docker compose's env_file, then exits
# (exit_after_auth): the api container starts after it (depends_on) and reads the file once, at creation.
exit_after_auth = true

vault {
  address = "https://vault.minha-empresa.example"
}

auto_auth {
  method "approle" {
    config = {
      role_id_file_path                   = "/agent/auth/role-id"
      secret_id_file_path                 = "/agent/auth/secret-id"
      remove_secret_id_file_after_reading = false
    }
  }
}

template {
  source      = "/agent/sentomaru.env.ctmpl"
  destination = "/rendered/sentomaru.env"
  perms       = "0600"
  error_on_missing_key = true
}
