# rasp-lab host

Laboratory consumer backend for the device round. It is the third-party sample
(`../aspnetcore-third-party`: enrollment routes, `POST /pedidos/{id}/concluir`, the fake `step_up` handler) plus:

- a laboratory login (`LabSession.cs`): scheme `Lab`; the header `X-Lab-Auth-Age-Seconds` (0..86400) makes the user
  `rasp-lab-user` (tenant `rasp-lab`) authenticated with `auth_time = now - age`. The step-up handler accepts a login of at most 5
  minutes, so age 1800 gets `401 challenge-required` `step_up` and age 30 gets `200`. Only loopback, private (RFC 1918) and
  IPv6 ULA/link-local peers are accepted; anything else is 401.
- an in-memory self-signed certificate (`LabCertificate.cs`, RSA 2048, SANs `localhost`, `127.0.0.1` and `Lab__Hosts`), new
  on every start; the host prints `rasp-lab host certificate sha256: <hex>`, which the app test takes as `hostCertSha256`.
- it starts only with `ASPNETCORE_ENVIRONMENT=Development` (the login trusts the network). Lab network, for the window of the round.

## Run

```bash
docker build -f integrations/samples/aspnetcore-rasp-lab-host/Dockerfile -t rasp-lab-host .
docker run --rm -p 8443:8443 --env-file lab-host.env rasp-lab-host
```

`lab-host.env` (never committed; the token is the `consumer` workload token, set by the owner of the environment):

```
Lab__Hosts=<address the device uses, e.g. 192.0.2.10>
Sentomaru__BaseAddress=<API origin>
Sentomaru__PublicBaseUrl=https://<address the device uses>:8443
Sentomaru__Org=ebees
Sentomaru__App=rasp-lab
Sentomaru__Env=hml
Sentomaru__WorkloadToken=<consumer token>
```

Without Docker: `dotnet run --project integrations/samples/aspnetcore-rasp-lab-host` with the same variables (the repository's
`global.json` pins the SDK; the Dockerfile drops the pin).

## App side

`sdk/android/sample-app/src/androidTestRaspLab/.../RaspLabStepUpInstrumentedTest.kt` (build `-Psentomaru.raspLab=true`,
`assembleRaspLabAndroidTest`). Arguments: `host` (`https://<address>:8443`), `hostCertSha256`, optional `signals`,
`expectedSigner`, `deadlineMs`, `warmup`. The test trusts only that certificate, holds no token and reports statuses
`d06iCase`: `enroll`, `step-up-old-login`, `step-up-recent-login`.
