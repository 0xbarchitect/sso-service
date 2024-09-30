# SSO Service

The all-on-one SSO Service that complies with OAuth2 standard and supports multiple authentication schemes, including email, social accounts, EOA wallet, multi-sig wallet.

## Architecture

- [System architecture](./docs/architecture.md)

Main components:
>   - Authorization gateway
>   - Service API

## Prerequisites

- [GCC](https://linuxize.com/post/how-to-install-gcc-on-ubuntu-20-04/)
- [Go v1.23](https://go.dev/doc/install)
- [PostgreSQL v15](https://www.digitalocean.com/community/tutorials/how-to-install-postgresql-on-ubuntu-20-04-quickstart)

## Setup

- Create `.env` file from template and populate necessary credentials and secrets.

```bash
$ cp .env.default .env
```

## Run

- Start running dev 

```bash
$ go run main.go
```

## Compile

- Compile executables

```bash
$ make build
```

- Generate swagger docs
>   [Install swag](https://github.com/swaggo/swag/releases/download/v1.8.5/swag_1.8.5_Linux_x86_64.tar.gz)

```bash
$ ~/swag init
```

## Unit Test

- Execute unit tests

```bash
$ make test-unit
```

## Demo

- Create symlink `.env` for client apps

```bash
$ cd demo; ln -s ../.env .env
```

- Run client demo

```bash
$ cd demo; go run client.go
```

- Access to client demo apps http://localhost:9015, then login, this will redirect to Authorization gateway on SSO server
- Signup with arbitrary email / password
- Authorize client apps, verify retrieve access token succeed
- Logout then try to login again with just created account
- Test token http://localhost:9015/try
- Refresh token http://localhost:9015/refresh