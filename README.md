# SSO Service

The all-on-one SSO Service that complies with OAuth2 standard and supports multiple authentication schemes, including email, social accounts, EOA wallet, multi-sig wallet.

## Architecture

- [System architecture](./docs/architecture.md)

Main components:
>   - Authorization gateway
>   - Service API

## Prerequisites

- [GCC](https://linuxize.com/post/how-to-install-gcc-on-ubuntu-20-04/)
- [Go v1.22](https://go.dev/doc/install)
- [Python 3.8](https://www.python.org/downloads/release/python-380/)
- [PostgreSQL](https://www.digitalocean.com/community/tutorials/how-to-install-postgresql-on-ubuntu-20-04-quickstart)
- [Redis](https://hub.docker.com/_/redis)

## Setup

- Create `.env` file from template and populate necessary credentials and secrets.

```sh
$ cp .env.example .env
```

- Migrate DB

```sh
$ cd admin && python manage.py migrate
```

## Run

- Start running dev 

```sh
$ go run main.go
```

## Compile

- Compile executables

```sh
$ make build
```

- Generate swagger docs
>   [Install swag](https://github.com/swaggo/swag/releases/download/v1.8.5/swag_1.8.5_Linux_x86_64.tar.gz)

```sh
$ ~/swag init
```

## Unit Test

- Execute unit tests

```sh
$ make test-unit
```