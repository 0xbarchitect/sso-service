# CMS

CMS and DB migration scripts for SSO service that is powered by Django.

## Prerequisites

- [Python 3.8](https://www.python.org/downloads/release/python-380/)
- [PostgreSQL 14](https://hub.docker.com/_/postgres)

## Setup

- Install dependencies packages

```sh
$ pip install -r requirement.txt
```

- Clone default template to create new config env
```sh
$ cd ..; cp .env.default .env
```
- Change configuration in .env to adapt your local dev environments (PostgreSQL, DynamoDB, Scanner server, etc)

- Apply environment variables into current bash session
```sh
$ cd ..; source ./start_conda.sh
```

- Migrate DB
```sh
$ python manage.py migrate
$ python manage.py showmigrations
```
*need to ensure that all migrations is completed.*

- Create superuser (run only once)
```
$ python manage.py createsuperuser
```
select your username and password, need for login into Admin page.

## Running

- Start server
```
$ python manage.py runserver 0.0.0.0:<PORT>
```
> By default usage port is 8080 if omitted.

- Open Admin tools in URL http://localhost:[PORT]/admin/

- Login with your superuser account created in previous step.
