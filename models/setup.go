package models

import (
	"fmt"
	"os"
	"time"

	"sso/helper"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

const (
	NONCE_EXPIRATION = 5 * time.Minute
)

var DB *gorm.DB

func ConnectDB(dsn string) error {
	var err error
	if DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{}); err == nil {
		if sqlDB, err := DB.DB(); err == nil {
			// SetMaxIdleConns sets the maximum number of connections in the idle connection pool.
			sqlDB.SetMaxIdleConns(10)

			// SetMaxOpenConns sets the maximum number of open connections to the database.
			sqlDB.SetMaxOpenConns(100)

			// SetConnMaxLifetime sets the maximum amount of time a connection may be reused.
			sqlDB.SetConnMaxLifetime(time.Hour)
		}
	}
	return err
}

func CreateDBTest() error {
	var err error
	// connect to postgres db
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s", os.Getenv("POSTGRES_HOST"), os.Getenv("POSTGRES_USER"),
		os.Getenv("POSTGRES_PASSWORD"), "postgres", os.Getenv("POSTGRES_PORT"))
	if os.Getenv("POSTGRES_SSLMODE") == "false" {
		dsn += " sslmode=disable"
	}
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return err
	}

	sql := fmt.Sprintf("CREATE DATABASE %s;", os.Getenv("POSTGRES_DB_TEST"))
	if rs := DB.Exec(sql); rs.Error != nil {
		return rs.Error
	}

	// reconnect db test
	dsn = fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s", os.Getenv("POSTGRES_HOST"), os.Getenv("POSTGRES_USER"),
		os.Getenv("POSTGRES_PASSWORD"), os.Getenv("POSTGRES_DB_TEST"), os.Getenv("POSTGRES_PORT"))
	if os.Getenv("POSTGRES_SSLMODE") == "false" {
		dsn += " sslmode=disable"
	}
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	return err
}

func DropDBTest() error {
	var err error
	// connect to db test
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s", os.Getenv("POSTGRES_HOST"), os.Getenv("POSTGRES_USER"),
		os.Getenv("POSTGRES_PASSWORD"), os.Getenv("POSTGRES_DB_TEST"), os.Getenv("POSTGRES_PORT"))
	if os.Getenv("POSTGRES_SSLMODE") == "false" {
		dsn += " sslmode=disable"
	}
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		helper.GetLogger().Error("DB test is not existed")
		return nil
	}

	sqlDB, _ := DB.DB()
	sqlDB.Close()

	// connect postgres db
	dsn = fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s", os.Getenv("POSTGRES_HOST"), os.Getenv("POSTGRES_USER"),
		os.Getenv("POSTGRES_PASSWORD"), "postgres", os.Getenv("POSTGRES_PORT"))
	if os.Getenv("POSTGRES_SSLMODE") == "false" {
		dsn += " sslmode=disable"
	}
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return err
	}

	sql := fmt.Sprintf("DROP DATABASE %s;", os.Getenv("POSTGRES_DB_TEST"))
	if rs := DB.Exec(sql); rs.Error != nil {
		return rs.Error
	}
	return nil
}
