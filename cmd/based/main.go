package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/phillip-england/based/internal/config"
	"github.com/phillip-england/based/internal/server"
	"github.com/phillip-england/based/internal/tmux"
)

const defaultAddr = ":37491"

func main() {
	if err := run(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return serve(args)
	}

	switch args[0] {
	case "serve":
		return serve(args[1:])
	case "set-credentials":
		return setCredentials(args[1:])
	case "credentials-path":
		path, err := config.EnvFilePath()
		if err != nil {
			return err
		}
		fmt.Println(path)
		return nil
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	addr := fs.String("addr", defaultAddr, "address to listen on")
	dbPath := fs.String("db", "", "sqlite database path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if cfg.AdminUsername == "" || cfg.AdminPassword == "" {
		return errors.New("admin credentials are not set; run: based set-credentials -username <name> -password <password>")
	}

	if err := tmux.EnsureInstalled(context.Background()); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv, err := server.New(server.Options{
		Addr:          *addr,
		DBPath:        *dbPath,
		AdminUsername: cfg.AdminUsername,
		AdminPassword: cfg.AdminPassword,
	})
	if err != nil {
		return err
	}
	defer srv.Close()

	log.Printf("based listening on http://localhost%s", *addr)
	return srv.Run(ctx)
}

func setCredentials(args []string) error {
	fs := flag.NewFlagSet("set-credentials", flag.ContinueOnError)
	username := fs.String("username", "", "admin username")
	password := fs.String("password", "", "admin password")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *username == "" || *password == "" {
		return errors.New("username and password are required")
	}
	path, err := config.WriteCredentials(*username, *password)
	if err != nil {
		return err
	}
	fmt.Printf("Wrote credentials to %s\n", path)
	return nil
}

func usage() {
	fmt.Println(`based

Usage:
  based serve [-addr :37491] [-db /path/to/based.sqlite]
  based set-credentials -username admin -password secret
  based credentials-path

Environment:
  BASED_ADMIN_USERNAME overrides the configured username
  BASED_ADMIN_PASSWORD overrides the configured password`)
}
