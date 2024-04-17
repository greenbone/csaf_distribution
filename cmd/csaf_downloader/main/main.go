// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

// Package main implements the csaf_downloader tool.
package main

import (
	"context"
	"os"
	"os/signal"

	"golang.org/x/exp/slog"

	"github.com/csaf-poc/csaf_distribution/v3/cmd/csaf_downloader"
	"github.com/csaf-poc/csaf_distribution/v3/pkg/options"
)

func run(cfg *csaf_downloader.Config, domains []string) error {
	d, err := csaf_downloader.NewDownloader(cfg)
	if err != nil {
		return err
	}
	defer d.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt)
	defer stop()

	if cfg.ForwardURL != "" {
		f := csaf_downloader.NewForwarder(cfg)
		go f.Run()
		defer func() {
			f.Log()
			f.Close()
		}()
		d.Forwarder = f
	}

	return d.Run(ctx, domains)
}

func main() {

	domains, cfg, err := csaf_downloader.ParseArgsConfig()
	options.ErrorCheck(err)
	options.ErrorCheck(cfg.Prepare())

	if len(domains) == 0 {
		slog.Warn("No domains given.")
		return
	}

	options.ErrorCheck(run(cfg, domains))
}
