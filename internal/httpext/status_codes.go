// SPDX-FileCopyrightText: 2025 Greenbone AG <https://greenbone.net>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package httpext

const (
	// non standard status code used by NGINX: https://nginx.org/en/docs/http/ngx_http_ssl_module.html#errors
	StatusNGINXInvalidClientCert = 495
	StatusNGINXNoClientCert      = 496
)
