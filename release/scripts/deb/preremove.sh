#!/bin/sh
set -e
systemctl disable --now pve-imds.service || true
