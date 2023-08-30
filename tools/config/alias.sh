#!/bin/bash

ALIAS_FILE="pkg/config/bgp_aliases.go"

echo "package config" > "${ALIAS_FILE}"
echo >> "${ALIAS_FILE}"
echo 'import "github.com/osrg/gobgp/v3/internal/pkg/config"' >> "${ALIAS_FILE}"
echo >> "${ALIAS_FILE}"
echo "type BgpConfigSet = config.BgpConfigSet" >> "${ALIAS_FILE}"

grep -E -o '^type [A-Z]\w*' internal/pkg/config/bgp_configs.go | grep -E -o '\w+$' | sed "s,\(.*\),type \1 = config.\1,g" >> "${ALIAS_FILE}"
grep -E -o '^\s+[A-Z][0-9A-Z_]+\s+' internal/pkg/config/bgp_configs.go | grep -E -o '^\s+\w+' | grep -E -o '\w+$' | sed "s,\(.*\),const \1 = config.\1,g" >> "${ALIAS_FILE}"
