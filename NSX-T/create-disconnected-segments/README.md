# Create disconnected NSX segments in bulk

This script creates multiple disconnected segments in NSX using the Policy API. It is intended to be used as part of a migration or lab build process where a large number of segments, each with a known subnet and gateway, need to be created quickly and consistently.

For each network supplied, the script creates a segment of type `DISCONNECTED` in the default overlay transport zone. The segment `id` and display name are generated from the network and prefix (for example, `192.0.2.0/24` becomes `net_192.0.2.0_24`). Because the script uses `PATCH`, running it again with the same networks will update the existing segments rather than fail.

## Requirements

- `bash`
- `curl`
- `jq`
- Network access to the NSX Manager API (HTTPS)
- An NSX account with permission to create segments
- A default overlay transport zone configured in NSX

Note that the script uses `curl -k`, which skips TLS certificate verification.

## Inputs

### NSX Manager connection details

The NSX Manager, username and password are resolved in the following order (highest priority first):

1. Command-line arguments
2. Environment variables
3. Hard-coded defaults at the top of the script

| Setting     | Argument | Environment variable | Default |
|-------------|----------|----------------------|---------|
| NSX Manager | `-m`     | `NSX_MANAGER`        | none (required) |
| Username    | `-u`     | `NSX_USER`           | `admin` |
| Password    | `-p`     | `NSX_PASS`           | none (prompted if not set) |

To hard-code values, edit `DEFAULT_NSX_MANAGER`, `DEFAULT_NSX_USER` and `DEFAULT_NSX_PASS` at the top of the script. This is not recommended for a password if the script will be shared.

Passing the password with `-p` exposes it in the process list and shell history. Prefer the `NSX_PASS` environment variable or the interactive prompt.

### Networks

Networks can be supplied from any combination of the following sources. All sources are combined.

| Source     | How                                                  |
|------------|------------------------------------------------------|
| File       | `-f <file>` (repeatable, use `-f -` to read stdin)   |
| Argument   | `-n "<entry>"` (repeatable)                          |
| Hard-coded | Add entries to the `HARDCODED_NETWORKS` array        |

Each entry must contain the network, prefix length and gateway. Either of the following formats is accepted:

```
<network>/<prefix> <gateway>
<network> <prefix> <gateway>
```

In a file, use one entry per line. Blank lines and anything after a `#` are ignored. See `networks.example.txt` for a sample.

```
# Example networks file
192.0.2.0/24 192.0.2.1
198.51.100.0 24 198.51.100.1
```

The script exits with an error if no networks are supplied.

## Usage

```
./create_disconnected_segments.sh [-m nsx_manager] [-u username] [-p password] [-f file] [-n entry]...
```

| Option | Description |
|--------|-------------|
| `-m`   | NSX Manager hostname or IP |
| `-u`   | NSX username |
| `-p`   | NSX password |
| `-f`   | File of networks, one per line (use `-` for stdin). May be repeated. |
| `-n`   | Single network entry. May be repeated. |
| `-h`   | Show help |

## Examples

Create segments from a file, being prompted for the password:

```bash
./create_disconnected_segments.sh -m nsx.example.com -u admin -f networks.txt
```

Use environment variables for the connection details and supply a single network as an argument:

```bash
export NSX_MANAGER=nsx.example.com
export NSX_USER=admin
export NSX_PASS='changeme'
./create_disconnected_segments.sh -n "192.0.2.0/24 192.0.2.1"
```

Combine a file and additional arguments:

```bash
./create_disconnected_segments.sh -m nsx.example.com -f networks.txt -n "203.0.113.0/24 203.0.113.1"
```

Read networks from stdin:

```bash
cat networks.txt | ./create_disconnected_segments.sh -m nsx.example.com -f -
```

A successful `PATCH` returns an empty response, so no JSON is printed between the progress lines. If NSX rejects a request, the error response body is printed in that position.

## Notes

- Entries that cannot be parsed are skipped with a warning on stderr.
- The script does not stop if a single segment fails to be created. Review the output for any error responses.
- Segments are created in the default overlay transport zone, which is discovered automatically from the NSX Manager.
