# aws-auth

`aws-auth` is a command line to get aws sts token and write it to `~/.aws/credentials` via okta authentication.

> Note: The development is in progress. Currently it only supports AWS China Ningxia (`cn-northwest-1`).

## How to use it

1. Download the binary from [releases](https://github.com/zhangyuan/aws-auth/releases) and make it executable with proper permission, or build the project and get the executable program `aws-auth`

```
cargo build --release
```

2. Create the configuration file `.aws-auth.toml`, either in the same directory as `aws-auth` or in HOME directory. Example:

```
app-link = "https://yourcompanyname.okta.com/home/yourcompanyname_awschinamyapp_1/aaaaaaaaaaaaaa/bbbbbbbbbbbb"
```

3. Run the command `aws-auth`, you'll be asked for username, password, mfa code, etc.
