# Sentry

GoBGP supports Sentry for error and exception tracking.

To enable Sentry, set the `--sentry-dsn` flag to your Sentry DSN.

```bash
$ gobgpd --sentry-dsn=<your-dsn>
```

In addition, you can set the `--sentry-environment` flag to your Sentry environment.

```bash
$ gobgpd --sentry-dsn=<your-dsn> --sentry-environment=<your-environment>
```

You can also set the `--sentry-sample-rate` flag to the sample rate of Sentry traces.

```bash
$ gobgpd --sentry-dsn=<your-dsn> --sentry-sample-rate=<your-sample-rate>
```

Finally, you can set the `--sentry-debug` flag to enable Sentry debug mode.

```bash
$ gobgpd --sentry-dsn=<your-dsn> --sentry-debug=true
```

When Sentry debug mode is enabled, there is a message logged to Sentry when the program starts.
This is particularly useful to verify that Sentry is working as expected.
