# GoBGP Release Notes - BGP-LS Error Notification

## New Features

**BGP-LS Error Notification to Topolograph**: Automatically sends HTTP POST notifications to Topolograph when malformed BGP-LS Link NLRI messages are detected. Uses `WEBHOOK_URL` environment variable.

**Network-Engineer-Friendly Error Messages**: Extracts node identifiers (ASN, BGP LS ID, IGP Router ID) from LocalNodeDesc and RemoteNodeDesc for clear error reporting.

## Technical

- Fire-and-forget async HTTP POST (non-blocking, best-effort)
- 2-second timeout to avoid blocking BGP decode path
- Error notification sent before returning ATTRIBUTE_DISCARD error
- Node identifier extraction using `.Extract().String()` method

## Configuration

Set `WEBHOOK_URL` environment variable to enable notifications (e.g., `http://topolograph:5000`). If not set, notifications are silently skipped.

## Backward Compatibility

✅ Fully backward compatible. Notification is optional and non-blocking.
