Wire the dormant interception features to reachable UI entry points.

Read the existing implementations and the p1 map first. Add dashboard controls,
route through the controller, follow the existing toggle pattern.

Targets: monitor_device (silent intercept, no drop) and toggle_dns_spoof
(DNS redirect).

These already exist — this is reachability, not new capability. If scope comes
up, that is the answer.

Mocked tests for both. Add a `manual-verify` entry to audit.md listing what must
be run on the lab box. Run p8. Stop.
