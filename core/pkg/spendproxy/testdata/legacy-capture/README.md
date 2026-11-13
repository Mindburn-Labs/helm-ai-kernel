# Historical offline fixture

This capture was produced by the retired spend-proxy test harness against a local mock provider. It contains one warmup and eight paired replay calls, signed receipt records, the public-key registry and the capture inputs used by offline savings export.

The signing seed is the fixed public test value `01` repeated 32 times. These records grant no authority and contain no real provider credentials or provider spending. Their signatures and original receipt payloads are retained to check compatibility after the live runtime was removed.
