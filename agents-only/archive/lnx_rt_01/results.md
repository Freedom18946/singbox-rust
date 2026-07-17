<!-- tier: B -->
# LNX-RT-01 dual-kernel Linux result table

Aggregate counts and current closure state live only in `../../active_context.md` after archival.
Raw artifacts stay outside Git under
`/private/tmp/singbox-rust-lnx-rt-01/amd64/interop-artifacts/`.

| Case | Linux outcome | Evidence run |
|---|---|---|
| `l6_local_harness_smoke` | `PASS` | `20260716T195153Z-dfe41192-0710-491e-a8d1-1e34f9804a9a` |
| `p0_clash_api_contract` | `PASS` | `20260716T195153Z-7649f9aa-e6e0-414c-bfcc-e51520bd9970` |
| `p0_clash_api_contract_strict` | `PASS` | `20260716T195208Z-7de256ea-0402-4754-901e-bcaae0710b4d` |
| `p1_auth_negative_missing_token` | `PASS` | `20260716T195216Z-b10180f1-455b-43d3-bb07-25b6501ac3ce` |
| `p1_auth_negative_wrong_token` | `PASS` | `20260716T195220Z-b9cdbf8e-21a9-4447-ae44-b227d7ccaec3` |
| `p1_block_outbound_via_socks` | `PASS` | `20260716T195223Z-2b2c903e-b6b2-4d5d-8c90-5b3e1735c9b1` |
| `p1_clash_api_auth_enforcement` | `PASS` | `20260716T195227Z-58d5781d-d66b-4def-95ca-336a5d9d0315` |
| `p1_dns_cache_ttl_via_socks` | `PASS` | `20260716T195242Z-1d4fcb9e-3933-4d00-967a-2977675169b4` |
| `p1_dns_query_endpoint_contract` | `PASS` | `20260716T195251Z-a10c6e96-8646-4bc8-bfa6-777b0f0973ee` |
| `p1_domain_rule_via_socks` | `PASS` | `20260716T195254Z-6106d3af-3af6-4599-8b7a-27298ab897ec` |
| `p1_fakeip_cache_flush_contract` | `DIV-COVERED` | `20260716T195258Z-c054ef90-20d6-467f-9510-d2c93253d1cd` |
| `p1_fakeip_dns_query_contract` | `PASS` | `20260716T195302Z-0f2380a7-db4f-426d-8c9f-3764be4d8965` |
| `p1_graceful_shutdown_drain` | `PASS` | `20260716T195511Z-ebdabfb2-a3ba-49b9-b285-93929e52bcf8` |
| `p1_gui_connections_tracking` | `PASS` | `20260716T195514Z-8c6dc516-1854-4b75-b8dc-abb4d0a77616` |
| `p1_gui_full_boot_replay` | `PASS` | `20260716T195526Z-11a3b0aa-58d0-4071-89b2-d2e4cc7ef4de` |
| `p1_gui_full_session_replay` | `PASS` | `20260716T195533Z-52a74d3a-48b6-4710-99a3-db5ec2c20131` |
| `p1_gui_group_delay_replay` | `PASS` | `20260716T195543Z-0ac351ca-6cde-4e51-8c67-2e7ae8854bd9` |
| `p1_gui_proxy_delay_replay` | `PASS` | `20260716T195548Z-01ddc359-d721-4b38-b70d-7c2193fc7b5d` |
| `p1_gui_proxy_switch_replay` | `PASS` | `20260716T195552Z-a160f0f5-a406-4848-8928-9772900705ce` |
| `p1_gui_ws_reconnect_behavior` | `PASS` | `20260716T195556Z-c4e62f49-f27b-48cd-9974-741ee66113f8` |
| `p1_http_connect_via_http_proxy` | `PASS` | `20260716T195609Z-e4acdc82-4e4d-4998-a82f-416e726338ed` |
| `p1_inbound_hot_reload_sighup` | `PASS` | `20260716T195613Z-b5a7425d-a22b-4ddb-b447-a4e4314f9c47` |
| `p1_ip_cidr_rule_via_socks` | `PASS` | `20260716T195634Z-c59d55e2-8fe9-44c0-99a6-d044b5c8932b` |
| `p1_lifecycle_restart_reload_replay` | `PASS` | `20260716T195638Z-806b445e-9407-488e-a7d2-886020ae77d7` |
| `p1_mixed_inbound_dual_protocol` | `PASS` | `20260716T195649Z-c1342449-26c8-4ba4-be8e-a02561b1975a` |
| `p1_optional_endpoints_contract` | `PASS` | `20260716T195653Z-7e460e2a-d3a7-41f9-b22a-f3f5453b589d` |
| `p1_rust_core_dns_via_socks` | `PASS` | `20260716T195729Z-0a45d9e5-7cbb-4e63-85c8-613a323e86d1` |
| `p1_rust_core_http_via_socks` | `PASS` | `20260716T195733Z-ff81c209-a372-475f-ac76-ecd8236ad22c` |
| `p1_rust_core_tcp_via_socks` | `PASS` | `20260716T195736Z-daf8b7f1-c89e-4a8f-8e06-4fd138f160af` |
| `p1_rust_core_udp_via_socks` | `PASS` | `20260716T195740Z-9103f65a-52d6-46a9-8a72-de06faed9bfb` |
| `p1_selector_switch_traffic_replay` | `PASS` | `20260716T195743Z-6347cb24-43bb-481c-b2c4-4aef6b1bc930` |
| `p1_sniff_rule_action_tls` | `PASS` | `20260716T195753Z-bbdb8849-d057-403a-bacc-86228b838962` |
| `p1_urltest_auto_select_replay` | `PASS` | `20260716T195804Z-2f18026d-8a46-40c5-81fd-bc03037ee74f` |
| `p1_version_endpoint_contract` | `PASS` | `20260716T195817Z-92c428d2-ab20-44af-b635-e1e6e55c50ab` |
| `p2_connections_ws_soak_dual_core` | `PASS` | `20260716T195823Z-2e2caab6-ba0a-46a3-b49a-e44cf0831866` |
| `p2_dataplane_chain_proxy` | `PASS` | `20260716T200529Z-e8382f57-1181-4058-9197-be9b017b1397` |
| `p2_shadowsocks_dual_dataplane_local` | `PASS` | `20260716T194949Z-33468719-4c57-4e9e-9b7f-4812cc8f6143` |
| `p2_shadowtls_dual_dataplane_local` | `PASS` | `20260716T200236Z-1a324000-798d-4416-a5a9-91b279000b0b` |
| `p2_trojan_dual_dataplane_local` | `PASS` | `20260716T194953Z-de68efd2-fdb3-4297-bbd7-85557863fba0` |
| `p2_vless_dual_dataplane_local` | `PASS` | `20260716T194958Z-7ecd6e43-216b-4ed4-b5e5-31fc03e03801` |
| `p2_vmess_dual_dataplane_local` | `PASS` | `20260717T142243Z-34b05275-47aa-41ff-bcfa-39220788da3d` |

`p1_fakeip_cache_flush_contract` uses only `DIV-M-001` and `DIV-M-012` from S4.
`p2_vmess_dual_dataplane_local` ran the committed strict case with complete assertions on both
kernels. Its summary has no covered divergence or environment-limited attribution.
