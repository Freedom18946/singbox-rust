#![cfg(feature = "v2ray-api")]

use sb_api::v2ray::simple::{SimpleQueryStatsRequest, SimpleStatsRequest};
use sb_api::v2ray::GrpcV2RayApiServer as ModuleGrpcV2RayApiServer;
use sb_api::v2ray::SimpleV2RayApiServer;
use sb_api::GrpcV2RayApiServer as RootGrpcV2RayApiServer;

#[test]
fn explicit_grpc_v2ray_api_server_paths_resolve_to_same_type() {
    fn assert_same_type<T>(_root: Option<T>, _module: Option<T>) {}

    assert_same_type::<RootGrpcV2RayApiServer>(None, Option::<ModuleGrpcV2RayApiServer>::None);
}

#[test]
fn simple_v2ray_api_contract_paths_remain_clean() {
    let _server = Option::<SimpleV2RayApiServer>::None;
    let _stats = Option::<SimpleStatsRequest>::None;
    let _query = Option::<SimpleQueryStatsRequest>::None;
}
