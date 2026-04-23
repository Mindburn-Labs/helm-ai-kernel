/// Build script for HELM Rust SDK.
/// When the `codegen` feature is enabled, compiles proto files via tonic-build.
fn main() {
    #[cfg(feature = "codegen")]
    {
        let proto_root = "../../protocols/proto";
        let protos = [
            "helm/kernel/v1/helm.proto",
            "helm/authority/v1/authority.proto",
            "helm/effects/v1/effects.proto",
            "helm/intervention/v1/intervention.proto",
            "helm/truth/v1/truth.proto",
        ];

        let proto_paths: Vec<String> = protos
            .iter()
            .map(|p| format!("{}/{}", proto_root, p))
            .collect();

        tonic_build::configure()
            .build_server(false)
            .out_dir("src/generated")
            .compile_protos(&proto_paths, &[proto_root])
            .expect("Failed to compile HELM proto files");
    }
}
