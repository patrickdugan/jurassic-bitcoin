const { runApplicationMesh } = require("./procedural_application_mesh_common");

runApplicationMesh("oracle_sidecar")
  .then((payload) => {
    console.log("[procedural-oracle-sidecar-mesh-live] SUCCESS");
    console.log(JSON.stringify(payload, null, 2));
  })
  .catch((err) => {
    console.error("[procedural-oracle-sidecar-mesh-live] failed:", err && err.stack ? err.stack : err);
    process.exit(1);
  });
